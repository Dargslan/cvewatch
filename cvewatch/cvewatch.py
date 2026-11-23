#!/usr/bin/env python3
"""cvewatch - automated CVE tracking for Linux hosts.

Collects installed packages from local and remote Linux hosts, finds known
vulnerabilities through OSV.dev, enriches them with the CISA KEV catalogue and
FIRST EPSS scores, prioritises them by exposure, keeps history in SQLite,
writes HTML/CSV/JSON/Prometheus reports and sends alerts for new findings.

Single file, Python 3.8+ standard library only.
(c) 2026 Dargslan - MIT licence - https://dargslan.com
"""

import argparse
import configparser
import csv
import datetime as dt
import html
import json
import os
import platform
import re
import shutil
import smtplib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

VERSION = "1.0.0"
UA = f"cvewatch/{VERSION} (+https://dargslan.com)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
PRIORITIES = ["P1", "P2", "P3", "P4"]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
QUIET = False

DEFAULT_CONFIG = """\
[general]
data_dir = /var/lib/cvewatch
report_dir = /var/lib/cvewatch/reports
hosts_file = /etc/cvewatch/hosts.ini
exceptions_file = /etc/cvewatch/exceptions.csv
cache_hours = 20
keep_reports = 30

[sources]
osv = yes
kev = yes
epss = yes
include_kernel = yes

[priority]
p1_epss = 0.5
p2_epss = 0.1

[alerts]
min_priority = P2
ntfy_url =
ntfy_token =
webhook_url =
email_to =
email_from = cvewatch@localhost
smtp_host = localhost
smtp_port = 25

[output]
prometheus_file =
"""


# --------------------------------------------------------------------------- logging

def log(msg, level="INFO"):
    if QUIET and level == "INFO":
        return
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    print(f"{stamp} {level:5} {msg}", file=sys.stderr, flush=True)


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- version comparison

def _deb_order(c):
    if not c:
        return 0
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _deb_part_cmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i] if i < len(a) else "")
            bc = _deb_order(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return -1 if first < 0 else 1
    return 0


def _split_evr(v, sep_release=True):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if sep_release and "-" in v:
        u, r = v.rsplit("-", 1)
    else:
        u, r = v, ""
    return epoch, u, r


def deb_cmp(a, b):
    """Compare two Debian package versions like dpkg --compare-versions."""
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part_cmp(ua, ub) or _deb_part_cmp(ra, rb)


def _rpm_segments(s):
    return re.findall(r"~|\^|\d+|[A-Za-z]+", s)


def _rpmvercmp(a, b):
    if a == b:
        return 0
    ta, tb = _rpm_segments(a), _rpm_segments(b)
    i = 0
    while True:
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x == "~" or y == "~":
            if x != "~":
                return 1
            if y != "~":
                return -1
            i += 1
            continue
        if x == "^" or y == "^":
            if x is None:
                return -1
            if y is None:
                return 1
            if x != "^":
                return 1
            if y != "^":
                return -1
            i += 1
            continue
        if x is None and y is None:
            return 0
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return 1 if xi > yi else -1
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        elif x != y:
            return 1 if x > y else -1
        i += 1


def rpm_cmp(a, b):
    """Compare RPM (and, approximately, Alpine) versions as epoch:version-release."""
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpmvercmp(ua, ub) or _rpmvercmp(ra, rb)


def version_cmp(fmt, a, b):
    return deb_cmp(a, b) if fmt == "deb" else rpm_cmp(a, b)


# --------------------------------------------------------------------------- CVSS 3.x base score

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["C"][m["I"]]) * (1 - _CVSS3["C"][m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError):
        return None


LABEL_SCORE = {"critical": 9.5, "high": 7.5, "important": 7.5, "medium": 5.0, "moderate": 5.0,
               "low": 2.5, "negligible": 0.5, "unimportant": 0.5}


def rating(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# --------------------------------------------------------------------------- HTTP with fixtures

class Http:
    """Small JSON HTTP client. With a fixtures directory it works fully offline."""

    def __init__(self, fixtures=None):
        self.fixtures = fixtures

    def _request(self, url, data=None, headers=None, timeout=60):
        hdrs = {"User-Agent": UA, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            hdrs["Content-Type"] = "application/json"
        last = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=body, headers=hdrs)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.loads(r.read().decode("utf-8"))
            except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
                last = e
                code = getattr(e, "code", None)
                if code and 400 <= code < 500 and code != 429:
                    break
                time.sleep(2 ** attempt)
        raise RuntimeError(f"request to {url.split('?')[0]} failed: {last}")

    # OSV ---------------------------------------------------------------
    def osv_batch(self, queries):
        if self.fixtures:
            index = json.load(open(os.path.join(self.fixtures, "osv_index.json")))
            out = []
            for q in queries:
                key = f"{q['package']['ecosystem']}|{q['package']['name']}"
                out.append({"vulns": [{"id": i, "modified": "fixture"} for i in index.get(key, [])]})
            return out
        results = [None] * len(queries)
        for start in range(0, len(queries), 1000):
            pending = [(start + k, dict(q)) for k, q in enumerate(queries[start:start + 1000])]
            for _ in range(20):
                if not pending:
                    break
                resp = self._request(OSV_BATCH, {"queries": [q for _, q in pending]})
                nxt = []
                for (slot, q), res in zip(pending, resp.get("results", [])):
                    if results[slot] is None:
                        results[slot] = {"vulns": []}
                    results[slot]["vulns"].extend(res.get("vulns", []) or [])
                    tok = res.get("next_page_token")
                    if tok:
                        q2 = dict(q)
                        q2["page_token"] = tok
                        nxt.append((slot, q2))
                pending = nxt
        return [r or {"vulns": []} for r in results]

    def osv_vuln(self, vid):
        if self.fixtures:
            p = os.path.join(self.fixtures, "vulns", f"{vid}.json")
            return json.load(open(p)) if os.path.exists(p) else None
        return self._request(OSV_VULN + urllib.parse.quote(vid))

    # KEV / EPSS --------------------------------------------------------
    def kev(self):
        if self.fixtures:
            return json.load(open(os.path.join(self.fixtures, "kev.json")))
        return self._request(KEV_URL, timeout=120)

    def epss(self, cves):
        if self.fixtures:
            data = json.load(open(os.path.join(self.fixtures, "epss.json")))["data"]
            return {d["cve"]: d for d in data if d["cve"] in cves}
        out = {}
        cves = sorted(cves)
        for i in range(0, len(cves), 80):
            chunk = ",".join(cves[i:i + 80])
            res = self._request(f"{EPSS_URL}?cve={chunk}")
            for d in res.get("data", []):
                out[d["cve"]] = d
        return out


# --------------------------------------------------------------------------- inventory collection

def _run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def read_os_release():
    info = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.exists(path):
            for line in open(path, encoding="utf-8", errors="replace"):
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    info[k] = v.strip().strip('"')
            break
    return info


UBUNTU_CODENAMES = {"noble": "24.04", "jammy": "22.04", "focal": "20.04", "resolute": "26.04",
                    "questing": "25.10", "plucky": "25.04", "oracular": "24.10"}
LTS = {"20.04", "22.04", "24.04", "26.04"}


def osv_ecosystem(osr):
    ids = [osr.get("ID", "")] + osr.get("ID_LIKE", "").split()
    vid = osr.get("VERSION_ID", "")
    if osr.get("ID") == "ubuntu" or (osr.get("UBUNTU_CODENAME") and "ubuntu" in ids):
        ver = vid if osr.get("ID") == "ubuntu" else UBUNTU_CODENAMES.get(osr.get("UBUNTU_CODENAME", ""), "")
        if not ver:
            return None
        return f"Ubuntu:{ver}:LTS" if ver in LTS else f"Ubuntu:{ver}"
    if osr.get("ID") in ("debian", "raspbian") and vid:
        return f"Debian:{vid.split('.')[0]}"
    if osr.get("ID") == "almalinux" and vid:
        return f"AlmaLinux:{vid.split('.')[0]}"
    if osr.get("ID") == "rocky" and vid:
        return f"Rocky Linux:{vid.split('.')[0]}"
    if osr.get("ID") == "alpine" and vid:
        return "Alpine:v" + ".".join(vid.split(".")[:2])
    return None


def _kernel_pkg(name, running):
    return re.match(r"linux-(image|modules|headers|modules-extra)-\d", name) and running not in name


def collect_local():
    """Return the local host's inventory as a dict (runs unprivileged)."""
    osr = read_os_release()
    running = platform.release()
    inv = {
        "collector": VERSION, "collected": now_iso(), "hostname": socket.getfqdn() or platform.node(),
        "os": osr.get("PRETTY_NAME", "unknown"), "os_id": osr.get("ID", ""), "version_id": osr.get("VERSION_ID", ""),
        "ecosystem": osv_ecosystem(osr), "kernel": running, "format": None, "packages": [],
        "security_updates": [], "reboot_required": os.path.exists("/var/run/reboot-required"),
    }
    if shutil.which("dpkg-query"):
        inv["format"] = "deb"
        rc, out = _run(["dpkg-query", "-W", "-f",
                        "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 5 or not parts[0].startswith("ii"):
                continue
            _, name, ver, src, srcver = parts
            if _kernel_pkg(name, running):
                continue
            inv["packages"].append({"name": name, "version": ver, "source": src or name, "source_version": srcver or ver})
        rc, out = _run(["apt", "list", "--upgradable"])
        for line in out.splitlines():
            m = re.match(r"^([^/]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
            if m and "-security" in m.group(2):
                inv["security_updates"].append({"package": m.group(1), "from": m.group(4), "to": m.group(3), "advisory": "", "severity": ""})
    elif shutil.which("rpm"):
        inv["format"] = "rpm"
        rc, out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or parts[0].startswith("gpg-pubkey"):
                continue
            name, evr, srpm = parts
            if evr.startswith("0:"):
                evr = evr[2:]
            m = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", srpm)
            src = m.group(1) if m else name
            inv["packages"].append({"name": name, "version": evr, "source": src, "source_version": evr})
        if shutil.which("dnf"):
            rc, out = _run(["dnf", "-q", "updateinfo", "list", "--security"], timeout=300)
            for line in out.splitlines():
                m = re.match(r"^(\S+)\s+(\S+?)(?:/Sec\.)?\s+(\S+)$", line.strip())
                if m and re.match(r"^[A-Z]+-\d{4}", m.group(1)):
                    inv["security_updates"].append({"package": m.group(3), "from": "", "to": m.group(3),
                                                    "advisory": m.group(1), "severity": m.group(2)})
                m5 = re.match(r"^([A-Z]+-\d{4}[:-]\S+)\s+security\s+(\S+)\s+(\S+)", line.strip())
                if m5 and not m:
                    inv["security_updates"].append({"package": m5.group(3), "from": "", "to": m5.group(3),
                                                    "advisory": m5.group(1), "severity": m5.group(2)})
        rc, out = _run(["rpm", "-q", "kernel-core", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}\n"])
        if rc != 0:
            rc, out = _run(["rpm", "-q", "kernel", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}\n"])
        kernels = [k for k in out.split() if k and "not installed" not in k]
        if kernels:
            newest = kernels[0]
            for k in kernels[1:]:
                if rpm_cmp(k, newest) > 0:
                    newest = k
            if newest != running:
                inv["reboot_required"] = True
    elif shutil.which("apk"):
        inv["format"] = "apk"
        rc, out = _run(["apk", "list", "-I"])
        for line in out.splitlines():
            m = re.match(r"^(\S+)-(\d\S*-r\d+)\s+\S+\s+\{([^}]+)\}", line)
            if m:
                inv["packages"].append({"name": m.group(1), "version": m.group(2), "source": m.group(3), "source_version": m.group(2)})
    return inv


def collect_remote(host, script_path):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if host.get("port"):
        cmd += ["-p", str(host["port"])]
    if host.get("identity"):
        cmd += ["-i", host["identity"]]
    target = f"{host['user']}@{host['address']}" if host.get("user") else host["address"]
    if host.get("mode", "push") == "installed":
        cmd += [target, host.get("remote_command", "cvewatch collect")]
        stdin = None
    else:
        cmd += [target, host.get("python", "python3"), "-", "collect"]
        stdin = open(script_path, "rb").read()
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise RuntimeError("ssh timed out")
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip().splitlines()
        raise RuntimeError(f"ssh exit {p.returncode}: {err[-1] if err else 'no output'}")
    return json.loads(p.stdout.decode())


# --------------------------------------------------------------------------- configuration

def load_config(path):
    cfg = configparser.ConfigParser()
    cfg.read_string(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        cfg.read(path)
    return cfg


def load_hosts(path, local_default=True):
    hosts = []
    if path and os.path.exists(path):
        hp = configparser.ConfigParser()
        hp.read(path)
        for name in hp.sections():
            h = dict(hp[name])
            h["name"] = name
            h.setdefault("address", name)
            h.setdefault("exposure", "lan")
            h.setdefault("criticality", "medium")
            if h.get("enabled", "yes").lower() in ("no", "false", "0"):
                continue
            hosts.append(h)
    if not hosts and local_default:
        hosts.append({"name": socket.gethostname(), "address": "local", "exposure": "lan", "criticality": "medium"})
    return hosts


def load_exceptions(path):
    out = []
    if path and os.path.exists(path):
        with open(path, newline="") as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith("#") or len(row) < 3:
                    continue
                out.append({"vuln": row[0].strip(), "host": row[1].strip() or "*", "expires": row[2].strip(),
                            "reason": row[3].strip() if len(row) > 3 else ""})
    return out


def exception_for(exceptions, vuln, host):
    today = dt.date.today().isoformat()
    for e in exceptions:
        if e["vuln"] == vuln and e["host"] in ("*", host):
            if not e["expires"] or e["expires"] >= today:
                return e
    return None


# --------------------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, started TEXT, finished TEXT, hosts INTEGER, failed INTEGER,
  new INTEGER, resolved INTEGER);
CREATE TABLE IF NOT EXISTS hosts (name TEXT PRIMARY KEY, address TEXT, os TEXT, ecosystem TEXT, kernel TEXT,
  reboot_required INTEGER, packages INTEGER, security_updates INTEGER, exposure TEXT, criticality TEXT,
  last_scan TEXT, last_error TEXT);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, host TEXT, vuln TEXT, package TEXT, installed TEXT,
  fixed TEXT, source_ids TEXT, summary TEXT, score REAL, severity TEXT, epss REAL, epss_pct REAL, kev INTEGER,
  ransomware INTEGER, priority TEXT, status TEXT, note TEXT, first_seen TEXT, last_seen TEXT, resolved_at TEXT,
  UNIQUE(host, vuln, package));
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, priority);
"""


def open_db(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    db = sqlite3.connect(os.path.join(data_dir, "cvewatch.db"))
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


# --------------------------------------------------------------------------- analysis

def _osv_cached(http, cache_dir, vid, modified):
    path = os.path.join(cache_dir, re.sub(r"[^A-Za-z0-9._-]", "_", vid) + ".json")
    if os.path.exists(path):
        try:
            rec = json.load(open(path))
            if modified in (None, "fixture") or rec.get("modified") == modified:
                return rec
        except ValueError:
            pass
    rec = http.osv_vuln(vid)
    if rec:
        with open(path, "w") as f:
            json.dump(rec, f)
    return rec


def _attack_vector(rec):
    for lst in [rec.get("severity") or []] + [a.get("severity") or [] for a in rec.get("affected", [])]:
        for s in lst:
            m = re.search(r"/AV:([NALP])", str(s.get("score", "")))
            if m:
                return m.group(1)
    return None


def _severity(rec, ecosystem):
    scores, labels = [], []
    sev_lists = [rec.get("severity") or []]
    for aff in rec.get("affected", []):
        sev_lists.append(aff.get("severity") or [])
        for spec in (aff.get("ecosystem_specific") or {}, aff.get("database_specific") or {}):
            for key in ("severity", "urgency", "priority"):
                if isinstance(spec.get(key), str):
                    labels.append(spec[key])
    db = rec.get("database_specific") or {}
    for key in ("severity", "urgency", "priority"):
        if isinstance(db.get(key), str):
            labels.append(db[key])
    for lst in sev_lists:
        for s in lst:
            t, val = s.get("type", ""), str(s.get("score", ""))
            if t.startswith("CVSS_V3") or val.startswith("CVSS:3"):
                sc = cvss3_score(val)
                if sc is not None:
                    scores.append(sc)
            elif t.lower() in ("ubuntu", "debian") or val.lower() in LABEL_SCORE:
                labels.append(val)
    if scores:
        return max(scores), rating(max(scores))
    for lab in labels:
        sc = LABEL_SCORE.get(lab.lower().strip())
        if sc is not None:
            return sc, lab.upper()
    return None, "UNKNOWN"


def _fixed_version(rec, ecosystem, name, fmt):
    fixed = []
    for aff in rec.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    if not fixed:
        return None
    best = fixed[0]
    for f in fixed[1:]:
        if version_cmp(fmt, f, best) > 0:
            best = f
    return best


def _ids_from(rec):
    texts = [rec.get("id", "")] + list(rec.get("aliases", []) or []) + list(rec.get("upstream", []) or [])
    cves = []
    for t in texts:
        for c in CVE_RE.findall(t):
            if c not in cves:
                cves.append(c)
    return cves


def analyse_host(inv, http, cache_dir, include_kernel=True):
    """Return a dict keyed by (vuln, package) with raw findings for one inventory."""
    eco, fmt = inv.get("ecosystem"), inv.get("format")
    findings = {}
    if eco and inv.get("packages"):
        sources = {}
        for p in inv["packages"]:
            src = p["source"]
            if not include_kernel and re.match(r"^linux(-|$)", src):
                continue
            sources.setdefault((src, p["source_version"]), []).append(p["name"])
        queries, keys = [], []
        for (src, ver) in sources:
            names = [src]
            if src.startswith("linux-signed"):
                names.append(re.sub(r"^linux-signed(-amd64|-arm64)?", "linux", src))
            for n in names:
                queries.append({"package": {"name": n, "ecosystem": eco}, "version": ver})
                keys.append((n, src, ver))
        log(f"  OSV: {len(queries)} source packages ({len(inv['packages'])} binaries) in {eco}")
        results = http.osv_batch(queries)
        for (name, src, ver), res in zip(keys, results):
            for v in res.get("vulns", []):
                rec = _osv_cached(http, cache_dir, v["id"], v.get("modified"))
                if not rec or rec.get("withdrawn"):
                    continue
                fixed = _fixed_version(rec, eco, name, fmt)
                if fixed and version_cmp(fmt, ver, fixed) >= 0:
                    continue
                score, sev = _severity(rec, eco)
                av = _attack_vector(rec)
                summary = (rec.get("summary") or rec.get("details") or "").strip().splitlines()
                summary = summary[0][:180] if summary else ""
                vulns = _ids_from(rec) or [rec["id"]]
                for vid in vulns:
                    key = (vid, src)
                    f = findings.get(key)
                    if not f:
                        findings[key] = f = {"vuln": vid, "package": src, "installed": ver, "fixed": fixed,
                                             "source_ids": [], "summary": summary, "score": score, "severity": sev,
                                             "av": av}
                    if rec["id"] not in f["source_ids"]:
                        f["source_ids"].append(rec["id"])
                    if fixed and (not f["fixed"] or version_cmp(fmt, fixed, f["fixed"]) > 0):
                        f["fixed"] = fixed
                    if score is not None and (f["score"] is None or score > f["score"]):
                        f["score"], f["severity"] = score, sev
                    if not f["summary"] and summary:
                        f["summary"] = summary
    else:
        if not eco:
            log(f"  no OSV ecosystem for {inv.get('os')}: using native security updates only", "WARN")
        for u in inv.get("security_updates", []):
            vid = u.get("advisory") or f"UPDATE:{u['package']}"
            sc = LABEL_SCORE.get(u.get("severity", "").lower())
            findings[(vid, u["package"])] = {"vuln": vid, "package": u["package"], "installed": u.get("from", ""),
                                             "fixed": u.get("to") or "available", "source_ids": [vid],
                                             "summary": "Security update available from the distribution",
                                             "score": sc, "severity": rating(sc) if sc else "UNKNOWN"}
    if inv.get("reboot_required"):
        findings[("REBOOT-PENDING", "kernel")] = {"vuln": "REBOOT-PENDING", "package": "kernel", "installed": inv.get("kernel", ""),
                                                  "fixed": "reboot", "source_ids": [], "score": 7.0, "severity": "HIGH",
                                                  "summary": "Updated kernel or core libraries installed but not running"}
    return findings


def prioritise(f, host, cfg):
    p1, p2 = cfg.getfloat("priority", "p1_epss"), cfg.getfloat("priority", "p2_epss")
    sev = f["score"] if f["score"] is not None else 5.0
    epss = f.get("epss") or 0.0
    # local (L) and physical (P) attack vectors need prior access, so internet exposure does not apply
    exposed = host.get("exposure", "lan") == "internet" and f.get("av") not in ("L", "P")
    fixable = bool(f.get("fixed"))
    if (f.get("kev") or epss >= p1) and exposed:
        pr = 1
    elif f.get("kev") or epss >= p2 or (sev >= 9.0 and exposed and fixable):
        pr = 2
    elif sev >= 7.0 and fixable:
        pr = 3
    else:
        pr = 4
    if host.get("criticality", "medium") == "high":
        pr = max(1, pr - 1)
    return f"P{pr}"


# --------------------------------------------------------------------------- KEV / EPSS cache

def _cached_json(path, hours, fetch):
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < hours * 3600:
        try:
            return json.load(open(path))
        except ValueError:
            pass
    try:
        data = fetch()
        with open(path, "w") as f:
            json.dump(data, f)
        return data
    except Exception as e:  # keep running on a stale cache
        log(f"{os.path.basename(path)}: {e}", "WARN")
        if os.path.exists(path):
            return json.load(open(path))
        return None


def enrich(all_findings, http, cfg, cache_dir):
    cves = {f["vuln"] for fs in all_findings.values() for f in fs.values() if f["vuln"].startswith("CVE-")}
    hours = cfg.getfloat("general", "cache_hours")
    kev = {}
    if cfg.getboolean("sources", "kev"):
        data = _cached_json(os.path.join(cache_dir, "kev.json"), hours, http.kev)
        if data:
            kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    epss = {}
    if cfg.getboolean("sources", "epss") and cves:
        path = os.path.join(cache_dir, "epss.json")
        cached = {}
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < hours * 3600:
            try:
                cached = json.load(open(path))
            except ValueError:
                cached = {}
        missing = sorted(c for c in cves if c not in cached)
        if missing:
            try:
                cached.update(http.epss(set(missing)))
                for c in missing:
                    cached.setdefault(c, {"cve": c, "epss": "0", "percentile": "0"})
                with open(path, "w") as f:
                    json.dump(cached, f)
            except Exception as e:
                log(f"EPSS: {e}", "WARN")
        epss = cached
    for fs in all_findings.values():
        for f in fs.values():
            k = kev.get(f["vuln"])
            f["kev"] = 1 if k else 0
            f["ransomware"] = 1 if k and k.get("knownRansomwareCampaignUse") == "Known" else 0
            e = epss.get(f["vuln"])
            f["epss"] = float(e["epss"]) if e else None
            f["epss_pct"] = float(e["percentile"]) if e else None
    return len(kev), len(epss)


# --------------------------------------------------------------------------- scan

def scan(cfg, args):
    data_dir = cfg.get("general", "data_dir")
    cache_dir = os.path.join(data_dir, "cache")
    os.makedirs(os.path.join(cache_dir, "osv"), exist_ok=True)
    http = Http(args.fixtures)
    db = open_db(data_dir)
    hosts = load_hosts(args.hosts or cfg.get("general", "hosts_file"))
    if args.local_only:
        hosts = [h for h in hosts if h["address"] == "local"] or [{"name": socket.gethostname(), "address": "local",
                                                                  "exposure": "lan", "criticality": "medium"}]
    exceptions = load_exceptions(cfg.get("general", "exceptions_file"))
    started = now_iso()
    log(f"cvewatch {VERSION}: scanning {len(hosts)} host(s)")
    invs, all_findings, failed = {}, {}, []
    for h in hosts:
        log(f"[{h['name']}] collecting ({h['address']})")
        try:
            if h["address"] == "local":
                inv = collect_local()
            elif h["address"].startswith("file:"):
                inv = json.load(open(h["address"][5:]))
            elif h["address"].startswith("fixture:"):
                inv = json.load(open(os.path.join(args.fixtures, f"inventory_{h['address'][8:]}.json")))
            else:
                inv = collect_remote(h, os.path.abspath(__file__))
            invs[h["name"]] = inv
            all_findings[h["name"]] = analyse_host(inv, http, os.path.join(cache_dir, "osv"),
                                                   cfg.getboolean("sources", "include_kernel"))
            log(f"[{h['name']}] {inv.get('os')}: {len(inv.get('packages', []))} packages, "
                f"{len(all_findings[h['name']])} findings")
        except Exception as e:
            failed.append(h["name"])
            log(f"[{h['name']}] failed: {e}", "ERROR")
            db.execute("INSERT INTO hosts(name, address, exposure, criticality, last_error) VALUES(?,?,?,?,?) "
                       "ON CONFLICT(name) DO UPDATE SET last_error=excluded.last_error",
                       (h["name"], h["address"], h.get("exposure"), h.get("criticality"), str(e)))
    n_kev, n_epss = enrich(all_findings, http, cfg, cache_dir)
    log(f"enrichment: KEV catalogue {n_kev} entries, EPSS scores for {n_epss} CVEs")
    ts = now_iso()
    new, resolved = [], 0
    hostmap = {h["name"]: h for h in hosts}
    for name, fs in all_findings.items():
        h, inv = hostmap[name], invs[name]
        db.execute("INSERT INTO hosts(name, address, os, ecosystem, kernel, reboot_required, packages, security_updates, "
                   "exposure, criticality, last_scan, last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL) "
                   "ON CONFLICT(name) DO UPDATE SET address=excluded.address, os=excluded.os, ecosystem=excluded.ecosystem, "
                   "kernel=excluded.kernel, reboot_required=excluded.reboot_required, packages=excluded.packages, "
                   "security_updates=excluded.security_updates, exposure=excluded.exposure, "
                   "criticality=excluded.criticality, last_scan=excluded.last_scan, last_error=NULL",
                   (name, h["address"], inv.get("os"), inv.get("ecosystem"), inv.get("kernel"),
                    int(bool(inv.get("reboot_required"))), len(inv.get("packages", [])),
                    len(inv.get("security_updates", [])), h.get("exposure"), h.get("criticality"), ts))
        seen = set()
        for f in fs.values():
            f["priority"] = prioritise(f, h, cfg)
            exc = exception_for(exceptions, f["vuln"], name)
            status = "accepted" if exc else "open"
            note = f"exception until {exc['expires']}: {exc['reason']}" if exc else ""
            row = db.execute("SELECT id, status FROM findings WHERE host=? AND vuln=? AND package=?",
                             (name, f["vuln"], f["package"])).fetchone()
            vals = (f["installed"], f["fixed"], " ".join(f["source_ids"]), f["summary"], f["score"], f["severity"],
                    f["epss"], f["epss_pct"], f["kev"], f["ransomware"], f["priority"], status, note, ts)
            if row:
                db.execute("UPDATE findings SET installed=?, fixed=?, source_ids=?, summary=?, score=?, severity=?, epss=?, "
                           "epss_pct=?, kev=?, ransomware=?, priority=?, status=?, note=?, last_seen=?, resolved_at=NULL "
                           "WHERE id=?", vals + (row["id"],))
                if row["status"] == "resolved" and status == "open":
                    new.append(dict(f, host=name, reopened=True))
                seen.add(row["id"])
            else:
                cur = db.execute("INSERT INTO findings(installed, fixed, source_ids, summary, score, severity, epss, "
                                 "epss_pct, kev, ransomware, priority, status, note, last_seen, host, vuln, package, "
                                 "first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                 vals + (name, f["vuln"], f["package"], ts))
                seen.add(cur.lastrowid)
                if status == "open":
                    new.append(dict(f, host=name))
        for row in db.execute("SELECT id FROM findings WHERE host=? AND status IN ('open','accepted')", (name,)).fetchall():
            if row["id"] not in seen:
                db.execute("UPDATE findings SET status='resolved', resolved_at=? WHERE id=?", (ts, row["id"]))
                resolved += 1
    db.execute("INSERT INTO scans(started, finished, hosts, failed, new, resolved) VALUES(?,?,?,?,?,?)",
               (started, now_iso(), len(hosts), len(failed), len(new), resolved))
    db.commit()
    log(f"scan done: {len(new)} new, {resolved} resolved, {len(failed)} host(s) failed")
    write_reports(db, cfg)
    if not args.no_alerts:
        send_alerts(cfg, new, failed)
    worst = db.execute("SELECT MIN(priority) p FROM findings WHERE status='open'").fetchone()["p"]
    if args.fail_on and worst and PRIORITIES.index(worst) <= PRIORITIES.index(args.fail_on):
        return 2
    return 1 if failed else 0


# --------------------------------------------------------------------------- alerts

def send_alerts(cfg, new, failed):
    limit = cfg.get("alerts", "min_priority").upper()
    hot = [f for f in new if PRIORITIES.index(f["priority"]) <= PRIORITIES.index(limit)]
    hot.sort(key=lambda f: (f["priority"], -(f.get("epss") or 0)))
    if not hot and not failed:
        return
    lines = []
    for f in hot[:12]:
        tag = " KEV" if f.get("kev") else ""
        ep = f" EPSS {f['epss']:.2f}" if f.get("epss") is not None else ""
        fix = f"fix {f['fixed']}" if f.get("fixed") else "no fix yet"
        lines.append(f"{f['priority']}{tag} {f['host']}: {f['vuln']} in {f['package']} ({f['severity']}{ep}; {fix})")
    if len(hot) > 12:
        lines.append(f"... and {len(hot) - 12} more")
    if failed:
        lines.append("Scan failed for: " + ", ".join(failed))
    title = f"cvewatch: {len(hot)} new {limit}+ finding(s)" if hot else "cvewatch: scan problems"
    body = "\n".join(lines)
    prio = "urgent" if any(f["priority"] == "P1" for f in hot) else "high"
    if cfg.get("alerts", "ntfy_url"):
        try:
            hdrs = {"Title": title, "Priority": prio, "Tags": "rotating_light" if prio == "urgent" else "warning",
                    "User-Agent": UA}
            if cfg.get("alerts", "ntfy_token"):
                hdrs["Authorization"] = "Bearer " + cfg.get("alerts", "ntfy_token")
            urllib.request.urlopen(urllib.request.Request(cfg.get("alerts", "ntfy_url"), data=body.encode(),
                                                          headers=hdrs), timeout=30)
            log("alert sent via ntfy")
        except Exception as e:
            log(f"ntfy alert failed: {e}", "WARN")
    if cfg.get("alerts", "webhook_url"):
        try:
            payload = json.dumps({"text": f"*{title}*\n{body}", "content": f"**{title}**\n{body}",
                                  "title": title, "findings": hot[:50]}, default=str).encode()
            urllib.request.urlopen(urllib.request.Request(cfg.get("alerts", "webhook_url"), data=payload,
                                                          headers={"Content-Type": "application/json", "User-Agent": UA}),
                                   timeout=30)
            log("alert sent via webhook")
        except Exception as e:
            log(f"webhook alert failed: {e}", "WARN")
    if cfg.get("alerts", "email_to"):
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = title, cfg.get("alerts", "email_from"), cfg.get("alerts", "email_to")
            msg.set_content(body + "\n\nFull report: " + os.path.join(cfg.get("general", "report_dir"), "cvewatch-report.html"))
            with smtplib.SMTP(cfg.get("alerts", "smtp_host"), cfg.getint("alerts", "smtp_port"), timeout=30) as s:
                s.send_message(msg)
            log("alert sent via email")
        except Exception as e:
            log(f"email alert failed: {e}", "WARN")


# --------------------------------------------------------------------------- reports

def metrics(db):
    m = {"open": {p: 0 for p in PRIORITIES}}
    for r in db.execute("SELECT priority, COUNT(*) n FROM findings WHERE status='open' GROUP BY priority"):
        m["open"][r["priority"]] = r["n"]
    m["kev"] = db.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND kev=1").fetchone()[0]
    m["accepted"] = db.execute("SELECT COUNT(*) FROM findings WHERE status='accepted'").fetchone()[0]
    m["fixable"] = db.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND fixed IS NOT NULL").fetchone()[0]
    m["mttr"] = {}
    for r in db.execute("SELECT priority, AVG(julianday(resolved_at) - julianday(first_seen)) d, COUNT(*) n "
                        "FROM findings WHERE status='resolved' GROUP BY priority"):
        m["mttr"][r["priority"]] = (round(r["d"], 1), r["n"])
    last = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    m["last_scan"] = dict(last) if last else {}
    m["hosts"] = [dict(r) for r in db.execute("SELECT * FROM hosts ORDER BY name")]
    return m


def _fmt_epss(v):
    return "" if v is None else f"{v:.3f}"


def write_reports(db, cfg):
    out = cfg.get("general", "report_dir")
    os.makedirs(out, exist_ok=True)
    m = metrics(db)
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM findings WHERE status IN ('open','accepted') ORDER BY status DESC, priority, kev DESC, "
        "COALESCE(epss,0) DESC, COALESCE(score,0) DESC")]
    # CSV
    with open(os.path.join(out, "findings-open.csv"), "w", newline="") as f:
        w = csv.writer(f)
        cols = ["priority", "host", "vuln", "package", "installed", "fixed", "severity", "score", "epss", "kev",
                "ransomware", "status", "first_seen", "source_ids", "summary", "note"]
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, "") if r.get(c) is not None else "" for c in cols])
    # JSON
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump({"generated": now_iso(), "metrics": m, "findings": rows}, f, indent=1, default=str)
    # Prometheus
    prom = cfg.get("output", "prometheus_file")
    if prom:
        lines = ["# HELP cvewatch_open_findings Open findings by host and priority",
                 "# TYPE cvewatch_open_findings gauge"]
        for r in db.execute("SELECT host, priority, COUNT(*) n FROM findings WHERE status='open' GROUP BY host, priority"):
            lines.append(f'cvewatch_open_findings{{host="{r["host"]}",priority="{r["priority"]}"}} {r["n"]}')
        lines += ["# TYPE cvewatch_open_kev gauge", f"cvewatch_open_kev {m['kev']}",
                  "# TYPE cvewatch_reboot_required gauge"]
        for h in m["hosts"]:
            lines.append(f'cvewatch_reboot_required{{host="{h["name"]}"}} {h.get("reboot_required") or 0}')
        lines += ["# TYPE cvewatch_last_scan_timestamp gauge", f"cvewatch_last_scan_timestamp {int(time.time())}"]
        tmp = prom + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, prom)
    # HTML
    page = render_html(m, rows)
    path = os.path.join(out, "cvewatch-report.html")
    with open(path, "w") as f:
        f.write(page)
    stamp = dt.date.today().isoformat()
    shutil.copyfile(path, os.path.join(out, f"cvewatch-report-{stamp}.html"))
    keep = cfg.getint("general", "keep_reports")
    old = sorted(p for p in os.listdir(out) if re.match(r"cvewatch-report-\d{4}-\d\d-\d\d\.html$", p))
    for p in old[:-keep] if keep > 0 else []:
        os.remove(os.path.join(out, p))
    log(f"reports written to {out}")


def render_html(m, rows):
    e = html.escape
    o = m["open"]
    tiles = [("P1", o["P1"], "#EF4444"), ("P2", o["P2"], "#F97316"), ("P3", o["P3"], "#EAB308"), ("P4", o["P4"], "#64748B"),
             ("KEV", m["kev"], "#EF4444"), ("Fix available", m["fixable"], "#2DD4BF"), ("Accepted", m["accepted"], "#94A3B8"),
             ("Hosts", len(m["hosts"]), "#60A5FA")]
    tile_html = "".join(f'<div class="tile"><div class="n" style="color:{c}">{n}</div><div class="l">{e(l)}</div></div>'
                        for l, n, c in tiles)
    host_rows = ""
    for h in m["hosts"]:
        cnt = {p: 0 for p in PRIORITIES}
        for r in rows:
            if r["host"] == h["name"] and r["status"] == "open":
                cnt[r["priority"]] += 1
        err = f'<span class="bad">{e(h["last_error"])}</span>' if h.get("last_error") else ""
        reboot = '<span class="warn">reboot</span>' if h.get("reboot_required") else ""
        host_rows += (f'<tr><td><b>{e(h["name"])}</b><br><small>{e(h.get("address") or "")}</small></td>'
                      f'<td>{e(h.get("os") or "")}<br><small>{e(h.get("ecosystem") or "native")}</small></td>'
                      f'<td>{e(h.get("exposure") or "")} / {e(h.get("criticality") or "")}</td>'
                      f'<td>{h.get("packages") or 0}</td><td>{h.get("security_updates") or 0}</td>'
                      + "".join(f'<td class="c {p}">{cnt[p] or ""}</td>' for p in PRIORITIES)
                      + f'<td>{reboot} {err}</td><td><small>{e((h.get("last_scan") or "")[:16])}</small></td></tr>')
    frows = ""
    for r in rows:
        link = (f'https://nvd.nist.gov/vuln/detail/{r["vuln"]}' if r["vuln"].startswith("CVE-")
                else f'https://osv.dev/vulnerability/{r["source_ids"].split()[0]}' if r["source_ids"] else "#")
        badges = ('<span class="kev">KEV</span>' if r["kev"] else "") + ('<span class="rw">ransomware</span>' if r["ransomware"] else "")
        cls = "acc" if r["status"] == "accepted" else ""
        frows += (f'<tr class="{cls}" data-p="{r["priority"]}" data-h="{e(r["host"])}">'
                  f'<td class="c {r["priority"]}">{r["priority"]}</td><td class="nw">{e(r["host"])}</td>'
                  f'<td><a href="{e(link)}" target="_blank" rel="noopener">{e(r["vuln"])}</a> {badges}<br>'
                  f'<small>{e(r["summary"] or "")}</small></td>'
                  f'<td><b>{e(r["package"])}</b><br><small>{e(r["installed"] or "")}</small></td>'
                  f'<td>{e(r["fixed"] or "no fix yet")}</td><td>{e(r["severity"] or "")}'
                  f'{" " + format(r["score"], ".1f") if r["score"] is not None else ""}</td>'
                  f'<td>{_fmt_epss(r["epss"])}</td><td><small>{e((r["first_seen"] or "")[:10])}</small>'
                  f'{"<br><small>" + e(r["note"]) + "</small>" if r["note"] else ""}</td></tr>')
    mttr = " · ".join(f"{p}: {v[0]} days ({v[1]} fixed)" for p, v in sorted(m["mttr"].items())) or "no resolved findings yet"
    hosts_opts = "".join(f'<option>{e(h["name"])}</option>' for h in m["hosts"])
    ls = m.get("last_scan") or {}
    demo = any((h.get("address") or "").startswith("fixture:") for h in m["hosts"])
    banner = '<div class="demo">DEMO DATA from the built-in self-test: versions, EPSS values and KEV entries are illustrative.</div>' if demo else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>cvewatch report</title><style>
:root{{--bg:#0A0F1C;--card:#111827;--line:#1F2A3D;--text:#E5E7EB;--muted:#94A3B8}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
header{{padding:22px 28px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px}}
h1{{margin:0;font-size:22px}} h1 span{{color:#F97316}} h2{{font-size:16px;margin:28px 0 10px}}
main{{padding:0 28px 40px}} small{{color:var(--muted)}} a{{color:#60A5FA;text-decoration:none}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:20px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.tile .n{{font-size:28px;font-weight:700}} .tile .l{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%}} th,td{{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:#0D1424;position:sticky;top:0}}
.c{{text-align:center;font-weight:700}} .P1{{color:#EF4444}} .P2{{color:#F97316}} .P3{{color:#EAB308}} .P4{{color:#64748B}}
.kev,.rw{{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:4px}} .kev{{background:#EF4444;color:#fff}} .rw{{background:#7F1D1D;color:#FECACA}}
.nw{{white-space:nowrap}} .demo{{background:#7C2D12;color:#FED7AA;padding:8px 28px;font-size:13px}} .warn{{color:#EAB308;font-weight:600}} .bad{{color:#EF4444}} tr.acc td{{opacity:.5}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}} select,input{{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 8px}}
footer{{color:var(--muted);font-size:12px;padding:16px 28px;border-top:1px solid var(--line)}}
</style></head><body>
<header><h1><span>cve</span>watch report</h1><small>generated {e(now_iso())} · last scan {e(str(ls.get('finished', ''))[:16])} · {ls.get('new', 0)} new · {ls.get('resolved', 0)} resolved</small></header>
{banner}<main>
<div class="tiles">{tile_html}</div>
<h2>Hosts</h2>
<div class="wrap"><table><tr><th>Host</th><th>System</th><th>Exposure / criticality</th><th>Packages</th><th>Security updates waiting</th><th>P1</th><th>P2</th><th>P3</th><th>P4</th><th>State</th><th>Last scan</th></tr>{host_rows}</table></div>
<h2>Open findings</h2>
<div class="filters"><select id="fp"><option value="">All priorities</option><option>P1</option><option>P2</option><option>P3</option><option>P4</option></select>
<select id="fh"><option value="">All hosts</option>{hosts_opts}</select><input id="fq" placeholder="Search CVE, package, text" size="30"></div>
<div class="wrap"><table id="ft"><tr><th>Prio</th><th>Host</th><th>Vulnerability</th><th>Package / installed</th><th>Fixed in</th><th>Severity</th><th>EPSS</th><th>First seen</th></tr>{frows}</table></div>
<h2>Mean time to remediate</h2><p>{e(mttr)}</p>
</main>
<footer>cvewatch {VERSION} · data: OSV.dev, CISA KEV, FIRST EPSS · priority = KEV/EPSS + exposure + severity + fix availability · https://dargslan.com</footer>
<script>
const fp=document.getElementById('fp'),fh=document.getElementById('fh'),fq=document.getElementById('fq');
function f(){{const p=fp.value,h=fh.value,q=fq.value.toLowerCase();
document.querySelectorAll('#ft tr[data-p]').forEach(r=>{{r.style.display=(!p||r.dataset.p===p)&&(!h||r.dataset.h===h)&&(!q||r.textContent.toLowerCase().includes(q))?'':'none'}})}}
[fp,fh,fq].forEach(x=>x.addEventListener('input',f));
</script></body></html>"""


# --------------------------------------------------------------------------- status

def status(cfg):
    db = open_db(cfg.get("general", "data_dir"))
    m = metrics(db)
    o = m["open"]
    print(f"open findings  P1 {o['P1']}  P2 {o['P2']}  P3 {o['P3']}  P4 {o['P4']}   KEV {m['kev']}   accepted {m['accepted']}")
    print(f"{'HOST':22} {'OS':28} {'PKGS':>5} {'SEC':>4} {'P1':>3} {'P2':>3} {'P3':>4} {'P4':>4}  STATE")
    for h in m["hosts"]:
        c = {p: 0 for p in PRIORITIES}
        for r in db.execute("SELECT priority, COUNT(*) n FROM findings WHERE host=? AND status='open' GROUP BY priority", (h["name"],)):
            c[r["priority"]] = r["n"]
        state = "reboot" if h.get("reboot_required") else ""
        if h.get("last_error"):
            state = "ERROR " + h["last_error"][:40]
        print(f"{h['name'][:22]:22} {(h.get('os') or '')[:28]:28} {h.get('packages') or 0:>5} {h.get('security_updates') or 0:>4} "
              f"{c['P1']:>3} {c['P2']:>3} {c['P3']:>4} {c['P4']:>4}  {state}")
    top = db.execute("SELECT * FROM findings WHERE status='open' AND priority IN ('P1','P2') ORDER BY priority, kev DESC, "
                     "COALESCE(epss,0) DESC LIMIT 15").fetchall()
    if top:
        print("\nP1/P2 findings:")
        for r in top:
            print(f"  {r['priority']} {r['host']:16} {r['vuln']:16} {r['package']:18} {'KEV ' if r['kev'] else ''}"
                  f"EPSS {_fmt_epss(r['epss']) or '-'}  fix: {r['fixed'] or 'none yet'}")
    return 0


# --------------------------------------------------------------------------- selftest

def selftest(args):
    here = os.path.dirname(os.path.abspath(__file__))
    fixtures = args.fixtures or os.path.join(here, "tests", "fixtures")
    assert deb_cmp("1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.5") < 0
    assert deb_cmp("2.0~rc1", "2.0") < 0 and deb_cmp("1.0-1", "1.0-1") == 0 and deb_cmp("1:1.0", "2.0") > 0
    assert rpm_cmp("1:3.0.7-24.el9", "1:3.0.7-27.el9") < 0 and rpm_cmp("2.0~rc1-1", "2.0-1") < 0
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 7.8
    assert osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.04"}) == "Ubuntu:24.04:LTS"
    assert osv_ecosystem({"ID": "debian", "VERSION_ID": "13"}) == "Debian:13"
    assert osv_ecosystem({"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "UBUNTU_CODENAME": "noble"}) == "Ubuntu:24.04:LTS"
    log("unit checks passed (version comparison, CVSS, ecosystems)")
    if not os.path.isdir(fixtures):
        log(f"fixtures not found at {fixtures}", "ERROR")
        return 1
    tmp = args.out or tempfile.mkdtemp(prefix="cvewatch-selftest-")
    cfg = load_config(None)
    cfg.set("general", "data_dir", os.path.join(tmp, "data"))
    cfg.set("general", "report_dir", os.path.join(tmp, "reports"))
    cfg.set("general", "exceptions_file", os.path.join(fixtures, "exceptions.csv"))
    cfg.set("output", "prometheus_file", os.path.join(tmp, "reports", "cvewatch.prom"))
    ns = argparse.Namespace(fixtures=fixtures, hosts=os.path.join(fixtures, "hosts.ini"), local_only=False,
                            no_alerts=True, fail_on=None)
    rc = scan(cfg, ns)
    db = open_db(cfg.get("general", "data_dir"))
    n = db.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0]
    p1 = db.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND priority='P1'").fetchone()[0]
    assert n > 0 and p1 > 0, "expected demo findings"
    # second run with the patched inventory: findings must resolve
    ns.hosts = os.path.join(fixtures, "hosts_patched.ini")
    scan(cfg, ns)
    left = db.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND host='demo-web01'").fetchone()[0]
    res = db.execute("SELECT COUNT(*) FROM findings WHERE status='resolved'").fetchone()[0]
    assert res > 0, "expected resolved findings after patching"
    log(f"selftest passed: {n} demo findings, {p1} P1, {res} resolved after patching, {left} still open on demo-web01")
    log(f"demo report: {os.path.join(tmp, 'reports', 'cvewatch-report.html')}")
    return 0 if rc in (0, 1) else rc


# --------------------------------------------------------------------------- CLI

def main(argv=None):
    global QUIET
    ap = argparse.ArgumentParser(prog="cvewatch", description="Automated CVE tracking for Linux hosts")
    ap.add_argument("-c", "--config", default=os.environ.get("CVEWATCH_CONFIG", "/etc/cvewatch/cvewatch.ini"))
    ap.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("collect", help="print this host's package inventory as JSON")
    p.add_argument("-o", "--output")
    p = sub.add_parser("scan", help="collect, analyse, store, report and alert")
    p.add_argument("--hosts", help="hosts file (default from config)")
    p.add_argument("--local-only", action="store_true", help="scan only this machine")
    p.add_argument("--no-alerts", action="store_true")
    p.add_argument("--fail-on", choices=PRIORITIES, help="exit 2 if open findings at or above this priority")
    p.add_argument("--fixtures", default=os.environ.get("CVEWATCH_FIXTURES"), help=argparse.SUPPRESS)
    sub.add_parser("report", help="rebuild reports from the database")
    sub.add_parser("status", help="summary in the terminal")
    p = sub.add_parser("selftest", help="offline test with demo data")
    p.add_argument("--fixtures")
    p.add_argument("--out", help="directory for the demo database and report")
    sub.add_parser("config", help="print the default configuration")
    sub.add_parser("version")
    args = ap.parse_args(argv)
    QUIET = args.quiet
    if args.cmd == "collect":
        inv = collect_local()
        data = json.dumps(inv, indent=1)
        if args.output:
            open(args.output, "w").write(data)
        else:
            print(data)
        return 0
    if args.cmd == "version":
        print(VERSION)
        return 0
    if args.cmd == "config":
        print(DEFAULT_CONFIG)
        return 0
    if args.cmd == "selftest":
        return selftest(args)
    cfg = load_config(args.config)
    if args.cmd == "scan":
        return scan(cfg, args)
    if args.cmd == "report":
        write_reports(open_db(cfg.get("general", "data_dir")), cfg)
        return 0
    if args.cmd == "status":
        return status(cfg)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
