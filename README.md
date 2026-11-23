<h1 align="center">cvewatch</h1> <p align="center"> <b>Automated CVE tracking for Linux hosts.</b><br> Know every morning which of your servers are vulnerable, which three findings matter, and get an alert only when something new does. </p> <p align="center"> <img alt="Python 3.8+" src="https://img.shields.io/badge/python-3.8%2B-3776AB"> <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-2DD4BF"> <img alt="Agentless over SSH" src="https://img.shields.io/badge/agentless-SSH-F97316"> <img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-4ADE80"> </p> <p align="center"><img src="docs/report.png" alt="cvewatch HTML report (self-test demo data)" width="900"></p>

cvewatch collects the installed packages of every host you list, locally or agentless over SSH. It looks them up in OSV.dev, which carries the security data of Debian, Ubuntu, AlmaLinux, Rocky Linux and Alpine, including backported fixes. Every CVE is enriched with the CISA KEV catalogue and FIRST EPSS scores and ranked P1 to P4 by exploitation, exposure, severity and fix availability. History is kept in SQLite. Each scan writes an HTML/CSV/JSON report and Prometheus metrics, and new P1/P2 findings are sent to ntfy, a webhook or email.

One Python file. Standard library only. Read-only on the hosts it checks.

Contents
Why cvewatch
Features
Quick start
How it works
Prioritisation
Scanning remote hosts
Configuration
Commands
Supported systems
Files
Security model
Network and privacy
Limitations
FAQ
Contributing
Licence
Why cvewatch

unattended-upgrades and dnf-automatic install fixes. They do not tell you:

which hosts are affected when a serious CVE is published,
whether updates actually installed and whether the running kernel is the patched one,
what to fix first among hundreds of open CVEs,
whether things are getting better over time.

Network scanners see ports and banners, not package versions. Commercial vulnerability platforms cost money per asset. cvewatch fills the gap for home labs, small teams and anyone who wants a transparent, auditable tool they can read in an afternoon.

Features
	
Inventory	dpkg, rpm and apk packages, source package names, running kernel, reboot-required state, pending security updates
Matching	OSV.dev querybatch with distro ecosystems (Ubuntu:24.04:LTS, Debian:13, AlmaLinux:9, ...), native dpkg and rpm version comparison
Enrichment	CISA KEV (incl. ransomware flag), FIRST EPSS, CVSS 3.x base score and attack vector
Prioritisation	P1-P4 from KEV, EPSS, exposure, attack vector, severity, fix availability and host criticality
Collection	local, SSH push mode (nothing installed on targets), SSH installed mode, offline file: inventories
Least privilege	dedicated cvewatch user, SSH key restricted to one forced command and the scanner's IP
History	SQLite: first seen, resolved, reopened, mean time to remediate
Exceptions	accepted risks in a CSV with expiry dates
Output	static HTML report with filters, CSV, JSON summary, Prometheus textfile metrics
Alerts	ntfy (phone push), generic webhook (Slack, Teams, Discord, Mattermost), email; only new P1/P2 by default
Operations	hardened systemd service and timer, --fail-on exit codes for CI gates, offline self-test
Quick start

On the machine that will be the scanner (Debian/Ubuntu/RHEL family, Python 3.8+):

bash
git clone https://github.com/<your-account>/cvewatch.git
cd cvewatch
sudo ./install.sh                          # program, user, config, SSH key, self-test, daily timer
sudo -u cvewatch cvewatch scan --local-only
sudo -u cvewatch cvewatch status

Open the report at /var/lib/cvewatch/reports/cvewatch-report.html.

Try it without installing anything. The self-test runs offline with demo data:

bash
python3 cvewatch.py selftest
How it works
 hosts.ini ──► collect ──► OSV.dev ──► KEV + EPSS ──► prioritise ──► SQLite ──► report + alerts
   local        dpkg/rpm/apk   distro      exploited?     P1..P4         history     HTML · CSV · JSON
   SSH          kernel         security    likely?                       resolved?   Prometheus
   file:        reboot flag    data                                                  ntfy · webhook · mail
Collect the package inventory of each host (read-only).
Match source packages against OSV.dev distro data. Versions are compared with real dpkg/rpm rules, so backported fixes such as 3.0.13-0ubuntu3.4 are handled correctly.
Enrich each CVE with KEV, EPSS and the CVSS vector.
Prioritise P1 to P4 (see below), apply exceptions.
Remember in SQLite: new, still open, resolved, reopened.
Report and alert: rewrite the reports, send one message per channel for new P1/P2 findings and failed hosts.
Prioritisation
Priority	Rule	Suggested target
P1	(in KEV or EPSS ≥ 0.5) and host exposure is internet and the attack vector is not local/physical	48 hours
P2	in KEV, or EPSS ≥ 0.1, or (CVSS ≥ 9 and exposed and a fix exists)	7 days
P3	CVSS ≥ 7 and a fix exists	30 days
P4	everything else	next maintenance

Hosts with criticality = high move every finding up one level. The EPSS thresholds are configurable ([priority] p1_epss, p2_epss).

Local privilege-escalation bugs (AV:L) never count as "exposed" on their own, so an exploited kernel EoP on a web server is P2, not P1. On a high-criticality host it becomes P1.

Scanning remote hosts

cvewatch is agentless. In the default push mode the scanner pipes the collector to python3 - over SSH, so nothing is installed on the target.

1. On each target, authorise the scanner's key for one command only:

bash
sudo ./setup-target.sh "$(cat scanner_key.pub)" 192.168.10.5

This creates a cvewatch user with a locked password and adds the key as:

from="192.168.10.5",restrict,command="/usr/bin/python3 /usr/local/lib/cvewatch/cvewatch.py collect" ssh-ed25519 AAAA...

The key cannot open a shell, forward ports or run anything else, and it only works from the scanner's address. An Ansible playbook for many hosts is in examples/ansible-setup-targets.yml.

2. On the scanner, list the host in /etc/cvewatch/hosts.ini:

ini
[web01]
address = 192.168.10.20
user = cvewatch
exposure = internet      # internet | lan | internal | isolated
criticality = high       # high | medium | low

[nas01]
address = file:/srv/inventories/nas01.json   # offline host
exposure = isolated

3. Confirm the host key once (sudo -u cvewatch ssh cvewatch@192.168.10.20) and run a scan.

Configuration

/etc/cvewatch/cvewatch.ini (print all defaults with cvewatch config):

ini
[general]
data_dir = /var/lib/cvewatch
hosts_file = /etc/cvewatch/hosts.ini
exceptions_file = /etc/cvewatch/exceptions.csv
cache_hours = 20
keep_reports = 30

[priority]
p1_epss = 0.5
p2_epss = 0.1

[alerts]
min_priority = P2
ntfy_url = https://ntfy.sh/your-long-random-topic
webhook_url =
email_to =

[output]
prometheus_file = /var/lib/cvewatch/cvewatch.prom

Exceptions (/etc/cvewatch/exceptions.csv) record accepted risks with an end date:

# vuln,host,expires,reason
CVE-2023-50495,docker01,2027-03-01,tic is not used on this host; Ubuntu priority low

Expired exceptions stop applying and the finding alerts again.

Commands
Command	Purpose
cvewatch scan	Collect, analyse, store, report, alert (--local-only, --hosts FILE, --no-alerts, --fail-on P1)
cvewatch status	Open findings per host and the current P1/P2 list
cvewatch report	Rebuild reports from the database
cvewatch collect	Print this host's inventory as JSON (used over SSH)
cvewatch selftest	Offline test with demo data; writes a demo report
cvewatch config	Print the default configuration
cvewatch version	Print the version

Global options: -c CONFIG (or CVEWATCH_CONFIG), -q for warnings and errors only.

Run commands as the cvewatch user (sudo -u cvewatch cvewatch status) so the database stays writable for the timer.

Exit codes of scan: 0 ok, 1 at least one host failed, 2 the --fail-on threshold was reached. Use it as a gate in CI or image pipelines:

bash
cvewatch scan --hosts new-image.ini --no-alerts --fail-on P2 || echo "image has open P1/P2 vulnerabilities"
Supported systems
Family	Detection	Notes
Ubuntu (LTS and interim), Linux Mint and other derivatives	OSV Ubuntu:<version>[:LTS]	Source packages; backports handled by Ubuntu data
Debian, Raspberry Pi OS, Proxmox VE	OSV Debian:<major>	Source packages
AlmaLinux, Rocky Linux	OSV + dnf updateinfo	Source RPM names
RHEL, Fedora, CentOS Stream, Oracle Linux	dnf updateinfo --security	Advisories, no CVE-level detail
Alpine	OSV Alpine:v<x.y>	Origin packages

Targets need Python 3 (on RHEL 8 set python = /usr/libexec/platform-python) and an SSH server.

Files
Path	Content
/usr/local/lib/cvewatch/	Program, self-test fixtures, README
/etc/cvewatch/cvewatch.ini	Configuration
/etc/cvewatch/hosts.ini	Hosts to scan
/etc/cvewatch/exceptions.csv	Accepted risks with expiry dates
/var/lib/cvewatch/cvewatch.db	SQLite history
/var/lib/cvewatch/reports/	HTML, CSV, JSON reports and dated archive
/var/lib/cvewatch/cache/	OSV, KEV and EPSS cache

Repository layout:

cvewatch.py              the program (single file)
install.sh               install | uninstall | purge on the scanner
setup-target.sh          prepare a remote host (user + restricted key)
systemd/                 hardened service and daily timer (06:15, randomised)
examples/                config, hosts, exceptions, Ansible playbook, nginx for reports
tests/fixtures/          demo data for the self-test
docs/                    screenshots
Security model
Read-only targets. The collector only reads the package database and a few files under /proc, /etc and /var/run.
Restricted key. from=, restrict and a forced command= limit the scanner's key to one action from one address.
Unprivileged scanner. The systemd service runs as cvewatch with ProtectSystem=strict, ProtectHome, NoNewPrivileges and a single writable path.
Sensitive output. Reports list unpatched hosts. /var/lib/cvewatch is not world-readable. Put the report behind authentication if you publish it (see examples/nginx-reports.conf).

Found a security issue in cvewatch itself? See SECURITY.md.

Network and privacy

The scanner needs HTTPS to api.osv.dev, www.cisa.gov and api.first.org. HTTPS_PROXY and similar variables are honoured. Targets need only an SSH connection from the scanner.

Only package names and versions go to OSV.dev and only CVE IDs go to FIRST. Host names, IP addresses and findings never leave your network.

Limitations
cvewatch reports known vulnerabilities in distro packages. It does not see software installed outside the package manager (tarballs, pip, npm, container images). Use a container or SBOM scanner for those.
RHEL and Fedora without OSV coverage are reported from dnf security advisories, without per-CVE detail.
The CVSS score comes from OSV data where available; distro severity ratings can differ.
It is not an intrusion detection or configuration-audit tool.
FAQ

Does it install anything on my servers? Not in push mode. setup-target.sh only creates a user and an authorized_keys entry. The collector is streamed over SSH at scan time.

How long does a scan take? Seconds for one host after the first run. OSV queries are batched (up to 1000 packages per request) and KEV/EPSS are cached for cache_hours.

Why is a CVE I patched still shown? Usually the fix is installed but not active: the kernel or a library needs a reboot or a service restart. The report shows reboot in the host state.

Can I use it in CI? Yes. --fail-on P1 (or P2) returns exit code 2 when such findings are open.

Is there a Windows version? A sister project for Windows is described in the guide below.

The guide

cvewatch is the companion toolkit of the guide "Automate Linux CVE Tracking" (63 pages, PDF + EPUB, with a 20-slide deck). It explains every design decision, the security model, alerts, exceptions, dashboards, automatic remediation and a daily routine. Available at dargslan.com.

Contributing

Issues and pull requests are welcome. Please read CONTRIBUTING.md first. In short: keep it one file, standard library only, and make python3 cvewatch.py selftest pass.

Licence

MIT © 2026 Dargslan · dargslan.com · YouTube @Dargslan

Vulnerability data: OSV.dev (CC-BY 4.0 and source licences), CISA KEV (public domain), FIRST EPSS. cvewatch is not affiliated with these projects.
