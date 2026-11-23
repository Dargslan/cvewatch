# cvewatch

Automated CVE tracking for Linux hosts. One Python file, standard library only.

cvewatch collects the installed packages of every host you list (locally or agentless over SSH), looks them up in **OSV.dev** (Debian, Ubuntu, AlmaLinux, Rocky Linux and Alpine security data, including backported fixes), enriches every CVE with the **CISA KEV** catalogue and **FIRST EPSS** scores, ranks it P1 to P4 from exploitation, exposure, severity and fix availability, keeps history in **SQLite**, writes an **HTML/CSV/JSON report** and **Prometheus metrics**, and alerts on new P1/P2 findings via **ntfy, webhook or email**.

## Quick start

```bash
sudo ./install.sh                          # program, user, config, SSH key, self-test, daily timer
sudoedit /etc/cvewatch/hosts.ini           # list your hosts
sudo ./setup-target.sh "<scanner public key>" <scanner-ip>   # on every remote host
sudo systemctl start cvewatch.service      # first scan
sudo -u cvewatch cvewatch status           # summary in the terminal
```

Report: `/var/lib/cvewatch/reports/cvewatch-report.html`

## Commands

| Command | Purpose |
| --- | --- |
| `cvewatch scan` | Collect, analyse, store, report, alert (`--local-only`, `--hosts FILE`, `--no-alerts`, `--fail-on P1`) |
| `cvewatch status` | Open findings per host and the current P1/P2 list |
| `cvewatch report` | Rebuild reports from the database |
| `cvewatch collect` | Print this host's inventory as JSON (used over SSH) |
| `cvewatch selftest` | Offline test with demo data; writes a demo report |
| `cvewatch config` | Print the default configuration |

Run commands as the `cvewatch` user (`sudo -u cvewatch cvewatch status`) so the database stays writable for the timer.

## Supported systems

| Family | Detection | Notes |
| --- | --- | --- |
| Ubuntu (LTS and interim), Linux Mint and other Ubuntu derivatives | OSV `Ubuntu:<version>[:LTS]` | Source packages; backports handled by Ubuntu data |
| Debian, Raspberry Pi OS, Proxmox VE | OSV `Debian:<major>` | Source packages |
| AlmaLinux, Rocky Linux | OSV + `dnf updateinfo` | Source RPM names |
| RHEL, Fedora, CentOS Stream, Oracle Linux | `dnf updateinfo --security` | Advisories, no CVE-level detail |
| Alpine | OSV `Alpine:v<x.y>` | Origin packages |

## Files

| Path | Content |
| --- | --- |
| `/usr/local/lib/cvewatch/` | Program, self-test fixtures, README |
| `/etc/cvewatch/cvewatch.ini` | Configuration |
| `/etc/cvewatch/hosts.ini` | Hosts to scan |
| `/etc/cvewatch/exceptions.csv` | Accepted risks with expiry dates |
| `/var/lib/cvewatch/cvewatch.db` | SQLite history |
| `/var/lib/cvewatch/reports/` | HTML, CSV, JSON reports |
| `/var/lib/cvewatch/cache/` | OSV, KEV and EPSS cache |

## Network access

The scanner needs HTTPS to `api.osv.dev`, `www.cisa.gov` and `api.first.org` (proxy variables such as `HTTPS_PROXY` are honoured). Remote hosts need only an SSH connection from the scanner. Nothing is sent anywhere except package names and versions to OSV.dev and CVE IDs to FIRST.

## Licence

MIT. (c) 2026 Dargslan - https://dargslan.com
