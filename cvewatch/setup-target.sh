#!/usr/bin/env bash
# Prepare a host to be scanned by cvewatch - run on each target as root.
#   sudo ./setup-target.sh "ssh-ed25519 AAAA... cvewatch@scanner" [scanner-ip]
# Creates an unprivileged user 'cvewatch' whose SSH key can only run the
# read-only inventory collector, optionally only from the scanner's address.
set -euo pipefail
KEY="${1:?usage: setup-target.sh \"PUBLIC-KEY\" [scanner-ip]}"
FROM="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
PY="$(command -v python3 || true)"
[[ -z "$PY" && -x /usr/libexec/platform-python ]] && PY=/usr/libexec/platform-python
[[ -n "$PY" ]] || { echo "python3 is required on the target" >&2; exit 1; }

install -d -m 0755 /usr/local/lib/cvewatch
install -m 0755 "$HERE/cvewatch.py" /usr/local/lib/cvewatch/cvewatch.py
id cvewatch >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/cvewatch --shell /bin/sh cvewatch
passwd -l cvewatch >/dev/null 2>&1 || true
install -d -o cvewatch -g cvewatch -m 0700 /var/lib/cvewatch/.ssh
OPTS="restrict,command=\"$PY /usr/local/lib/cvewatch/cvewatch.py collect\""
[[ -n "$FROM" ]] && OPTS="from=\"$FROM\",$OPTS"
echo "$OPTS $KEY" > /var/lib/cvewatch/.ssh/authorized_keys
chown cvewatch:cvewatch /var/lib/cvewatch/.ssh/authorized_keys
chmod 0600 /var/lib/cvewatch/.ssh/authorized_keys
echo "target ready: user cvewatch may only run the inventory collector${FROM:+ from $FROM}"
echo "test from the scanner:  sudo -u cvewatch ssh cvewatch@$(hostname -f) | head"
