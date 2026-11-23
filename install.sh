#!/usr/bin/env bash
# cvewatch installer - run on the scanner host as root
#   sudo ./install.sh            install or upgrade
#   sudo ./install.sh uninstall  remove program and units (keeps data and config)
#   sudo ./install.sh purge      remove everything, including data and config
set -euo pipefail

PREFIX=/usr/local/lib/cvewatch
BIN=/usr/local/bin/cvewatch
CONF=/etc/cvewatch
DATA=/var/lib/cvewatch
UNITS=/etc/systemd/system
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
as_cvewatch() { if command -v runuser >/dev/null; then runuser -u cvewatch -- "$@"; else sudo -u cvewatch "$@"; fi; }
has_systemd() { [[ -d /run/systemd/system ]]; }

[[ $EUID -eq 0 ]] || die "run as root: sudo ./install.sh"
command -v python3 >/dev/null || die "python3 is required (apt install python3 / dnf install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python 3.8 or newer is required"

uninstall() {
    if has_systemd; then
        systemctl disable --now cvewatch.timer 2>/dev/null || true
        rm -f "$UNITS/cvewatch.service" "$UNITS/cvewatch.timer"
        systemctl daemon-reload
    fi
    rm -f "$BIN"
    rm -rf "$PREFIX"
    say "program removed; data in $DATA and configuration in $CONF were kept"
}

case "${1:-install}" in
uninstall) uninstall; exit 0 ;;
purge)
    uninstall
    rm -rf "$DATA" "$CONF"
    id cvewatch >/dev/null 2>&1 && userdel cvewatch || true
    say "data, configuration and user removed"
    exit 0 ;;
install) ;;
*) die "unknown command: $1" ;;
esac

say "installing program to $PREFIX"
install -d -m 0755 "$PREFIX"
install -m 0755 "$HERE/cvewatch.py" "$PREFIX/cvewatch.py"
cp -r "$HERE/tests" "$PREFIX/" 2>/dev/null || true
[[ -f "$HERE/README.md" ]] && install -m 0644 "$HERE/README.md" "$PREFIX/README.md"
ln -sf "$PREFIX/cvewatch.py" "$BIN"

if ! id cvewatch >/dev/null 2>&1; then
    say "creating system user cvewatch"
    useradd --system --home-dir "$DATA" --create-home --shell /usr/sbin/nologin cvewatch
fi
install -d -o cvewatch -g cvewatch -m 0750 "$DATA" "$DATA/reports" "$DATA/.ssh"
chmod 0700 "$DATA/.ssh"
chown -R cvewatch:cvewatch "$DATA"   # files created by earlier root runs

say "configuration in $CONF"
install -d -m 0755 "$CONF"
for f in cvewatch.ini hosts.ini exceptions.csv; do
    if [[ ! -f "$CONF/$f" ]]; then
        install -m 0640 -o root -g cvewatch "$HERE/examples/$f" "$CONF/$f"
    else
        echo "    keeping existing $CONF/$f"
    fi
done

if [[ ! -f "$DATA/.ssh/id_ed25519" ]]; then
    say "creating SSH key for remote scans"
    as_cvewatch ssh-keygen -q -t ed25519 -N "" -C "cvewatch@$(hostname)" -f "$DATA/.ssh/id_ed25519"
fi

say "running self-test"
as_cvewatch "$BIN" -q selftest --fixtures "$PREFIX/tests/fixtures" --out "$DATA/selftest" \
    && echo "    self-test passed - demo report: $DATA/selftest/reports/cvewatch-report.html"

if has_systemd; then
    say "installing systemd service and daily timer"
    install -m 0644 "$HERE/systemd/cvewatch.service" "$UNITS/cvewatch.service"
    install -m 0644 "$HERE/systemd/cvewatch.timer" "$UNITS/cvewatch.timer"
    systemctl daemon-reload
    systemctl enable --now cvewatch.timer
    systemctl list-timers cvewatch.timer --no-pager | head -3
else
    say "no systemd found - add a cron job instead:"
    echo "    15 6 * * * cvewatch /usr/local/bin/cvewatch -q scan   (in /etc/cron.d/cvewatch)"
fi

cat <<MSG

cvewatch $("$BIN" version) installed.

Next steps
  1. Edit the hosts to scan:        sudoedit $CONF/hosts.ini
  2. Prepare each remote host with: sudo ./setup-target.sh "$(cat "$DATA/.ssh/id_ed25519.pub")" <scanner-ip>
  3. Run the first scan:            sudo systemctl start cvewatch.service && journalctl -u cvewatch -f
  4. Open the report:               $DATA/reports/cvewatch-report.html
MSG
