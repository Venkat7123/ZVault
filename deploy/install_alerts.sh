#!/usr/bin/env bash
# install_alerts.sh - run the ZVault alert engine as a Linux (systemd) service.
# Run once on LinuxONE, AFTER sql/07_alerts.sql is applied and ~/.botsbank_alerts_env exists:
#   bash ~/botsbank-project/deploy/install_alerts.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$HOME/.botsbank_alerts_env" ] || { echo "Missing ~/.botsbank_alerts_env (ALERTSVC_PASSWORD=...)"; exit 1; }
chmod 600 "$HOME/.botsbank_alerts_env"
chmod +x "$DIR/../start_alerts.sh"

echo "1. One test pass (prints what it would raise, writes nothing)..."
"$DIR/../start_alerts.sh" --dry-run

echo "2. Installing the service..."
sudo cp "$DIR/botsbank-alerts.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now botsbank-alerts.service
sleep 3
systemctl --no-pager --lines=5 status botsbank-alerts | grep -E "●|Active:|alert" || true
echo "Watch it:  journalctl -u botsbank-alerts -f   (Ctrl+c to stop watching)"
