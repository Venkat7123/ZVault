#!/usr/bin/env bash
# start_alerts.sh - start the ZVault alert engine (reads ACCESS_LOG, writes ALERTS).
# Its Db2 password lives in its own file ~/.botsbank_alerts_env (chmod 600), e.g.:
#   ALERTSVC_PASSWORD=...
# Optional: ALERT_WORK_HOURS=8-20 (IST), ALERT_POLL_SECONDS=30, ALERT_USE_GRANITE=1
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE="$HOME/.botsbank_alerts_env"
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE - create it first (see the comment at the top of this file)."
  exit 1
fi
set -a; . "$ENV_FILE"; set +a

source "$HOME/venv/bin/activate"
exec python -m alerts.run "$@"
