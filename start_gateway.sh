#!/usr/bin/env bash
# start_gateway.sh - start the Bots Bank secure AI gateway on LinuxONE.
# Secrets are read from ~/.botsbank_env (create it once, chmod 600), e.g.:
#   DB_GW_PASSWORD=...
#   DEMO_PASSWORD=...
#   JWT_SECRET=<64 hex chars>
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE="$HOME/.botsbank_env"
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE - create it first (see the comment at the top of this file)."
  exit 1
fi
set -a; . "$ENV_FILE"; set +a

source "$HOME/venv/bin/activate"
exec uvicorn botsbank.main:app --host 127.0.0.1 --port 8000
