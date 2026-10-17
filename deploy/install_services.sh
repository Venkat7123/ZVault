#!/usr/bin/env bash
# install_services.sh - deploy Bots Bank as Linux (systemd) services.
# After this, Db2, Granite and the gateway start on boot and restart if they crash.
# Run once on LinuxONE:  bash ~/botsbank-project/deploy/install_services.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$HOME/.botsbank_env" ] || { echo "Missing ~/.botsbank_env (passwords file)"; exit 1; }
chmod +x "$DIR/../start_gateway.sh"

echo "1. Stopping the old tmux versions (if running)..."
tmux kill-session -t ai 2>/dev/null || true
pkill -f "uvicorn botsbank.main:app" 2>/dev/null || true
pkill -f "llama-server" 2>/dev/null || true
sleep 2

echo "2. Db2 container: start automatically after a reboot..."
sudo docker update --restart unless-stopped db2 >/dev/null
sudo docker start db2 >/dev/null

echo "3. Installing the two services..."
sudo cp "$DIR/botsbank-llm.service" "$DIR/botsbank-gateway.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now botsbank-llm.service botsbank-gateway.service

echo "4. Waiting for them to be ready..."
for i in $(seq 1 36); do
  curl -sf 127.0.0.1:8080/health >/dev/null && curl -sf 127.0.0.1:8000/health >/dev/null && break
  printf "."; sleep 5
done
echo
systemctl --no-pager --lines=0 status botsbank-llm botsbank-gateway | grep -E "●|Active:"
echo "Health: $(curl -s 127.0.0.1:8000/health)"
echo "If \"db\" is false, Db2 is still starting: wait 2 minutes and run  curl -s 127.0.0.1:8000/health"
