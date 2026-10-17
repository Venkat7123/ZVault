#!/usr/bin/env bash
# stop_all.sh - stop the Bots Bank services on LinuxONE.
# Stops: gateway + Granite (tmux session "ai") and the Db2 container.
# Keeps: all data, users, passwords and files. The Jupyter container is not touched.

echo "Stopping gateway and Granite..."
if [ -f /etc/systemd/system/botsbank-gateway.service ]; then
  sudo systemctl stop botsbank-gateway botsbank-llm
fi
tmux kill-session -t ai 2>/dev/null
pkill -f "uvicorn botsbank.main:app" 2>/dev/null
pkill -f "llama-server" 2>/dev/null

echo "Stopping Db2 (this can take a minute)..."
sudo docker stop db2 >/dev/null 2>&1

sleep 2
echo
pgrep -af "uvicorn|llama-server" && echo "WARNING: something is still running" \
  || echo "Gateway and Granite: stopped"
sudo docker ps --filter name=db2 --format '{{.Names}}' | grep -q db2 \
  && echo "WARNING: Db2 still running" || echo "Db2: stopped"
