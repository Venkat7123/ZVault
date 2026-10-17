#!/usr/bin/env bash
# start_all.sh - start the Bots Bank services on LinuxONE, in order:
#   1. Db2 container  2. Granite (llama-server :8080)  3. gateway (:8000)
# Granite and the gateway run in tmux session "ai" (see them: tmux attach -t ai).

MODEL="$HOME/models/granite-3.3-2b-instruct-Q8_0.gguf"
LLAMA="$HOME/llama.cpp/build/bin/llama-server"
PROJECT="$(cd "$(dirname "$0")" && pwd)"

wait_for() {  # wait_for <name> <seconds> <command...>
  local name=$1 max=$2; shift 2
  printf "Waiting for %s " "$name"
  for ((i = 0; i < max; i += 5)); do
    if "$@" >/dev/null 2>&1; then echo " ready"; return 0; fi
    printf "."; sleep 5
  done
  echo " NOT ready after ${max}s"; return 1
}

if [ ! -f "$HOME/.botsbank_env" ]; then
  echo "Missing ~/.botsbank_env (passwords file). Create it first."; exit 1
fi

# 1. Db2
echo "Starting Db2..."
sudo docker start db2 >/dev/null || { echo "Could not start the db2 container"; exit 1; }
wait_for "Db2" 300 sudo docker exec db2 su - db2inst1 -c "db2 connect to BOTSBANK" \
  || { echo "Db2 did not come up. Check: sudo docker logs --tail 50 db2"; exit 1; }

# Deployed as systemd services (deploy/install_services.sh)? Then use those.
if [ -f /etc/systemd/system/botsbank-gateway.service ]; then
  echo "Restarting services botsbank-llm and botsbank-gateway..."
  sudo systemctl restart botsbank-llm botsbank-gateway
  wait_for "Granite" 180 curl -sf 127.0.0.1:8080/health
  wait_for "gateway" 60 curl -sf 127.0.0.1:8000/health
  echo; echo "Health: $(curl -s 127.0.0.1:8000/health)"
  echo "Logs: journalctl -u botsbank-gateway -f   (Ctrl+c to stop watching)"
  exit 0
fi

# 2 + 3. Fresh tmux session with Granite and the gateway
tmux kill-session -t ai 2>/dev/null
pkill -f "uvicorn botsbank.main:app" 2>/dev/null

echo "Starting Granite..."
tmux new-session -d -s ai -n granite \
  "$LLAMA -m $MODEL --host 127.0.0.1 --port 8080 -c 4096 -t 3; read -p 'Granite stopped - press Enter'"
wait_for "Granite" 180 curl -sf 127.0.0.1:8080/health \
  || { echo "Granite did not come up. Check: tmux attach -t ai"; exit 1; }

echo "Starting gateway..."
tmux new-window -t ai -n gateway \
  "$PROJECT/start_gateway.sh; read -p 'Gateway stopped - press Enter'"
wait_for "gateway" 60 curl -sf 127.0.0.1:8000/health \
  || { echo "Gateway did not come up. Check: tmux attach -t ai"; exit 1; }

echo
echo "Health: $(curl -s 127.0.0.1:8000/health)"
echo "All started. Expect \"db\":true and \"llm\":true above."
echo "On your laptop, open the tunnel and browse to http://localhost:8000"
