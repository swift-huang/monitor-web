#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="/opt/monitor-web"
VENV="$APP_ROOT/venv"
BACKEND="$APP_ROOT/backend"
LOG_DIR="/var/log/monitor-web"

mkdir -p "$BACKEND/data" "$BACKEND/cache" "$LOG_DIR"

cd "$BACKEND"

if [ -f "$APP_ROOT/.env" ]; then
  set -a; source "$APP_ROOT/.env"; set +a
fi

exec "$VENV/bin/python3" -u whois_enrich.py 2>&1 | tee -a "$LOG_DIR/whois.log"

