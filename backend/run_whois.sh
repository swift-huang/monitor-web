#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ -f "../.env" ]; then
  set -a; source ../.env; set +a
fi

mkdir -p ./data ./cache

export SITES_PATH="./data/sites.json"
export OUTPUT_PATH="./data/sites.json"
export WHOIS_CACHE_PATH="./cache/whois.json"

python3 whois_enrich.py

echo "[OK] run_whois.sh done"