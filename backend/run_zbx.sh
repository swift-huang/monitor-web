#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ -f "../.env" ]; then
  set -a; source ../.env; set +a
fi

mkdir -p ./data ./cache

if [ -f "./data/sites.json" ]; then
  cp -f ./data/sites.json ./data/sites.prev.json
fi

export OUTPUT_PATH="./data/sites.json"
python3 zbx_build.py

python3 merge_whois.py

echo "[OK] run_zbx.sh done"