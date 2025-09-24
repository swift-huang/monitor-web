#!/usr/bin/env bash
set -euo pipefail

# 1) 固定工作目錄
cd "$(dirname "$0")"

# 2) 讀 .env
if [ -f "../.env" ]; then
  set -a; source ../.env; set +a
fi

# 3) 確保目錄存在
mkdir -p ./data ./cache

# 4) 指定檔案（接 whois_enrich.py 的環境變數）
export SITES_PATH="./data/sites.json"
export OUTPUT_PATH="./data/sites.json"
export WHOIS_CACHE_PATH="./cache/whois.json"

# 5) 執行「慢腳本」：補 main-domain + 到期日（有快取）
python3 whois_enrich.py

echo "[OK] run_whois.sh done"