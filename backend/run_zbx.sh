#!/usr/bin/env bash
set -euo pipefail

# 1) 永遠以本檔所在資料夾為工作目錄
cd "$(dirname "$0")"

# 2) 可選：讀取上一層 .env（用來放密碼等環境變數）
if [ -f "../.env" ]; then
  set -a; source ../.env; set +a
fi

# 3) 確保目錄存在
mkdir -p ./data ./cache

# 4) 備份舊檔（給 merge 用）
if [ -f "./data/sites.json" ]; then
  cp -f ./data/sites.json ./data/sites.prev.json
fi

# 5) 執行「快腳本」產生新的 sites.json
#    （如果你的 Python 讀 env，可在這裡覆寫輸出/快取位置）
export OUTPUT_PATH="./data/sites.json"
python3 zbx_build.py

# 6) 用舊檔補回 whois 欄位（避免重新載入後空白）
python3 merge_whois.py

echo "[OK] run_zbx.sh done"