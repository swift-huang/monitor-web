#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, os, sys, pathlib

BASE_DIR   = pathlib.Path(__file__).resolve().parent
DATA_PATH  = str(BASE_DIR / "data" / "sites.json")
PREV_PATH  = str(BASE_DIR / "data" / "sites.prev.json")  # 可選：如果你有先備份上一版

KEEP_FIELDS = ["whois_domain", "domain_expiry", "registrar"]

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def main():
    # 讀新資料（zbx_build.py 的輸出）
    new_data = load_json(DATA_PATH)
    if not isinstance(new_data, list):
        print(f"[WARN] New data not found or invalid: {DATA_PATH}")
        return

    # 優先從 data/sites.prev.json 讀上一版；沒有就用 data/sites.json 的舊內容（已不太可用）
    # 實務上建議 zbx_build.py 先把舊版 sites.json 複製成 sites.prev.json 再覆寫新檔。
    old_map = {}
    prev_data = load_json(PREV_PATH)
    if isinstance(prev_data, list):
        old_map = {r.get("site"): r for r in prev_data if isinstance(r, dict)}
    else:
        # 後備：用當前檔當成舊檔（效果有限，但至少不會噴）
        curr_old = load_json(DATA_PATH)
        if isinstance(curr_old, list):
            old_map = {r.get("site"): r for r in curr_old if isinstance(r, dict)}

    merged = []
    for r in new_data:
        site = r.get("site")
        if not site:
            merged.append(r)
            continue
        old = old_map.get(site)
        if old:
            for key in KEEP_FIELDS:
                if not r.get(key):  # 只有新資料該欄位為空才補
                    if old.get(key):
                        r[key] = old[key]
        merged.append(r)

    # 覆寫回去
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)

    print(f"[OK] Merged {len(merged)} records; preserved fields: {', '.join(KEEP_FIELDS)}")

if __name__ == "__main__":
    main()