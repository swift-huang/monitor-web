#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, os, sys, pathlib

# ---------- 路徑 / 參數 ----------
BASE_DIR   = pathlib.Path(__file__).resolve().parent
DATA_PATH  = str(BASE_DIR / "data" / "sites.json")
PREV_PATH  = str(BASE_DIR / "data" / "sites.prev.json")

KEEP_FIELDS = ["whois_domain", "domain_expiry", "registrar"]

# ---------- 小工具 ----------
def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ---------- 主流程 ----------
def main():
    new_data = load_json(DATA_PATH)
    if not isinstance(new_data, list):
        print(f"[WARN] New data not found or invalid: {DATA_PATH}")
        return

    old_map = {}
    prev_data = load_json(PREV_PATH)
    if isinstance(prev_data, list):
        old_map = {r.get("site"): r for r in prev_data if isinstance(r, dict)}
    else:
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
                if not r.get(key):
                    if old.get(key):
                        r[key] = old[key]
        merged.append(r)

    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)

    print(f"[OK] Merged {len(merged)} records; preserved fields: {', '.join(KEEP_FIELDS)}")

if __name__ == "__main__":
    main()