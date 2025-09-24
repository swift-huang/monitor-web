#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, re, sys
from datetime import datetime
import requests
from urllib.parse import urlparse

ZBX_URL  = os.getenv("ZBX_URL",  "http://10.227.92.147:8080/api_jsonrpc.php")
ZBX_USER = os.getenv("ZBX_USER", "api-read-web")
ZBX_PASS = os.getenv("ZBX_PASS", "")
ITEM_KEY_WILDCARD = "*_web.site.code[*]"
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "./data/sites.json")
VERIFY_SSL = os.getenv("VERIFY_SSL", "1") == "1"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

HEADERS = {"Content-Type":"application/json-rpc"}
SEV_ORDER = {"OK":1,"Info":2,"Warning":3,"Average":4,"High":5,"Disaster":6}

s = requests.Session(); s.trust_env = False

def zbx_call(method, params, auth=None, req_id=1):
    payload = {"jsonrpc":"2.0","method":method,"params":params,"id":req_id}
    if auth: payload["auth"] = auth
    r = s.post(ZBX_URL, headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
    r.raise_for_status()
    j = r.json()
    if "error" in j: raise RuntimeError(f"Zabbix API error: {j['error']}")
    return j["result"]

def login(): return zbx_call("user.login", {"username":ZBX_USER, "password":ZBX_PASS})

def fetch_items(auth):
    return zbx_call("item.get", {
        "output":["itemid","key_","lastvalue","lastclock","hostid"],
        "search":{"key_":ITEM_KEY_WILDCARD},
        "searchWildcardsEnabled": True,
        "selectHosts":["name"],
        "limit":100000
    }, auth, 2)

def parse_site(key_):
    m = re.search(r"\[([^\]]+)\]", key_)
    return m.group(1) if m else None

def parse_bu(key_):
    m = re.match(r"^([^_]+)_web\.site\.code", key_)
    return m.group(1) if m else ""

def status_from_code(code_str):
    try: c = int(code_str) if code_str not in (None,"") else None
    except ValueError: c = None
    if c is None or c == 0: return "unknown","Info"
    if c == 101: return "up","OK"           # WebSocket 握手
    if 200 <= c < 400: return "up","OK"
    if c >= 400: return "down","High"
    return "down","Warning"

def ts_human(epoch_str):
    try: return datetime.fromtimestamp(int(epoch_str)).strftime("%Y-%m-%d %H:%M:%S")
    except: return ""

def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH) or ".", exist_ok=True)
    print(f"[INFO] Login {ZBX_URL} as {ZBX_USER}", file=sys.stderr)
    auth = login()
    print("[INFO] Fetching items ...", file=sys.stderr)
    items = fetch_items(auth)
    rows=[]
    for it in items:
        key_ = it.get("key_","")
        site = parse_site(key_)
        if not site: continue
        bu = parse_bu(key_)
        code = it.get("lastvalue","")
        available, severity = status_from_code(code)
        host = (it.get("hosts") or [{}])[0].get("name","")
        rows.append({
            "site": site,
            "bu": bu,
            "code": str(code) if code is not None else "",
            "ts": ts_human(it.get("lastclock")),
            "host": host,
            "available": available,
            "severity": severity,
            "itemid": it.get("itemid",""),
            "key_": key_,
            "hostid": it.get("hostid",""),
            # 預留欄位（由 B 腳本填入）
            "whois_domain": "",
            "domain_expiry": ""
        })
    rows.sort(key=lambda x:(x.get("bu",""), x.get("site",""), x.get("itemid","")))
    with open(OUTPUT_PATH,"w",encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"[OK] Wrote {OUTPUT_PATH} with {len(rows)} records.", file=sys.stderr)

if __name__ == "__main__":
    try: main()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)