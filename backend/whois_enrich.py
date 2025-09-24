#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
whois_enrich.py
- 先從 data/sites.json 收集所有需要的 main domain（含推測/解析）
- 對「去重後」的 domain 進行併發查詢（Domain Admin → RDAP fallback），且自動重試
- 查到的 registrar / expiry 以快取保存（成功與失敗 TTL 分開）
- 再把結果回填到每一筆 rows；最後覆寫 data/sites.json

環境變數（可選）：
  WHOIS_CACHE_TTL    成功快取秒數（預設 86400）
  WHOIS_ERROR_TTL    失敗快取秒數（預設 300）
  WHOIS_WORKERS      併發查詢數（預設 12）
  WHOIS_API_URL      Domain Admin API base，例如 https://k8s-dns.msgcloud.net
  WHOIS_USER         Domain Admin 帳號
  WHOIS_PASS         Domain Admin 密碼
  VERIFY_SSL         1/0（預設 1）
"""

import os
import re
import json
import time
import random
import idna
import requests
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- 路徑 / 參數 ----------
DATA_PATH   = "./data/sites.json"
CACHE_PATH  = "./cache/whois.json"

CACHE_TTL   = int(os.getenv("WHOIS_CACHE_TTL", 86400))   # 成功：預設 1 天
ERROR_TTL   = int(os.getenv("WHOIS_ERROR_TTL", 300))     # 失敗：預設 5 分鐘（縮短以利第一次回補）
MAX_WORKERS = int(os.getenv("WHOIS_WORKERS", 12))
RETRY       = 3                                          # 單 domain 最大重試次數

WHOIS_API_URL = os.getenv("WHOIS_API_URL", "").strip()
WHOIS_USER    = os.getenv("WHOIS_USER", "").strip()
WHOIS_PASS    = os.getenv("WHOIS_PASS", "").strip()
VERIFY_SSL    = bool(int(os.getenv("VERIFY_SSL", "1")))

CN_SLD = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn"}

session = requests.Session()
session.trust_env = False


# ---------- 小工具 ----------
def _now() -> int:
    return int(time.time())


def _load_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _dump_json(path: str, obj: Any):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------- 快取 ----------
def _cache_load() -> Dict[str, dict]:
    j = _load_json(CACHE_PATH)
    return j if isinstance(j, dict) else {}


def _cache_get(cache: Dict[str, dict], domain: str) -> Optional[dict]:
    rec = cache.get(domain)
    if not rec:
        return None
    ts  = int(rec.get("ts", 0))
    ok  = bool(rec.get("ok", False))
    ttl = CACHE_TTL if ok else ERROR_TTL
    if _now() - ts > ttl:
        return None
    return rec


def _cache_put(cache: Dict[str, dict], domain: str, registrar: Optional[str], expiry: Optional[str], ok: bool):
    cache[domain] = {
        "ts": _now(),
        "ok": bool(ok),
        "registrar": (registrar or "")[:256],
        "expiry": (expiry or "")[:64],
    }


# ---------- 解析 main domain ----------
def _hostname_from_site(site: str) -> str:
    s = (site or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        return urlparse(s).hostname or ""
    except Exception:
        return ""


def _guess_main_domain(host: str) -> str:
    if not host or host.count(".") < 1:
        return host
    parts = host.split(".")
    if len(parts) >= 3:
        last2 = ".".join(parts[-2:])
        last3 = ".".join(parts[-3:])
        if last2 in CN_SLD:
            return last3
    return ".".join(parts[-2:])


# ---------- Domain Admin ----------
def _whois_login() -> Optional[str]:
    if not (WHOIS_API_URL and WHOIS_USER and WHOIS_PASS):
        return None
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/login",
            json={"username": WHOIS_USER, "password": WHOIS_PASS},
            timeout=10, verify=VERIFY_SSL,
        )
        r.raise_for_status()
        j = r.json()
        return ((j.get("data") or {}).get("token")) or None
    except Exception:
        return None


REG_PATTERNS = [
    r"Registrar:\s*(.+)",
    r"Sponsoring Registrar:\s*(.+)",
]
EXP_PATTERNS = [
    r"Expiration Time[:：]?\s*([0-9T:\-\.\/\sZ]+)",
    r"Expiry Date[:：]?\s*([0-9T:\-\.\/\sZ]+)",
    r"Expiration Date[:：]?\s*([0-9T:\-\.\/\sZ]+)",
    r"Registry Expiry Date[:：]?\s*([0-9T:\-\.\/\sZ]+)",
]


def _extract_first(raw: str, patterns) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, raw, re.I)
        if m:
            return m.group(1).strip()
    return None


def _da_lookup(domain: str, token: Optional[str]) -> Tuple[Optional[str], Optional[str], bool]:
    """回傳 (registrar, expiry, used_da)"""
    if not (token and WHOIS_API_URL):
        return (None, None, False)
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
            headers={"X-Token": token},
            json={"domain": domain},
            timeout=15, verify=VERIFY_SSL,
        )
        r.raise_for_status()
        j = r.json()
        raw = (j.get("data") or {}).get("raw_data") or j.get("whoisraw") or ""
        if not raw:
            # 有些實作會把值塞在 text 內，備援
            raw = r.text or ""
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")

        reg = _extract_first(raw, REG_PATTERNS)
        exp = _extract_first(raw, EXP_PATTERNS)
        return (reg, exp, True)
    except Exception:
        return (None, None, True)


def _da_resolve(host: str, token: Optional[str]) -> Optional[str]:
    """把 host 透過 Domain Admin 解析出主域名（resolve_domain），解析不到再回 None。"""
    if not (host and token and WHOIS_API_URL):
        return None
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
            headers={"X-Token": token},
            json={"domain": host},
            timeout=10, verify=VERIFY_SSL,
        )
        r.raise_for_status()
        j = r.json()
        data = j.get("data") or {}
        rd = data.get("resolve_domain") or data.get("domain")
        if isinstance(rd, str) and rd.strip():
            return rd.strip()
        return None
    except Exception:
        return None


# ---------- RDAP ----------
def _to_ascii(name: str) -> str:
    try:
        return idna.encode(name.strip()).decode("ascii")
    except Exception:
        return (name or "").strip().lower()


def _rdap_lookup(domain: str) -> Tuple[Optional[str], Optional[str]]:
    d = _to_ascii(domain)
    url = f"https://rdap.org/domain/{d}"
    try:
        r = session.get(url, timeout=10, verify=VERIFY_SSL)
        if r.status_code == 404:
            return (None, None)
        r.raise_for_status()
        j = r.json()

        registrar = j.get("registrar")
        if not registrar:
            for ent in j.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    vcard = ent.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) >= 2:
                        for item in vcard[1]:
                            if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                                registrar = item[3]
                                break
                if registrar:
                    break

        expiry = None
        for ev in j.get("events", []):
            if ev.get("eventAction") in ("expiration", "expiry"):
                expiry = ev.get("eventDate")
                break

        return (registrar, expiry)
    except Exception:
        return (None, None)


# ---------- 查詢（含重試與 fallback） ----------
def _lookup_with_retry(domain: str, token: Optional[str]) -> Dict[str, Any]:
    """
    針對單一 domain：
      - 先 Domain Admin（拿不到再 RDAP）
      - 失敗就重試（帶一點 jitter，避免被節流）
    回傳 dict: {registrar, expiry, ok, from_da}
    """
    for attempt in range(1, RETRY + 1):
        reg, exp, from_da = _da_lookup(domain, token)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": from_da}

        reg, exp = _rdap_lookup(domain)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": False}

        # 下一輪重試前隨機 sleep（遞增 backoff + jitter）
        time.sleep(0.3 * attempt + random.random() * 0.2)

    return {"registrar": None, "expiry": None, "ok": False, "from_da": False}


# ---------- 主流程 ----------
def main():
    if not os.path.exists(DATA_PATH):
        print("[ERROR] no sites.json to enrich")
        return

    rows = _load_json(DATA_PATH) or []
    cache = _cache_load()
    token = _whois_login()

    # 1) 先補 whois_domain（用 Domain Admin resolve 或猜測）
    unique_domains: Dict[str, None] = {}
    new_main = 0

    for r in rows:
        d = (r.get("whois_domain") or "").strip()
        if not d:
            host = _hostname_from_site(r.get("site", ""))
            if host:
                d = _da_resolve(host, token) or _guess_main_domain(host)
            r["whois_domain"] = d or ""
            if d:
                new_main += 1
        if d:
            unique_domains[d] = None  # 去重

    # 2) 先從快取帶可用值，缺的再排入查詢
    domains_result: Dict[str, dict] = {}
    to_query = []
    for d in unique_domains.keys():
        c = _cache_get(cache, d)
        if c:
            domains_result[d] = c
        else:
            to_query.append(d)

    # 3) 併發查詢
    used_da = used_rdap = 0
    if to_query:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(_lookup_with_retry, d, token): d for d in to_query}
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = {"registrar": None, "expiry": None, "ok": False, "from_da": False}

                if res["ok"] and res.get("from_da"):
                    used_da += 1
                elif res["ok"] and not res.get("from_da"):
                    used_rdap += 1

                domains_result[d] = {
                    "ts": _now(),
                    "ok": bool(res["ok"]),
                    "registrar": (res["registrar"] or ""),
                    "expiry": (res["expiry"] or ""),
                }
                _cache_put(cache, d, res.get("registrar"), res.get("expiry"), ok=res["ok"])

    # 4) 把結果回填到 rows
    hit_cache = len(unique_domains) - len(to_query)
    miss_cache = len(to_query)
    updated = 0

    for r in rows:
        d = r.get("whois_domain") or ""
        if not d:
            continue
        res = domains_result.get(d) or _cache_get(cache, d) or {}
        reg = res.get("registrar") or ""
        exp = res.get("expiry") or ""
        # 若前端已有更新的值，不覆蓋。這裡統一覆蓋（以 enrich 為準）。
        if r.get("registrar") != reg or r.get("domain_expiry") != exp:
            r["registrar"] = reg
            r["domain_expiry"] = exp
            updated += 1

    # 5) 寫回資料與快取
    _dump_json(DATA_PATH, rows)
    _dump_json(CACHE_PATH, cache)

    print(
        f"[OK] enriched={updated}, new_main={new_main}, "
        f"cache_hit={hit_cache}, cache_miss={miss_cache}, "
        f"used_da={used_da}, used_rdap={used_rdap}, "
        f"workers={MAX_WORKERS}, retry={RETRY}"
    )


if __name__ == "__main__":
    main()
