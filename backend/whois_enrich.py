#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, time, random, idna, requests
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from publicsuffix2 import get_sld

# ---------- 路徑 / 參數 ----------
DATA_PATH    = "./data/sites.json"
CACHE_PATH   = "./cache/whois.json"

CACHE_TTL    = int(os.getenv("WHOIS_CACHE_TTL", 86400))   # 成功：預設 1 天
ERROR_TTL    = int(os.getenv("WHOIS_ERROR_TTL", 300))     # 失敗：預設 5 分鐘（縮短以利第一次回補）
MAX_WORKERS  = int(os.getenv("WHOIS_WORKERS", 12))
RETRY        = 3                                          # 單 domain 最大重試次數

WHOIS_API_URL = os.getenv("WHOIS_API_URL", "").strip()
WHOIS_USER    = os.getenv("WHOIS_USER", "").strip()
WHOIS_PASS    = os.getenv("WHOIS_PASS", "").strip()
VERIFY_SSL    = bool(int(os.getenv("VERIFY_SSL", "1")))

session = requests.Session()
session.trust_env = False

# ---------- 小工具 ----------
def _now() -> int:
    return int(time.time())

def _load_json(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _dump_json(path: str, obj):
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

# ---------- 主域名解析 ----------
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

def _psl_main_domain(host: str) -> str:
    """使用 PublicSuffix List 正確取得主域名（ex: google.com.tw, hsb.co.id）"""
    try:
        # get_sld: 返回 "example.co.uk" 這種「註冊等級域名」
        d = get_sld(host, strict=False)
        return d or ""
    except Exception:
        return ""

def _guess_main_domain(host: str) -> str:
    """備援：簡單猜測（PSL 失敗時）"""
    if not host or host.count(".") < 1:
        return host
    parts = host.split(".")
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

def _normalize_expiry(s: Optional[str]) -> Optional[str]:
    """盡量轉 ISO8601（轉不動就原樣返回）"""
    if not s:
        return None
    s2 = s.strip()
    # 常見格式嘗試
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s2.replace("Z","").replace("/", "-"), fmt.replace("Z",""))
            return dt.strftime("%Y-%m-%d")
        except Exception:
            continue
    return s2

def _da_call(domain: str, token: Optional[str]):
    """封裝成可重登一次"""
    if not (token and WHOIS_API_URL):
        return None, None, None
    url = WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw"
    r = session.post(url, headers={"X-Token": token}, json={"domain": domain},
                     timeout=15, verify=VERIFY_SSL)
    return r, url, {"X-Token": token, "domain": domain}

def _da_lookup(domain: str, token: Optional[str]) -> Tuple[Optional[str], Optional[str], bool, Optional[str]]:
    """回傳 (registrar, expiry, used_da, new_token)；若 401/403 會自動重登一次"""
    if not (token and WHOIS_API_URL):
        return (None, None, False, None)
    try:
        r, url, ctx = _da_call(domain, token)
        if r is None:
            return (None, None, False, None)
        if r.status_code in (401, 403):
            # token 失效 → 重登再試一次
            new_token = _whois_login()
            if new_token:
                r = session.post(url, headers={"X-Token": new_token}, json={"domain": domain},
                                 timeout=15, verify=VERIFY_SSL)
                if r.status_code in (401, 403):
                    return (None, None, True, new_token)
                r.raise_for_status()
                j = r.json()
                raw = (j.get("data") or {}).get("raw_data") or j.get("whoisraw") or r.text or ""
                raw = raw.replace("\r\n", "\n").replace("\r", "\n")
                reg = (_extract_first(raw, REG_PATTERNS) or "").strip()
                exp = _normalize_expiry(_extract_first(raw, EXP_PATTERNS))
                return (reg or None, exp or None, True, new_token)
            return (None, None, True, None)

        r.raise_for_status()
        j = r.json()
        raw = (j.get("data") or {}).get("raw_data") or j.get("whoisraw") or r.text or ""
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        reg = (_extract_first(raw, REG_PATTERNS) or "").strip()
        exp = _normalize_expiry(_extract_first(raw, EXP_PATTERNS))
        return (reg or None, exp or None, True, None)
    except Exception:
        return (None, None, True, None)

# 解析主域名（Domain Admin 版）
def _da_resolve(host: str, token: Optional[str]) -> Optional[str]:
    if not (host and token and WHOIS_API_URL):
        return None
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
            headers={"X-Token": token},
            json={"domain": host},
            timeout=10, verify=VERIFY_SSL,
        )
        if r.status_code in (401,403):
            token2 = _whois_login()
            if not token2: return None
            r = session.post(
                WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
                headers={"X-Token": token2},
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

        return ((registrar or None), _normalize_expiry(expiry))
    except Exception:
        return (None, None)

# ---------- 查詢（含重試與 fallback） ----------
def _lookup_with_retry(domain: str, token: Optional[str]) -> Dict[str, Any]:
    """先 Domain Admin（token 失效自動刷新），不行再 RDAP；失敗重試 RETRY 次"""
    cur_token = token
    for attempt in range(1, RETRY + 1):
        reg, exp, used_da, new_token = _da_lookup(domain, cur_token)
        if new_token:
            cur_token = new_token
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": used_da}

        reg, exp = _rdap_lookup(domain)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": False}

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

    # 1) 先把每列的 whois_domain 補齊：resolve_domain -> PSL -> 備援猜測
    unique_domains: Dict[str, None] = {}
    new_main = 0
    for r in rows:
        d = (r.get("whois_domain") or "").strip()
        if not d:
            host = _hostname_from_site(r.get("site", ""))
            if host:
                d = _da_resolve(host, token) or _psl_main_domain(host) or _guess_main_domain(host)
            r["whois_domain"] = d or ""
            if d:
                new_main += 1
        if d:
            unique_domains[d] = None

    # 2) 快取命中 / 待查列表
    domains_result: Dict[str, dict] = {}
    to_query = []
    for d in unique_domains.keys():
        c = _cache_get(cache, d)
        if c:
            domains_result[d] = c
        else:
            to_query.append(d)

    used_da = used_rdap = 0

    # 3) 併發查詢（第一輪：DA 優先，缺就 RDAP）
    failed_ones = []
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
                if res["ok"] and not res.get("from_da"):
                    used_rdap += 1

                if res["ok"]:
                    domains_result[d] = {
                        "ts": _now(),
                        "ok": True,
                        "registrar": (res["registrar"] or ""),
                        "expiry": (res["expiry"] or ""),
                    }
                    _cache_put(cache, d, res.get("registrar"), res.get("expiry"), ok=True)
                else:
                    failed_ones.append(d)

    # 4) 第二輪補救（只跑 RDAP；首跑時能大幅補齊）
    if failed_ones:
        with ThreadPoolExecutor(max_workers=max(4, MAX_WORKERS // 2)) as ex:
            futs = {ex.submit(_rdap_lookup, d): d for d in failed_ones}
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    reg, exp = fut.result()
                except Exception:
                    reg, exp = (None, None)

                if reg or exp:
                    used_rdap += 1
                    domains_result[d] = {
                        "ts": _now(),
                        "ok": True,
                        "registrar": (reg or ""),
                        "expiry": (exp or ""),
                    }
                    _cache_put(cache, d, reg, exp, ok=True)
                else:
                    # 仍失敗 → 記入短 TTL，避免每輪都打爆
                    _cache_put(cache, d, None, None, ok=False)

    hit_cache = len(unique_domains) - len(to_query)
    miss_cache = len(to_query)
    updated = 0

    # 5) 寫回 rows
    for r in rows:
        d = r.get("whois_domain") or ""
        if not d:
            continue
        res = domains_result.get(d) or _cache_get(cache, d) or {}
        reg = (res.get("registrar") or "").strip()
        exp = (res.get("expiry") or "").strip()
        if r.get("registrar") != reg or r.get("domain_expiry") != exp:
            r["registrar"] = reg
            r["domain_expiry"] = exp
            updated += 1

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