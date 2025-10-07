#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WHOIS/RDAP 豐富化（同時處理兩份檔案）
- 支援 sources: 內部 DA(optional) → RDAP(含 TWNIC) → HTTP(多站含 TWNIC/dotPH) → WHOIS:43
- 特別補強:
  * .tw：先打 TWNIC RDAP；失敗則打 TWNIC web-WHOIS；再落回其它來源
  * .ph：dotPH 官方 whois 頁面抽取（Registrar/Expiry）
- 強韌解析：多語系與不同欄位名稱（Registrar/Registry Expiry/Record expires on...）
- 快取：成功快取 TTL=WHOIS_CACHE_TTL(預設 1d)，失敗與「有資料但 registrar 空白」都走較短 TTL=WHOIS_ERROR_TTL(預設 5m)
- 併發：預設 12 workers，可用 WHOIS_WORKERS 覆蓋
"""

import os
import re
import json
import time
import random
import socket
import idna
import requests
import html as htmllib
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from publicsuffix2 import get_sld

# ---------- 基本設定 ----------
DATA_PATHS: List[str] = ["./data/sites.json", "./data/sites_other.json"]
CACHE_PATH  = "./cache/whois.json"

CACHE_TTL   = int(os.getenv("WHOIS_CACHE_TTL", 86400))  # 成功快取
ERROR_TTL   = int(os.getenv("WHOIS_ERROR_TTL", 300))    # 失敗或 registrar 空白
MAX_WORKERS = int(os.getenv("WHOIS_WORKERS", 12))
RETRY       = 3
PH_PREF = os.getenv("WHOIS_PH_REG_SOURCE", "registry").lower()  # "registry" 或 "retailer"


# 可選：你有私有的 whois 代理 API 就填環境變數；沒有就會自動略過
WHOIS_API_URL = os.getenv("WHOIS_API_URL", "").strip()
WHOIS_USER    = os.getenv("WHOIS_USER", "").strip()
WHOIS_PASS    = os.getenv("WHOIS_PASS", "").strip()
VERIFY_SSL    = bool(int(os.getenv("VERIFY_SSL", "1")))

# 43/TCP 較容易不穩的 TLD 預設跳過（可用環境變數覆蓋）
SKIP_PORT43_TLDS = set(x.strip().lower() for x in os.getenv("WHOIS_SKIP_PORT43_TLDS", "ph,sg,vu").split(","))

# 43/TCP 指定 NIC 或常見註冊商查詢站
WHOIS_NIC_SERVERS: Dict[str, List[str]] = {
    "ph": ["whois.nic.ph", "whois.dot.ph", "whois.dns.ph"],  # 這幾個大多沒有 43，但留著以防萬一
    "tw": ["whois.twnic.net.tw"],                            # TWNIC 支援 43
    "uk": ["whois.nic.uk"],
    "hk": ["whois.hkirc.hk"],
    "cn": ["whois.cnnic.cn"],
}
WHOIS_REGISTRAR_FALLBACK: List[str] = [
    "whois.godaddy.com","whois.namecheap.com","whois.publicdomainregistry.com",
    "whois.webnic.cc","whois.tucows.com","whois.enom.com","whois.gandi.net",
    "whois.markmonitor.com","whois.name.com","whois.1api.net",
]

# HTTP session / log
session = requests.Session()
session.trust_env = False
LOG_DIR = "/var/log/monitor-web"
DEBUG_LOG = os.path.join(LOG_DIR, "whois_debug.log")

# ---------- 小工具 ----------
def _now() -> int:
    return int(time.time())

def _load_json(p: str):
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _dump_json(p: str, obj):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)

def _append_debug(msg: str):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

# ---------- 快取 ----------
def _cache_load() -> Dict[str, dict]:
    j = _load_json(CACHE_PATH)
    return j if isinstance(j, dict) else {}

def _cache_get(cache: Dict[str, dict], domain: str) -> Optional[dict]:
    rec = cache.get(domain)
    if not rec:
        return None
    ts = int(rec.get("ts", 0))
    ok = bool(rec.get("ok", False))
    registrar_empty = not bool((rec.get("registrar") or "").strip())
    ttl = ERROR_TTL if (ok and registrar_empty) else (CACHE_TTL if ok else ERROR_TTL)
    if _now() - ts > ttl:
        return None
    return rec

def _cache_put(cache: Dict[str, dict], d: str, r: Optional[str], e: Optional[str], ok: bool):
    cache[d] = {
        "ts": _now(),
        "ok": bool(ok),
        "registrar": (r or "")[:256],
        "expiry": (e or "")[:64],
    }

# ---------- domain 取得 ----------
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
    try:
        return get_sld(host, strict=False) or ""
    except Exception:
        return ""

def _guess_main_domain(host: str) -> str:
    if not host or host.count(".") < 1:
        return host
    parts = host.split(".")
    return ".".join(parts[-2:])

# ---------- 私有 API（可選） ----------
def _whois_login() -> Optional[str]:
    if not (WHOIS_API_URL and WHOIS_USER and WHOIS_PASS):
        return None
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/login",
            json={"username": WHOIS_USER, "password": WHOIS_PASS},
            timeout=10,
            verify=VERIFY_SSL,
        )
        r.raise_for_status()
        j = r.json()
        return ((j.get("data") or {}).get("token")) or None
    except Exception:
        return None

# ---------- 解析規則 ----------
REG_INLINE_PATTERNS = [
    r"Registrar Name[:：]\s*(.+)",
    r"Registrar[:：]\s*(.+?)(?:\s*\[|(?:\s+URL:)|$)",
    r"Sponsoring Registrar[:：]\s*(.+?)(?:\s*\(|\s*\[|$)",
    r"注册商[:：]\s*(.+)",
    r"注册服务机构[:：]\s*(.+)",
    r"Registrar Organization[:：]\s*(.+)",
    r"Registration Service Provider[:：]\s*(.+)",   # TWNIC
]
EXP_PATTERNS = [
    r"Registry\s*Registration\s*Expiration\s*Date[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Registry\s*Expiry\s*Date[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Expiry\s*date[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Expiration\s*Date[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Expiration\s*Time[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Expires\s*on[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Expires[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Valid\s*Until[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Paid-till[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"到期时间[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"到期日期[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",
    r"Record\s*expires\s*on[:：]?\s*([0-9A-Za-z ,:\/\-\.\+TZ]+)",  # TWNIC
]
_STOP_TOKENS_FOR_REG = [
    "iana id","abuse","registrant","technical","admin","name server",
    "name servers","dnssec","updated on","status","domain name","contact",
    "org","organisation","registration service url","registry gateway services"
]

def _cleanup_registrar(s: str) -> str:
    s = re.split(r"\s+(?:URL:|Homepage:)\s*", s, 1, flags=re.I)[0]
    low = s.lower()
    cut = len(s)
    for tok in _STOP_TOKENS_FOR_REG:
        i = low.find(tok)
        if i != -1:
            cut = min(cut, i)
    s = s[:cut]
    s = re.sub(r"\s*\[Tag\s*=\s*.*?\]\s*$", "", s, flags=re.I)
    return s.strip(" ;,·")

def _normalize_expiry(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s2 = s.strip()
    s2 = re.sub(r"\bUTC\b", "", s2, flags=re.I).strip()
    s2 = s2.replace("T", " ").replace("Z", "").strip()
    fmts = [
        "%Y-%m-%d %H:%M:%S","%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S","%Y/%m/%d",
        "%d-%b-%Y %H:%M:%S","%d-%b-%Y","%d %b %Y",
        "%d-%m-%Y","%d/%m/%Y",
        "%Y.%m.%d","%d.%m.%Y",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(s2, fmt).strftime("%Y-%m-%d")
        except Exception:
            pass
    try:
        m = re.search(r"(?P<d>\d{1,2})\s*(?P<m>[A-Za-z]{3,9})\s*(?P<y>\d{4})|(?P<m2>[A-Za-z]{3,9})\s*(?P<d2>\d{1,2})\s*,?\s*(?P<y2>\d{4})", s2)
        if m:
            months = {'jan':1,'january':1,'feb':2,'february':2,'mar':3,'march':3,'apr':4,'april':4,'may':5,'jun':6,'june':6,'jul':7,'july':7,'aug':8,'august':8,'sep':9,'sept':9,'september':9,'oct':10,'october':10,'nov':11,'november':11,'dec':12,'december':12}
            if m.group("m"):
                d = int(m.group("d")); mnum = months.get(m.group("m").lower(), 0); y = int(m.group("y"))
            else:
                d = int(m.group("d2")); mnum = months.get(m.group("m2").lower(), 0); y = int(m.group("y2"))
            if mnum:
                return f"{y:04d}-{mnum:02d}-{d:02d}"
    except Exception:
        pass
    return s.strip()

def _to_ascii(name: str) -> str:
    try:
        return idna.encode(name.strip()).decode("ascii")
    except Exception:
        return (name or "").strip().lower()

def _html_to_text(html: str) -> str:
    if not html:
        return ""
    txt = re.sub(r"(?i)<br\s*/?>", "\n", html)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = htmllib.unescape(txt)
    txt = re.sub(r"[ \t]+\n", "\n", txt)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    return txt

def _raw_looks_like_domain(raw: str, domain: str) -> bool:
    dom = domain.lower()
    txt = (raw or "").lower()
    if dom not in txt:
        return False
    return any(k in txt for k in ("domain name","registrar","registry","expiry","expiration","status","name server"))

# ---------- RDAP ----------
def _iana_rdap_endpoints(tld: str) -> List[str]:
    try:
        r = session.get("https://data.iana.org/rdap/dns.json", timeout=10, verify=VERIFY_SSL)
        r.raise_for_status()
        j = r.json()
        for svc in j.get("services", []):
            tlds, urls = svc
            if any(tld.lower() == x.lower() for x in tlds):
                return [u.rstrip("/") for u in urls]
    except Exception:
        return []
    return []

def _rdap_lookup(domain: str) -> Tuple[Optional[str], Optional[str]]:
    d = _to_ascii(domain)
    tld = d.split(".")[-1] if "." in d else d

    endpoints: List[str] = []
    # 先加官方/專屬端點
    if d.endswith(".tw"):
        endpoints.append("https://rdap.twnic.tw/rdap")
    if d.endswith(".cn"):
        endpoints.append("https://rdap.cnnic.cn")
    # 通用 rdap.org
    endpoints.append("https://rdap.org")
    # IANA 聲明的端點
    endpoints += _iana_rdap_endpoints(tld)

    seen = set()
    for base in [e for e in endpoints if e]:
        url = f"{base.rstrip('/')}/domain/{d}"
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=12, verify=VERIFY_SSL)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            j = r.json()

            registrar = j.get("registrar")
            if not registrar:
                for ent in j.get("entities", []):
                    roles = ent.get("roles") or []
                    if "registrar" in roles:
                        v = None
                        vcard = ent.get("vcardArray")
                        if isinstance(vcard, list) and len(vcard) >= 2:
                            for item in vcard[1]:
                                if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                                    v = item[3]
                                    break
                        registrar = v or ent.get("handle") or ent.get("name")
                    if registrar:
                        break

            expiry = None
            for ev in j.get("events", []):
                if ev.get("eventAction") in ("expiration", "expiry"):
                    expiry = ev.get("eventDate")
                    break

            if registrar or expiry:
                return (registrar or None, _normalize_expiry(expiry))
        except Exception:
            continue
    return (None, None)

# ---------- HTTP providers ----------
def _http_whois_whoiscom(domain: str, headers, ajax_headers) -> Tuple[Optional[str], Optional[str], bool]:
    urls = [
        f"https://www.whois.com/whois/{domain}?output=raw",  # 先打 RAW
        f"https://www.whois.com/whois/result/?domain={domain}",
        f"https://www.whois.com/whois/search/?query={domain}",
        f"https://www.whois.com/whois/{domain}",
    ]
    for url in urls:
        try:
            r = session.get(
                url,
                headers=ajax_headers if ("result" in url or "search" in url) else headers,
                timeout=15,
                verify=VERIFY_SSL,
            )
            if r.status_code == 404:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS whois.com 404 {domain} url={url}")
                continue
            if r.status_code >= 400:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS whois.com {r.status_code} {domain} url={url}")
                continue

            text = r.text
            raw = text
            m = re.search(r'"rawText"\s*:\s*"([^"]+)"', text, re.I) or re.search(r'"RawText"\s*:\s*"([^"]+)"', text, re.I)
            raw = (htmllib.unescape(m.group(1)).replace("\\n", "\n").replace("\\t", "\t")) if m else _html_to_text(text)

            if not _raw_looks_like_domain(raw, domain):
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS whois.com not match {domain} url={url}")
                continue

            reg, exp = _extract_registrar_and_expiry(raw)
            if reg or exp:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (whois.com) {domain} url={url} reg={reg} exp={exp}")
                return (reg, exp, True)
        except Exception as e:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS whois.com error {domain} url={url}: {e}")
    return (None, None, False)

def _http_whois_whois_is(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    try:
        url = f"https://who.is/whois/{domain}"
        r = session.get(url, headers=headers, timeout=15, verify=VERIFY_SSL)
        if r.status_code == 404:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS who.is 404 {domain}")
            return (None, None, False)
        if r.status_code >= 400:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS who.is {r.status_code} {domain}")
            return (None, None, False)
        txt = _html_to_text(r.text)
        if not _raw_looks_like_domain(txt, domain):
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS who.is not match {domain}")
            return (None, None, False)
        reg, exp = _extract_registrar_and_expiry(txt)
        if reg or exp:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (who.is) {domain} reg={reg} exp={exp}")
            return (reg, exp, True)
    except Exception as e:
        _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS who.is error {domain}: {e}")
    return (None, None, False)

def _http_whois_namesilo(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    try:
        url = f"https://www.namesilo.com/whois.php?query={domain}"
        r = session.get(url, headers=headers, timeout=15, verify=VERIFY_SSL)
        if r.status_code == 404:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS namesilo 404 {domain}")
            return (None, None, False)
        if r.status_code >= 400:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS namesilo {r.status_code} {domain}")
            return (None, None, False)
        txt = _html_to_text(r.text)
        if domain.lower() not in txt.lower():
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS namesilo not match {domain}")
            return (None, None, False)
        reg, exp = _extract_registrar_and_expiry(txt)
        if reg or exp:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (namesilo) {domain} reg={reg} exp={exp}")
            return (reg, exp, True)
    except Exception as e:
        _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS namesilo error {domain}: {e}")
    return (None, None, False)

def _http_whois_net_chinese(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    # Net-Chinese 不是所有 TLD 都覆蓋，但很多 .com/.net/.cn/.hk 可抓
    try:
        url = f"https://www.net-chinese.com.tw/Domain/whois.aspx?domain={domain}"
        r = session.get(url, headers=headers, timeout=15, verify=VERIFY_SSL)
        if r.status_code == 404:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS net-chinese 404 {domain}")
            return (None, None, False)
        if not r.ok:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS net-chinese {r.status_code} {domain}")
            return (None, None, False)
        txt = _html_to_text(r.text)
        if not _raw_looks_like_domain(txt, domain):
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS net-chinese not match {domain}")
            return (None, None, False)
        reg, exp = _extract_registrar_and_expiry(txt)
        if reg or exp:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (net-chinese) {domain} reg={reg} exp={exp}")
            return (reg, exp, True)
    except Exception as e:
        _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS net-chinese error {domain}: {e}")
    return (None, None, False)
def _http_whois_dotph(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    candidates = [
        f"https://whois.dot.ph/?domain={domain}",
        f"https://whois.dot.ph/?d={domain}",
        f"https://whois.dot.ph/?search={domain}",
        f"https://www.dot.ph/whois?domain={domain}",
        f"https://www.dot.ph/whois?search={domain}",
    ]
    for url in candidates:
        try:
            r = session.get(url, headers=headers, timeout=15, verify=VERIFY_SSL)
            if r.status_code == 404:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS dotph 404 {domain} url={url}")
                continue
            if r.status_code >= 400:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS dotph {r.status_code} {domain} url={url}")
                continue

            # 純文字化，再抽取
            txt = _html_to_text(r.text)
            if domain.lower() not in txt.lower():
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS dotph not match {domain} url={url}")
                continue

            reg, exp = _extract_registrar_and_expiry(txt)

            # 到期日用 JS moment(...) 的備援
            if not exp or not re.search(r"\d", exp):
                m = re.search(r"var\s+expiryDate\s*=\s*moment\('([^']+)'\)", r.text)
                if m:
                    exp = _normalize_expiry(m.group(1))

            # ★ 若偏好 retailer，且頁面有 domaincontrol.com（GoDaddy NS），則將 1API 視為 GoDaddy
            if PH_PREF == "retailer":
                if (reg or "").lower().startswith("1api") and "domaincontrol.com" in txt.lower():
                    reg = "GoDaddy.com, LLC"

            if reg or exp:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (dotph) {domain} url={url} reg={reg} exp={exp}")
                return (reg, exp, True)

        except Exception as e:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS dotph error {domain} url={url}: {e}")
    return (None, None, False)

def _http_whois_twnic(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    # TWNIC 官方 web-WHOIS
    try:
        url = f"https://whois.twnic.net.tw/cgi-bin/whois?name={domain}"
        r = session.get(url, headers=headers, timeout=15, verify=VERIFY_SSL)
        if not r.ok:
            return (None, None, False)
        # TWNIC 回應常是 BIG5，requests 可能會猜錯編碼；先用原文做抽取，再退回 text 轉碼
        raw = r.content
        try:
            txt = raw.decode("big5", errors="ignore")
        except Exception:
            txt = r.text
        txt = _html_to_text(txt)

        if domain.lower() not in txt.lower():
            return (None, None, False)

        reg = None; exp = None
        m = re.search(r"Registration Service Provider[:：]\s*(.+)", txt, re.I)
        if m:
            reg = _cleanup_registrar(m.group(1))
        m = re.search(r"Record\s*expires\s*on[:：]?\s*([^\n\(]+)", txt, re.I)
        if m:
            exp = _normalize_expiry(m.group(1))
        if reg or exp:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (twnic) {domain} reg={reg} exp={exp}")
            return (reg, exp, True)
    except Exception as e:
        _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS twnic error {domain}: {e}")
    return (None, None, False)

def _http_whois_godaddy(domain: str, headers) -> Tuple[Optional[str], Optional[str], bool]:
    # GoDaddy 常被 403 擋；能用就賺到
    for url in [
        f"https://www.godaddy.com/whois/results.aspx?domain={domain}",
        f"https://ie.godaddy.com/whois/results.aspx?domain={domain}",
        f"https://whois.godaddy.com/whois/{domain}",
    ]:
        try:
            r = session.get(url, headers=headers, timeout=12, verify=VERIFY_SSL)
            if r.status_code == 403:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS godaddy 403 {domain} {url}")
                continue
            if r.status_code == 404:
                continue
            r.raise_for_status()
            txt = _html_to_text(r.text)
            if not _raw_looks_like_domain(txt, domain):
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS godaddy not match {domain}")
                continue
            reg, exp = _extract_registrar_and_expiry(txt)
            if reg or exp:
                _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS hit (godaddy) {domain} reg={reg} exp={exp}")
                return (reg, exp, True)
        except Exception as e:
            _append_debug(f"[{time.strftime('%F %T')}] HTTP-WHOIS godaddy error {domain}: {e}")
    return (None, None, False)
def _http_whois_web(domain: str) -> Tuple[Optional[str], Optional[str]]:
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-TW;q=0.8,zh;q=0.7",
        "Cache-Control": "no-cache", "Pragma": "no-cache", "Upgrade-Insecure-Requests": "1",
    }
    ajax_headers = dict(headers); ajax_headers["X-Requested-With"] = "XMLHttpRequest"

    # .tw 先打 TWNIC
    if domain.lower().endswith(".tw"):
        reg, exp, ok = _http_whois_twnic(domain, headers)
        if ok: return (reg, exp)

    # whois.com（先 RAW）
    reg, exp, ok = _http_whois_whoiscom(domain, headers, ajax_headers)
    if ok: return (reg, exp)

    # who.is
    reg, exp, ok = _http_whois_whois_is(domain, headers)
    if ok: return (reg, exp)

    # NameSilo
    reg, exp, ok = _http_whois_namesilo(domain, headers)
    if ok: return (reg, exp)

    # Net-Chinese
    reg, exp, ok = _http_whois_net_chinese(domain, headers)
    if ok: return (reg, exp)

    # ★ .ph：依開關決定先後
    if domain.lower().endswith(".ph"):
        if PH_PREF == "retailer":
            # 先嘗試 GoDaddy（可能被 403，但有時能成功）
            reg, exp, ok = _http_whois_godaddy(domain, headers)
            if ok: return (reg, exp)
            # 失敗再回 registry（dotPH）
            reg, exp, ok = _http_whois_dotph(domain, headers)
            if ok: return (reg, exp)
        else:
            # 預設：registry 優先（dotPH）
            reg, exp, ok = _http_whois_dotph(domain, headers)
            if ok: return (reg, exp)

    # 其他：最後再試 GoDaddy
    reg, exp, ok = _http_whois_godaddy(domain, headers)
    if ok: return (reg, exp)

    return (None, None)

# ---------- WHOIS:43 ----------
def _whois_query(host: str, domain: str) -> Optional[str]:
    try:
        with socket.create_connection((host, 43), timeout=12) as sock:
            # 有些 .tw 需要前綴 "domain "，但 TWNIC 支援直接 domain
            sock.sendall((domain + "\r\n").encode("utf-8", errors="ignore"))
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("latin-1", errors="ignore")
    except Exception:
        return None

def _whois_port43(domain: str) -> Tuple[Optional[str], Optional[str]]:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    if tld in SKIP_PORT43_TLDS:
        _append_debug(f"[{time.strftime('%F %T')}] WHOIS:43 skipped for TLD .{tld} {domain}")
        return (None, None)

    tried: List[str] = []
    for host in WHOIS_NIC_SERVERS.get(tld, []):
        tried.append(host)
        raw = _whois_query(host, domain)
        if raw:
            reg, exp = _extract_registrar_and_expiry(raw)
            if reg or exp:
                return (reg, exp)

    for host in WHOIS_REGISTRAR_FALLBACK:
        tried.append(host)
        raw = _whois_query(host, domain)
        if raw:
            reg, exp = _extract_registrar_and_expiry(raw)
            if reg or exp:
                return (reg, exp)

    _append_debug(f"[{time.strftime('%F %T')}] WHOIS:43 no data for {domain}; tried: {', '.join(tried)}")
    return (None, None)

# ---------- 內部代理（可選） ----------
def _da_lookup(domain: str, token: Optional[str]) -> Tuple[Optional[str], Optional[str], bool, Optional[str]]:
    if not (token and WHOIS_API_URL):
        return (None, None, False, None)
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
            headers={"X-Token": token},
            json={"domain": domain},
            timeout=15,
            verify=VERIFY_SSL,
        )
        if r.status_code in (401, 403):
            new = _whois_login()
            if not new:
                return (None, None, True, None)
            r = session.post(
                WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
                headers={"X-Token": new},
                json={"domain": domain},
                timeout=15,
                verify=VERIFY_SSL,
            )
            if r.status_code in (401, 403):
                return (None, None, True, new)
            r.raise_for_status()
            j = r.json()
            raw = (j.get("data") or {}).get("raw_data") or j.get("whoisraw") or r.text or ""
            reg, exp = _extract_registrar_and_expiry(raw)
            return (reg, exp, True, new)
        r.raise_for_status()
        j = r.json()
        raw = (j.get("data") or {}).get("raw_data") or j.get("whoisraw") or r.text or ""
        reg, exp = _extract_registrar_and_expiry(raw)
        return (reg, exp, True, None)
    except Exception:
        return (None, None, True, None)

def _da_resolve(host: str, token: Optional[str]) -> Optional[str]:
    if not (host and token and WHOIS_API_URL):
        return None
    try:
        r = session.post(
            WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
            headers={"X-Token": token},
            json={"domain": host},
            timeout=10,
            verify=VERIFY_SSL,
        )
        if r.status_code in (401, 403):
            token2 = _whois_login()
            if not token2:
                return None
            r = session.post(
                WHOIS_API_URL.rstrip("/") + "/api/getWhoisRaw",
                headers={"X-Token": token2},
                json={"domain": host},
                timeout=10,
                verify=VERIFY_SSL,
            )
        r.raise_for_status()
        j = r.json()
        data = j.get("data") or {}
        rd = data.get("resolve_domain") or data.get("domain")
        return rd.strip() if isinstance(rd, str) and rd.strip() else None
    except Exception:
        return None

# ---------- 核心流程 ----------
def _extract_registrar_and_expiry(raw: str) -> Tuple[Optional[str], Optional[str]]:
    raw2 = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in raw2.split("\n")]

    registrar = None
    for ln in lines:
        s = ln.strip()
        for pat in REG_INLINE_PATTERNS:
            m = re.search(pat, s, re.I)
            if m:
                registrar = _cleanup_registrar(m.group(1))
                if registrar:
                    break
        if registrar:
            break

    if not registrar:
        for i, ln in enumerate(lines):
            if re.match(r"^\s*(Registrar(?: Name)?|Sponsoring Registrar|Registration Service Provider)\s*[:：]?\s*$", ln, re.I):
                for j in range(i + 1, min(i + 6, len(lines))):
                    nxt = (lines[j] or "").strip()
                    if not nxt:
                        continue
                    if re.match(r"^(URL|Whois Server|IANA ID|Referral URL|Relevant dates|Name servers|Domain|Registrant)\b", nxt, re.I):
                        break
                    registrar = _cleanup_registrar(nxt)
                    break
                if registrar:
                    break

    expiry_raw = None
    for ln in lines:
        s = ln.strip()
        for pat in EXP_PATTERNS:
            m = re.search(pat, s, re.I)
            if m:
                expiry_raw = m.group(1).strip()
                break
        if expiry_raw:
            break

    return (registrar or None, _normalize_expiry(expiry_raw))

def _lookup_with_retry(domain: str, token: Optional[str]) -> Dict[str, Any]:
    cur = token
    for attempt in range(1, RETRY + 1):
        # 1) 內部代理（可選）
        reg, exp, used_da, new = _da_lookup(domain, cur)
        if new:
            cur = new
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": used_da}

        # 2) RDAP
        reg, exp = _rdap_lookup(domain)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": False}

        # 3) HTTP
        reg, exp = _http_whois_web(domain)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": False}

        # 4) 43/TCP
        reg, exp = _whois_port43(domain)
        if reg or exp:
            return {"registrar": reg, "expiry": exp, "ok": True, "from_da": False}

        time.sleep(0.3 * attempt + random.random() * 0.2)
    return {"registrar": None, "expiry": None, "ok": False, "from_da": False}

def _prepare_rows(rows: list, token: Optional[str]) -> Tuple[Dict[str, None], int]:
    uniq: Dict[str, None] = {}
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
            uniq[d] = None
    return uniq, new_main

def main():
    targets = []
    for p in DATA_PATHS:
        rows = _load_json(p)
        if isinstance(rows, list):
            targets.append((p, rows))
    if not targets:
        print("[ERROR] no sites.json / sites_other.json to enrich")
        return

    cache = _cache_load()
    token = _whois_login()

    all_unique: Dict[str, None] = {}
    new_main_total = 0
    for _, rows in targets:
        uniq, newc = _prepare_rows(rows, token)
        new_main_total += newc
        for d in uniq.keys():
            all_unique[d] = None

    domains_result: Dict[str, dict] = {}
    to_query: List[str] = []
    for d in all_unique.keys():
        c = _cache_get(cache, d)
        if c:
            domains_result[d] = c
        else:
            to_query.append(d)

    used_da = used_rdap = 0
    failed: List[str] = []

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
                        "registrar": (res.get("registrar") or ""),
                        "expiry": (res.get("expiry") or ""),
                    }
                    _cache_put(cache, d, res.get("registrar"), res.get("expiry"), ok=True)
                else:
                    failed.append(d)

    # 失敗補打一輪 RDAP（有些暫時 404）
    if failed:
        with ThreadPoolExecutor(max_workers=max(4, MAX_WORKERS // 2)) as ex:
            futs = {ex.submit(_rdap_lookup, d): d for d in failed}
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    reg, exp = fut.result()
                except Exception:
                    reg, exp = (None, None)
                if reg or exp:
                    used_rdap += 1
                    domains_result[d] = {"ts": _now(), "ok": True, "registrar": (reg or ""), "expiry": (exp or "")}
                    _cache_put(cache, d, reg, exp, ok=True)
                else:
                    _cache_put(cache, d, None, None, ok=False)

    total_updated = 0
    for path, rows in targets:
        updated = 0
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
        if updated:
            _dump_json(path, rows)
        total_updated += updated

    _dump_json(CACHE_PATH, cache)
    hit_cache = len(all_unique) - len(to_query)
    miss_cache = len(to_query)
    print(f"[OK] files={','.join([p for p,_ in targets])} enriched={total_updated}, new_main={new_main_total}, cache_hit={hit_cache}, cache_miss={miss_cache}, used_da={used_da}, used_rdap={used_rdap}, workers={MAX_WORKERS}, retry={RETRY}")

if __name__ == "__main__":
    main()

