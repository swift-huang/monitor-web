#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, send_from_directory
import subprocess, os, time, pathlib

# ---- 基本設定 ----
BASE_DIR = pathlib.Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR / "../frontend").resolve()
DATA_DIR = (BASE_DIR / "data").resolve()
os.chdir(BASE_DIR)

app = Flask(__name__)

def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.after_request
def add_common_headers(resp):
    # /data 與前端資源都不快取（開發時好用）
    if request.path.startswith("/data/") or \
       request.path.startswith("/css/") or \
       request.path.startswith("/js/"):
        _no_cache(resp)
    return resp

# ---------- 前端頁面 ----------
@app.get("/")
def index():
    # ../frontend/index.html
    return send_from_directory(FRONTEND_DIR, "index.html")

# 服務 /css/* 與 /js/* 靜態檔
@app.get("/css/<path:filename>")
def css_files(filename):
    resp = send_from_directory(FRONTEND_DIR / "css", filename)
    return _no_cache(resp)

@app.get("/js/<path:filename>")
def js_files(filename):
    resp = send_from_directory(FRONTEND_DIR / "js", filename)
    return _no_cache(resp)

# ---------- 提供資料 ----------
@app.get("/data/<path:filename>")
def data_files(filename):
    # 讓前端以 /data/sites.json 直接拿最新資料
    resp = send_from_directory(DATA_DIR, filename)
    return _no_cache(resp)

# ---------- API ----------
@app.post("/api/run_zbx")
def run_zbx():
    """執行 backend/run_zbx.sh：抓 Zabbix、補 whois，再讓前端重抓 /data/sites.json"""
    try:
        proc = subprocess.run(
            ["bash", "./run_zbx.sh"],
            capture_output=True, text=True, timeout=900
        )
        return jsonify({
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "ts": int(time.time())
        }), (200 if proc.returncode == 0 else 500)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "cwd": str(BASE_DIR)})

if __name__ == "__main__":
    # python3 api_server.py
    app.run(host="0.0.0.0", port=8787)