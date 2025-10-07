#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, send_from_directory
import subprocess, os, time, pathlib

# ---- 基本設定 ----
BASE_DIR = pathlib.Path(__file__).resolve().parent              # /opt/monitor-web/backend
FRONTEND_DIR = (BASE_DIR / "../frontend").resolve()             # /opt/monitor-web/frontend
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
    if (request.path.startswith("/data/") or
        request.path.startswith("/css/")  or
        request.path.startswith("/js/")   or
        request.path.startswith("/images/") or
        request.path == "/favicon.ico"):
        _no_cache(resp)
    return resp

# ---------- 前端頁面 ----------
@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.get("/css/<path:filename>")
def css_files(filename):
    resp = send_from_directory(FRONTEND_DIR / "css", filename)
    return _no_cache(resp)

@app.get("/js/<path:filename>")
def js_files(filename):
    resp = send_from_directory(FRONTEND_DIR / "js", filename)
    return _no_cache(resp)

# 新增：images 與 favicon
@app.get("/images/<path:filename>")
def image_files(filename):
    return send_from_directory(FRONTEND_DIR / "images", filename)

@app.get("/favicon.ico")
def favicon():
    # 優先從 images/ 取；若未來你保留根目錄 symlink 也能 fallback
    img_dir = FRONTEND_DIR / "images"
    if (img_dir / "favicon.ico").exists():
        return send_from_directory(img_dir, "favicon.ico")
    return send_from_directory(FRONTEND_DIR, "favicon.ico")

# ---------- 提供資料 ----------
@app.get("/data/<path:filename>")
def data_files(filename):
    resp = send_from_directory(DATA_DIR, filename)
    return _no_cache(resp)

# ---------- API ----------
@app.post("/api/run_zbx")
def run_zbx():
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
    app.run(host="0.0.0.0", port=8787)

