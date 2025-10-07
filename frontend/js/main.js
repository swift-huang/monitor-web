(function () {
  // 由單一改為多來源：Zabbix + Other（若 other 檔不存在會自動忽略）
  const DATA_URLS = ["/data/sites.json", "/data/sites_other.json"];
  const API_RUN_ZBX = "/api/run_zbx";
  const $ = (id) => document.getElementById(id);

  // 狀態
  let sortField = null;
  let sortAsc = true;
  let suppressSortUntil = 0; // 拖曳欄寬後，暫停排序點擊 300ms
  let _allData = [];
  let _viewRows = [];
  let _loading = false;

  // 被選取集合（以 itemid 或 site|key_ 為唯一鍵）
  const selected = new Set();
  const rowId = (r) => (r.itemid ? String(r.itemid) : `${r.site}|${r.key_ || ""}`);

  // ===== Meta 顯示 =====
  function setMeta({ count = null, msg = "", ok = null } = {}) {
    const n = (count ?? _viewRows.length) || 0;
    const sel = selected.size;
    let base = `顯示 ${n} 筆 · 已選 ${sel} 筆`;
    if (msg) {
      const tag =
        ok === true
          ? '<span class="ml-2 inline-flex items-center gap-1 rounded bg-emerald-100 text-emerald-700 px-2 py-0.5 text-xs">更新完成 ✅</span>'
          : ok === false
          ? '<span class="ml-2 inline-flex items-center gap-1 rounded bg-red-100 text-red-700 px-2 py-0.5 text-xs">更新失敗 ❌</span>'
          : '<span class="ml-2 inline-flex items-center gap-1 rounded bg-slate-200 text-slate-700 px-2 py-0.5 text-xs">更新中…</span>';
      base += tag;
    }
    $("meta").innerHTML = base;
  }

  // ===== 小工具 =====
  function badge(text, cls) {
    return `<span class="px-2 py-0.5 rounded-full text-xs ${cls}">${text}</span>`;
  }
  function statusBadge(avail) {
    if (avail === "up") return badge("UP", "bg-emerald-100 text-emerald-700");
    if (avail === "down") return badge("DOWN", "bg-red-100 text-red-700");
    return badge("UNKNOWN", "bg-slate-200 text-slate-700");
  }
  function daysLeft(expStr) {
    if (!expStr) return null;
    const ms = Date.parse(expStr);
    if (isNaN(ms)) return null;
    return Math.floor((ms - Date.now()) / 86400000);
  }
  function expiryBadge(expStr) {
    if (!expStr) return `<span class="text-slate-400">—</span>`;
    const d = daysLeft(expStr);
    if (d === null) return `<span>${expStr}</span>`;
    if (d <= 30) return badge(`${expStr}（${d}天）`, "bg-red-100 text-red-700");
    if (d <= 90) return badge(`${expStr}（${d}天）`, "bg-amber-100 text-amber-700");
    return `<span>${expStr}</span>`;
  }

  async function fetchJSON(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  }

  // ===== 資料載入 =====
  async function load() {
    // 同時抓兩份，容錯：其中一份失敗則回傳空陣列
    const datasets = await Promise.all(
      DATA_URLS.map(async (url) => {
        try {
          return await fetchJSON(url);
        } catch (_) {
          return [];
        }
      })
    );

    // 合併：Zabbix 在前，Other 在後
    const data = datasets.flat();

    // 建立 BU 下拉
    const buSet = new Set(data.map((x) => x.bu).filter(Boolean));
    $("bu").innerHTML =
      '<option value="">全部 BU</option>' +
      [...buSet]
        .sort()
        .map((b) => `<option value="${b}">${b}</option>`)
        .join("");

    // 標記重複（跨來源一起計數）
    const siteCount = {};
    data.forEach((x) => (siteCount[x.site] = (siteCount[x.site] || 0) + 1));

    _allData = data.map((x) => ({ ...x, _dup: siteCount[x.site] > 1 }));
    render();
  }

  // ===== 排序箭頭 =====
  function updateSortIndicators() {
    document.querySelectorAll("#tbl-head th[data-sort] .th-label").forEach((lbl) => {
      const th = lbl.closest("th");
      const field = th.dataset.sort;
      const base = lbl.textContent.replace(/[▲▼]\s*$/, "").trim();
      lbl.textContent = base + (sortField === field ? (sortAsc ? " ▲" : " ▼") : "");
    });
  }

  // ===== 表頭核取方塊三態 =====
  function syncHeaderCheck() {
    const head = $("chkAllHead");
    if (!_viewRows.length) {
      head.checked = false;
      head.indeterminate = false;
      return;
    }
    const allIds = _viewRows.map(rowId);
    const selectedInView = allIds.filter((id) => selected.has(id)).length;
    head.checked = selectedInView === allIds.length && allIds.length > 0;
    head.indeterminate = selectedInView > 0 && selectedInView < allIds.length;
  }

  // ===== 繪製表身 =====
  function render() {
    const q = $("q").value.trim().toLowerCase();
    const dupOnly = $("dupOnly").checked;
    const badOnly = $("badOnly").checked;
    const bu = $("bu").value;

    let rows = _allData.slice();

    if (bu) rows = rows.filter((r) => r.bu === bu);
    if (dupOnly) rows = rows.filter((r) => r._dup);
    if (badOnly) rows = rows.filter((r) => r.available !== "up");

    if (q) {
      // 以空格拆開多個關鍵字（OR）
      const keywords = q.split(/\s+/).filter(Boolean);
      rows = rows.filter((r) => {
        const hay = `${r.site} ${r.bu} ${r.host} ${r.key_}`.toLowerCase();
        return keywords.some((kw) => hay.includes(kw));
      });
    }

    if (sortField) {
      rows.sort((a, b) => {
        let av = a[sortField] ?? "";
        let bv = b[sortField] ?? "";
        if (sortField === "code") {
          av = parseInt(av) || 0;
          bv = parseInt(bv) || 0;
          return sortAsc ? av - bv : bv - av;
        }
        if (sortField === "domain_expiry") {
          const ad = Date.parse(av) || 0;
          const bd = Date.parse(bv) || 0;
          return sortAsc ? ad - bd : bd - ad;
        }
        const cmp = av.toString().localeCompare(bv.toString(), "zh-Hant");
        return sortAsc ? cmp : -cmp;
      });
    }

    _viewRows = rows;
    $("tbody").innerHTML = rows
      .map((r) => {
        const id = rowId(r);
        const checked = selected.has(id) ? "checked" : "";
        return `
          <tr class="border-t ${r._dup ? "bg-amber-50" : ""}">
            <td class="p-2">
              <input type="checkbox" class="rowchk accent-slate-700" data-id="${id}" ${checked}>
            </td>
            <td class="p-2">${r.bu || ""}</td>
            <td class="p-2">${r.display_name || r.site}</td>
            <td class="p-2">${r.whois_domain || "—"}</td>
            <td class="p-2">${expiryBadge(r.domain_expiry || "")}</td>
            <td class="p-2">${r.registrar || "—"}</td>
            <td class="p-2">${r.code || ""}</td>
            <td class="p-2">${statusBadge(r.available)}</td>
            <td class="p-2">${r.ts || ""}</td>
            <td class="p-2">${r.host || ""}</td>
            <td class="p-2">${r.itemid || ""}</td>
            <td class="p-2 whitespace-nowrap">${r.key_ || ""}</td>
          </tr>`;
      })
      .join("");

    // 綁定列勾選
    document.querySelectorAll(".rowchk").forEach((chk) => {
      chk.addEventListener("change", (e) => {
        const id = e.target.dataset.id;
        if (e.target.checked) selected.add(id);
        else selected.delete(id);
        syncHeaderCheck();
        setMeta({});
      });
    });

    updateSortIndicators();
    syncHeaderCheck();
    if (!_loading) setMeta({});
  }

  // ===== 排序點擊（只點文字才會觸發，避免與拖曳衝突） =====
  function attachSortHandlers() {
    document.querySelectorAll("#tbl-head th[data-sort] .th-label").forEach((lbl) => {
      lbl.addEventListener("click", () => {
        if (Date.now() < suppressSortUntil) return; // 拖曳後短暫抑制
        const th = lbl.closest("th");
        const field = th.dataset.sort;
        if (sortField === field) sortAsc = !sortAsc;
        else {
          sortField = field;
          sortAsc = true;
        }
        render();
      });
    });
  }

  // ===== 欄寬同步/拖曳 =====
  function syncColWidths() {
    const hCols = document.querySelectorAll("#colgroup-head col");
    const bCols = document.querySelectorAll("#colgroup-body col");
    hCols.forEach((c, i) => {
      if (bCols[i]) bCols[i].style.width = c.style.width;
    });
  }

  function attachResize() {
    const hCols = document.querySelectorAll("#colgroup-head col");

    document.querySelectorAll("#tbl-head th.th-resizable").forEach((th, i) => {
      const grip = th.querySelector(".resizer");
      if (!grip) return;

      let startX = 0,
        startW = 0;

      grip.addEventListener("mousedown", (e) => {
        startX = e.pageX;
        startW = hCols[i].offsetWidth;
        document.body.classList.add("no-select");

        const move = (e2) => {
          const w = Math.max(40, startW + (e2.pageX - startX));
          hCols[i].style.width = w + "px";
          syncColWidths();
        };
        const up = () => {
          document.body.classList.remove("no-select");
          document.removeEventListener("mousemove", move);
          document.removeEventListener("mouseup", up);
          suppressSortUntil = Date.now() + 300; // 避免拖把放開被判定點擊
          // 記憶欄寬
          const widths = [...hCols].map((c) => c.style.width);
          localStorage.setItem("tbl-widths", JSON.stringify(widths));
        };

        document.addEventListener("mousemove", move);
        document.addEventListener("mouseup", up);
      });
    });

    // 還原已記憶的欄寬
    const saved = localStorage.getItem("tbl-widths");
    if (saved) {
      try {
        JSON.parse(saved).forEach((w, i) => {
          if (hCols[i] && w) hCols[i].style.width = w;
        });
      } catch {}
    }
    syncColWidths();
  }

  // ===== 重新載入 =====
  async function triggerReload() {
    if (_loading) return;
    _loading = true;
    const btn = $("reload");
    btn.disabled = true;
    btn.textContent = "更新中...";
    setMeta({ msg: "更新中", ok: null });

    try {
      const r = await fetch(API_RUN_ZBX, { method: "POST" });
      if (!r.ok) throw new Error(await r.text().catch(() => "run_zbx failed"));
      await load();
      setMeta({ msg: "完成", ok: true });
    } catch (e) {
      console.error(e);
      setMeta({ msg: "失敗", ok: false });
    } finally {
      setTimeout(() => setMeta({}), 2000);
      btn.disabled = false;
      btn.textContent = "重新載入";
      _loading = false;
    }
  }

  // ===== 選取/匯出 =====
  function toggleSelectVisible(checked) {
    _viewRows.forEach((r) => {
      const id = rowId(r);
      if (checked) selected.add(id);
      else selected.delete(id);
    });
    render(); // 讓勾選狀態同步、三態 header 更新
  }

  function exportSelectedCsv() {
    const rows = _allData.filter((r) => selected.has(rowId(r)));
    if (!rows.length) {
      alert("尚未選取任何資料");
      return;
    }
    const headers = [
      "BU",
      "Site",
      "Main Domain",
      "到期日",
      "Registrar",
      "Code",
      "Status",
      "Time",
      "Host",
      "itemid",
      "key_",
    ];
    const cols = [
      "bu",
      "site",
      "whois_domain",
      "domain_expiry",
      "registrar",
      "code",
      "available",
      "ts",
      "host",
      "itemid",
      "key_",
    ];

    // 依欄位做適當轉換與引用（CSV 安全）
    const escapeField = (value, col) => {
      let s = (value ?? "").toString();

      // BU 若是純數字（例如 09），用前置單引號讓 Excel 以文字處理，保留前導 0
      if (col === "bu" && /^\d+$/.test(s)) {
        s = "'" + s; // 變成 '09，Excel 讀入後會顯示 09
      }

      // 一般 CSV 轉義：把雙引號變成兩個雙引號，然後整欄再用雙引號包住
      s = s.replace(/"/g, '""');
      return `"${s}"`;
    };

    const lines = [];
    lines.push(headers.map((h) => `"${h.replace(/"/g, '""')}"`).join(","));
    rows.forEach((r) => {
      lines.push(cols.map((c) => escapeField(r[c], c)).join(","));
    });

    const csv = "\uFEFF" + lines.join("\n"); // UTF-8 BOM
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 16);
    a.href = url;
    a.download = `web-monitor-${ts}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ===== 初始化 =====
  window.addEventListener("DOMContentLoaded", async () => {
    attachSortHandlers(); // 表頭是靜態的，可先綁
    attachResize(); // 設定拖曳與欄寬還原
    await load(); // 載入資料並 render

    $("reload").addEventListener("click", triggerReload);
    $("q").addEventListener("input", () => {
      render();
      setMeta({});
    });
    $("dupOnly").addEventListener("change", () => {
      render();
      setMeta({});
    });
    $("badOnly").addEventListener("change", () => {
      render();
      setMeta({});
    });
    $("bu").addEventListener("change", () => {
      render();
      setMeta({});
    });

    // 主核取方塊：對目前結果全選/全不選
    $("chkAllHead").addEventListener("change", (e) => {
      toggleSelectVisible(e.target.checked);
    });

    // 控制列按鈕
    $("btnSelectVisible").addEventListener("click", () => {
      // 若目前已全選就改為全不選；否則全選
      const head = $("chkAllHead");
      toggleSelectVisible(!(head.checked && !head.indeterminate));
    });
    $("btnExportCsv").addEventListener("click", exportSelectedCsv);
    $("btnClearSel").addEventListener("click", () => {
      selected.clear();
      render();
    });
  });
})();

