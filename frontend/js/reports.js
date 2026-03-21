// js/reports.js — Security Reports section (all roles, viewer-safe)
(function () {

  const _rc = { bar: null, line: null };

  // ═══════════════════════════════════════════════════════════════
  window.loadReports = async function () {
    _skeleton();
    const data = await API.getReportsSummary();
    if (!data) { _error("Cannot reach server — is the backend running?"); return; }
    _renderStats(data);
    _renderProtocols(data);
    _renderCharts(data);
    _renderRecent(data);
  };

  // ── Stats bar ────────────────────────────────────────────────────────────
  function _renderStats(d) {
    const el = document.getElementById("reports-stats");
    if (!el) return;
    el.innerHTML = [
      { cls:"blue",   icon:"bi-activity",          val: d.total_analyses,           lbl:"Total Analyses" },
      { cls:"red",    icon:"bi-shield-exclamation", val: d.threat_count,             lbl:"Threats Detected" },
      { cls:"green",  icon:"bi-check-circle-fill",  val: d.normal_count,             lbl:"Normal Traffic" },
      { cls:"yellow", icon:"bi-graph-up-arrow",     val: Math.round(d.avg_risk_score * 100) + "%", lbl:"Avg Risk Score" },
      { cls:"purple", icon:"bi-cpu-fill",            val: d.model_accuracy,           lbl:"Model Accuracy" },
    ].map(s => `
      <div class="report-stat-card ${s.cls}">
        <div class="report-stat-icon"><i class="bi ${s.icon}"></i></div>
        <div class="report-stat-val">${s.val}</div>
        <div class="report-stat-lbl">${s.lbl}</div>
      </div>`).join("");
  }

  // ── Protocol breakdown list ───────────────────────────────────────────────
  function _renderProtocols(d) {
    const el = document.getElementById("reports-protocols");
    if (!el || !d.top_protocols?.length) {
      if (el) el.innerHTML = `<span style="color:var(--text-muted);font-size:.82rem;">No data yet.</span>`;
      return;
    }
    const max = d.top_protocols[0].count || 1;
    el.innerHTML = d.top_protocols.map(p => `
      <div class="rpt-proto-row">
        <span class="rpt-proto-name">${p.protocol}</span>
        <div class="rpt-proto-bar-track">
          <div class="rpt-proto-bar-fill"
               style="width:${Math.round(p.count / max * 100)}%;"></div>
        </div>
        <span class="rpt-proto-count">${p.count}</span>
      </div>`).join("");
  }

  // ── Charts ────────────────────────────────────────────────────────────────
  function _renderCharts(d) {
    if (_rc.bar)  { _rc.bar.destroy();  _rc.bar  = null; }
    if (_rc.line) { _rc.line.destroy(); _rc.line = null; }

    // Bar — top attack types
    const barCtx = document.getElementById("reportBarChart")?.getContext("2d");
    if (barCtx) {
      if (d.top_attack_types?.length) {
        _rc.bar = new Chart(barCtx, {
          type: "bar",
          data: {
            labels: d.top_attack_types.map(t => t.type),
            datasets: [{
              label: "Count",
              data:  d.top_attack_types.map(t => t.count),
              backgroundColor: [
                "rgba(239,68,68,.75)","rgba(245,158,11,.75)",
                "rgba(59,130,246,.75)","rgba(34,197,94,.75)",
                "rgba(168,85,247,.75)",
              ],
              borderRadius: 6,
              borderSkipped: false,
            }],
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { grid: { color:"rgba(255,255,255,.04)" },
                   ticks: { color:"#94a3b8", font:{ size:11 } } },
              y: { beginAtZero: true,
                   grid: { color:"rgba(255,255,255,.04)" },
                   ticks: { color:"#94a3b8", precision:0, font:{ size:11 } } },
            },
          },
        });
      } else {
        barCtx.canvas.parentElement.innerHTML = _noData("No attack data yet.");
      }
    }

    // Line — 7-day trend
    const lineCtx = document.getElementById("reportLineChart")?.getContext("2d");
    if (lineCtx) {
      const labels = (d.weekly || []).map(w =>
        new Date(w.date).toLocaleDateString("en-IN", { month:"short", day:"numeric" }));
      _rc.line = new Chart(lineCtx, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "Total Analyses",
              data: (d.weekly || []).map(w => w.total),
              borderColor: "#3b82f6",
              backgroundColor: "rgba(59,130,246,.08)",
              tension: 0.4, fill: true, pointRadius: 4,
            },
            {
              label: "Threats",
              data: (d.weekly || []).map(w => w.threats),
              borderColor: "#ef4444",
              backgroundColor: "rgba(239,68,68,.08)",
              tension: 0.4, fill: true, pointRadius: 4,
            },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          interaction: { mode:"index", intersect:false },
          plugins: {
            legend: {
              labels: { color:"#94a3b8", font:{ size:11 }, boxWidth:12, padding:10 },
            },
          },
          scales: {
            x: { grid:{ color:"rgba(255,255,255,.04)" },
                 ticks:{ color:"#64748b", font:{ size:10 } } },
            y: { beginAtZero:true, grid:{ color:"rgba(255,255,255,.04)" },
                 ticks:{ color:"#64748b", precision:0 } },
          },
        },
      });
    }
  }

  // ── Recent analyses table ─────────────────────────────────────────────────
  function _renderRecent(d) {
    const el = document.getElementById("reports-recent");
    if (!el) return;
    if (!d.recent?.length) {
      el.innerHTML = `<tr><td colspan="5" class="tbl-empty">
        No analyses yet — upload a PCAP file to generate detections.
      </td></tr>`;
      return;
    }
    const C = { Critical:"#fca5a5", High:"#fcd34d", Medium:"#93c5fd", Low:"#86efac" };
    el.innerHTML = d.recent.map(r => `
      <tr>
        <td style="font-weight:600;color:var(--text-main);max-width:220px;
                   overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
            title="${r.filename}">${r.filename}</td>
        <td style="font-weight:700;color:${C[r.risk_label]||"var(--text-muted)"};">
          ${r.risk_label || "—"}
        </td>
        <td style="color:${C[r.risk_label]||"var(--text-muted)"};font-size:.8rem;">
          ${r.attack_type || "—"}
        </td>
        <td class="tbl-right">${(r.total_packets||0).toLocaleString()}</td>
        <td class="tbl-muted">
          ${r.created_at ? r.created_at.substring(0,16).replace("T"," ") : "—"}
        </td>
      </tr>`).join("");
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function _skeleton() {
    const s = document.getElementById("reports-stats");
    if (s) s.innerHTML = Array(5).fill(`
      <div class="report-stat-card" style="opacity:.4;">
        <div class="skeleton-row" style="height:28px;border-radius:6px;margin:0;"></div>
        <div class="skeleton-row" style="width:55%;margin-top:10px;"></div>
      </div>`).join("");
    const r = document.getElementById("reports-recent");
    if (r) r.innerHTML = `<tr><td colspan="5" class="tbl-empty">
      <div class="skeleton-row"></div></td></tr>`;
  }

  function _error(msg) {
    const s = document.getElementById("reports-stats");
    if (s) s.innerHTML = `<div style="color:#f87171;padding:16px;font-size:.85rem;">
      <i class="bi bi-exclamation-triangle-fill me-2"></i>${msg}</div>`;
  }

  function _noData(msg) {
    return `<div style="display:flex;flex-direction:column;align-items:center;
                        justify-content:center;height:100%;color:var(--text-muted);
                        font-size:.82rem;gap:8px;">
      <i class="bi bi-bar-chart" style="font-size:2rem;opacity:.3;"></i>${msg}</div>`;
  }

  // ═══════════════════════════════════════════════════════════════
  // REPORT EXPORT
  // ═══════════════════════════════════════════════════════════════
  window.exportReport = async function (format) {
    const data = await API.getReportsSummary();
    if (!data) { showToast("Cannot fetch report data", "error"); return; }

    if (format === "json") {
      _downloadBlob(JSON.stringify(data, null, 2), "ids_report.json", "application/json");
      showToast("JSON report downloaded", "success");
    } else if (format === "csv") {
      const rows = (data.recent || []);
      const header = "Filename,Risk,Attack Type,Packets,Risk Score,Duration,Protocols,Analysed At\n";
      const csv = header + rows.map(r =>
        `"${r.filename}","${r.risk_label||''}","${r.attack_type||''}",${r.total_packets||0},${r.risk_score||0},${r.duration_seconds||0},"${r.top_protocols||''}","${r.created_at||''}"`
      ).join("\n");
      _downloadBlob(csv, "ids_report.csv", "text/csv");
      showToast("CSV report downloaded", "success");
    } else if (format === "html") {
      const html = _buildHTMLReport(data);
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      showToast("Report opened — use Ctrl+S or Print to save", "success");
    }
  };

  function _downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function _buildHTMLReport(d) {
    const now = new Date().toLocaleString("en-IN");
    const C = { Critical:"#ef4444", High:"#f59e0b", Medium:"#3b82f6", Low:"#22c55e" };
    const recentRows = (d.recent || []).map(r => `
      <tr>
        <td>${r.filename}</td>
        <td style="color:${C[r.risk_label]||'#94a3b8'};font-weight:700">${r.risk_label||'—'}</td>
        <td>${r.attack_type||'—'}</td>
        <td style="text-align:right">${(r.total_packets||0).toLocaleString()}</td>
        <td style="text-align:right">${r.risk_score ? Math.round(r.risk_score*100)+'%' : '—'}</td>
        <td>${r.created_at ? r.created_at.substring(0,16).replace('T',' ') : '—'}</td>
      </tr>`).join("");

    const attacks = (d.top_attack_types || []).map(a =>
      `<li><strong>${a.type}</strong> — ${a.count} occurrence${a.count!==1?'s':''}</li>`).join("");

    const protocols = (d.top_protocols || []).map(p =>
      `<li><strong>${p.protocol}</strong> — ${p.count}</li>`).join("");

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>IDS-ML Security Report — ${now}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:40px;line-height:1.6}
  .container{max-width:900px;margin:0 auto;background:#1e293b;border-radius:12px;padding:36px;box-shadow:0 4px 30px rgba(0,0,0,.5)}
  h1{font-size:1.6rem;color:#f8fafc;margin-bottom:6px;display:flex;align-items:center;gap:10px}
  h1 span{font-size:.7rem;background:#3b82f6;color:#fff;padding:3px 10px;border-radius:12px;font-weight:600}
  .meta{font-size:.8rem;color:#64748b;margin-bottom:28px}
  h2{font-size:1.1rem;color:#94a3b8;margin:28px 0 12px;padding-bottom:6px;border-bottom:1px solid #334155}
  .stats{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
  .stat{flex:1 1 140px;padding:16px;background:#0f172a;border-radius:8px;border-left:3px solid #3b82f6}
  .stat-val{font-size:1.4rem;font-weight:800;color:#f8fafc}
  .stat-lbl{font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.4px;margin-top:3px}
  table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.85rem}
  th{text-align:left;padding:10px 12px;background:#0f172a;color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}
  td{padding:10px 12px;border-bottom:1px solid #1e293b}
  tr:nth-child(even) td{background:rgba(255,255,255,.02)}
  ul{padding-left:18px;font-size:.88rem}
  li{margin-bottom:4px}
  .footer{margin-top:32px;padding-top:16px;border-top:1px solid #334155;font-size:.72rem;color:#475569;text-align:center}
  @media print{body{background:#fff;color:#1e293b;padding:20px}
    .container{background:#fff;box-shadow:none;border:1px solid #e2e8f0}
    .stat{background:#f8fafc;border-left-color:#2563eb}
    th{background:#f1f5f9;color:#475569}
    td{border-bottom-color:#e2e8f0}
    h2{color:#475569;border-bottom-color:#e2e8f0}}
</style></head><body>
<div class="container">
  <h1>🛡 IDS-ML Security Report <span>v2.0</span></h1>
  <div class="meta">Generated: ${now} &nbsp;|&nbsp; Model: ${d.model_name||'Random Forest IDS'} (${d.model_accuracy||'—'})</div>

  <div class="stats">
    <div class="stat"><div class="stat-val">${d.total_analyses||0}</div><div class="stat-lbl">Total Analyses</div></div>
    <div class="stat" style="border-left-color:#ef4444"><div class="stat-val">${d.threat_count||0}</div><div class="stat-lbl">Threats Detected</div></div>
    <div class="stat" style="border-left-color:#22c55e"><div class="stat-val">${d.normal_count||0}</div><div class="stat-lbl">Normal Traffic</div></div>
    <div class="stat" style="border-left-color:#f59e0b"><div class="stat-val">${d.avg_risk_score ? Math.round(d.avg_risk_score*100)+'%' : '0%'}</div><div class="stat-lbl">Avg Risk Score</div></div>
  </div>

  <h2>Top Attack Types</h2>
  ${attacks ? `<ul>${attacks}</ul>` : '<p style="color:#64748b;">No attack types detected.</p>'}

  <h2>Protocol Distribution</h2>
  ${protocols ? `<ul>${protocols}</ul>` : '<p style="color:#64748b;">No protocol data.</p>'}

  <h2>Recent Analyses</h2>
  <table>
    <thead><tr><th>Filename</th><th>Risk</th><th>Attack Type</th><th style="text-align:right">Packets</th><th style="text-align:right">Score</th><th>Date</th></tr></thead>
    <tbody>${recentRows || '<tr><td colspan="6" style="text-align:center;color:#64748b">No data</td></tr>'}</tbody>
  </table>

  <div class="footer">IDS-ML v2.0 — Intrusion Detection System &nbsp;|&nbsp; Report auto-generated</div>
</div></body></html>`;
  }

})();
