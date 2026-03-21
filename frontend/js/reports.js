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

})();
