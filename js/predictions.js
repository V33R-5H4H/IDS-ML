// js/predictions.js — Predictions Feed
// Consumes GET /analyze-pcap/history and renders a filterable risk feed.
// loadPredictions() is called by dashboard.js navigateTo('predictions').
(function () {

  let _filter    = "all";
  let _data      = [];
  let _limit     = 20;
  let _timer     = null;

  // ── Risk colour palette ─────────────────────────────────────────────────────
  const RISK = {
    Critical: { bar:"#ef4444", text:"#fca5a5", bg:"rgba(239,68,68,.12)",  border:"rgba(239,68,68,.3)",  icon:"bi-exclamation-octagon-fill" },
    High:     { bar:"#f59e0b", text:"#fcd34d", bg:"rgba(245,158,11,.12)", border:"rgba(245,158,11,.3)", icon:"bi-exclamation-triangle-fill" },
    Medium:   { bar:"#3b82f6", text:"#93c5fd", bg:"rgba(59,130,246,.12)", border:"rgba(59,130,246,.3)", icon:"bi-shield-exclamation" },
    Low:      { bar:"#22c55e", text:"#86efac", bg:"rgba(34,197,94,.12)",  border:"rgba(34,197,94,.3)",  icon:"bi-shield-check" },
  };
  const rc = l => RISK[l] || RISK.Low;

  // ═══════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════════
  window.loadPredictions = async function () {
    _limit = 20;
    _filter = "all";
    document.querySelectorAll(".pred-filter-btn").forEach((b, i) =>
      b.classList.toggle("active", i === 0));
    await _fetchRender(false);
    _startRefresh();
  };

  window.setPredFilter = function (filter, btn) {
    _filter = filter;
    document.querySelectorAll(".pred-filter-btn").forEach(b =>
      b.classList.toggle("active", b === btn));
    _renderFeed(_data);
  };

  window.predLoadMore = function () {
    _limit += 20;
    _renderFeed(_data);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTO-REFRESH (every 30 s while section is active)
  // ═══════════════════════════════════════════════════════════════════════════
  function _startRefresh() {
    if (_timer) clearInterval(_timer);
    _timer = setInterval(async () => {
      const sec = document.getElementById("section-predictions");
      if (!sec || !sec.classList.contains("active")) {
        clearInterval(_timer); _timer = null; return;
      }
      await _fetchRender(true); // silent — no skeleton flash
    }, 30_000);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FETCH
  // ═══════════════════════════════════════════════════════════════════════════
  async function _fetchRender(silent) {
    if (!silent) _skeleton();
    const rows = await API.getPcapHistory(100);
    if (!rows) { _error("Cannot reach server. Is the backend running?"); return; }
    _data = rows;
    _renderStats(rows);
    _renderFeed(rows);
    _updateBadge(rows);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STATS BAR
  // ═══════════════════════════════════════════════════════════════════════════
  function _renderStats(rows) {
    const el = document.getElementById("pred-stats-bar");
    if (!el) return;
    const cnt = l => rows.filter(r => r.risk_label === l).length;
    const critical = cnt("Critical"), high = cnt("High"),
          medium   = cnt("Medium"),   low  = cnt("Low");
    const threats  = critical + high;
    el.innerHTML = `
      <div class="pred-stat">
        <span class="pred-stat-val">${rows.length}</span>
        <span class="pred-stat-lbl">Total Analyses</span>
      </div>
      <div class="pred-stat-div"></div>
      <div class="pred-stat">
        <span class="pred-stat-val" style="color:#fca5a5;">${critical}</span>
        <span class="pred-stat-lbl">Critical</span>
      </div>
      <div class="pred-stat">
        <span class="pred-stat-val" style="color:#fcd34d;">${high}</span>
        <span class="pred-stat-lbl">High</span>
      </div>
      <div class="pred-stat">
        <span class="pred-stat-val" style="color:#93c5fd;">${medium}</span>
        <span class="pred-stat-lbl">Medium</span>
      </div>
      <div class="pred-stat">
        <span class="pred-stat-val" style="color:#86efac;">${low}</span>
        <span class="pred-stat-lbl">Normal / Low</span>
      </div>
      <div class="pred-stat-div"></div>
      <div class="pred-stat">
        <span class="pred-stat-val" style="color:${threats > 0 ? "#fca5a5" : "#86efac"};">
          ${threats}
        </span>
        <span class="pred-stat-lbl">Threats</span>
      </div>
      <div class="pred-stat-div"></div>
      <div class="pred-stat" title="Auto-refreshes every 30 seconds">
        <span class="pred-stat-val" style="font-size:.8rem;color:var(--accent-teal);">
          <i class="bi bi-arrow-repeat"></i> 30s
        </span>
        <span class="pred-stat-lbl">Auto-Refresh</span>
      </div>`;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FEED
  // ═══════════════════════════════════════════════════════════════════════════
  function _renderFeed(rows) {
    const feed = document.getElementById("pred-feed");
    const more = document.getElementById("pred-load-more");
    if (!feed) return;

    const filtered = _filter === "all"
      ? rows
      : rows.filter(r => (r.risk_label || "Low").toLowerCase() === _filter.toLowerCase());

    const slice = filtered.slice(0, _limit);

    if (slice.length === 0) {
      feed.innerHTML = `
        <div class="pred-empty">
          <i class="bi bi-shield-check pred-empty-icon"></i>
          <div style="margin-bottom:10px;">
            ${_filter === "all"
              ? "No PCAP analyses yet."
              : `No <strong>${_filter}</strong> risk entries found.`}
          </div>
          ${_filter === "all"
            ? `<button class="btn btn-primary btn-sm" onclick="navigateTo('pcap')">
                 <i class="bi bi-upload me-1"></i>Upload PCAP
               </button>`
            : ""}
        </div>`;
      if (more) more.style.display = "none";
      return;
    }

    feed.innerHTML = slice.map(_card).join("");

    // Animate bars after browser paint
    requestAnimationFrame(() => requestAnimationFrame(() => {
      document.querySelectorAll(".pred-bar-fill[data-w]").forEach(b => {
        b.style.width = b.dataset.w + "%";
      });
    }));

    if (more) more.style.display = filtered.length > _limit ? "flex" : "none";
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CARD BUILDER
  // ═══════════════════════════════════════════════════════════════════════════
  function _card(r) {
    const label  = r.risk_label  || "Low";
    const score  = r.risk_score  != null ? r.risk_score : 0;
    const pct    = Math.round(score * 100);
    const c      = rc(label);
    const attack = r.attack_type || _inferAttack(r, label);
    const proto  = (r.top_protocols || "—")
      .split(",").map(p => `<span class="proto-pill">${p.trim()}</span>`).join("");

    // Protocol donut-style mini bars
    const total  = Math.max(r.total_packets || 1, 1);
    const tcpPct = Math.round((r.tcp_packets  || 0) / total * 100);
    const udpPct = Math.round((r.udp_packets  || 0) / total * 100);
    const icmPct = Math.round((r.icmp_packets || 0) / total * 100);

    return `
    <div class="pred-card" style="border-left:3px solid ${c.bar};">
      <!-- Top row: filename + badges -->
      <div class="pred-card-top">
        <div class="pred-card-file">
          <i class="bi bi-file-earmark-binary-fill"
             style="color:${c.bar};font-size:1rem;margin-right:8px;flex-shrink:0;"></i>
          <span class="pred-card-fname" title="${_esc(r.filename)}">
            ${_trunc(r.filename, 48)}
          </span>
        </div>
        <div class="pred-card-badges">
          <span class="pred-risk-badge"
                style="background:${c.bg};border:1px solid ${c.border};color:${c.text};">
            <i class="bi ${c.icon} me-1"></i>${label}
          </span>
          <span class="pred-time">${_ago(r.created_at)}</span>
        </div>
      </div>

      <!-- Risk bar -->
      <div class="pred-risk-row">
        <span class="pred-risk-lbl" style="color:${c.text};">Risk Score</span>
        <div class="pred-bar-track">
          <div class="pred-bar-fill" data-w="${pct}"
               style="background:${c.bar};width:0%;"></div>
        </div>
        <span class="pred-risk-pct" style="color:${c.text};">${pct}%</span>
      </div>

      <!-- Meta grid -->
      <div class="pred-meta-grid">
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-tag-fill me-1"></i>Attack Type</span>
          <span class="pred-meta-val" style="color:${c.text};font-weight:600;">${attack}</span>
        </div>
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-cpu me-1"></i>Model</span>
          <span class="pred-meta-val">${r.model_used || "heuristic"}</span>
        </div>
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-box-seam me-1"></i>Packets</span>
          <span class="pred-meta-val">${(r.total_packets || 0).toLocaleString()}</span>
        </div>
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-speedometer2 me-1"></i>B/s</span>
          <span class="pred-meta-val">${(r.bytes_per_second || 0).toFixed(1)}</span>
        </div>
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-pc-display me-1"></i>Src IPs</span>
          <span class="pred-meta-val">${r.unique_src_ips || 0}
            <span style="color:var(--text-muted);"> / ${r.unique_dst_ips || 0} dst</span>
          </span>
        </div>
        <div class="pred-meta-item">
          <span class="pred-meta-key"><i class="bi bi-stopwatch me-1"></i>Duration</span>
          <span class="pred-meta-val">${(r.duration_seconds || 0).toFixed(2)} s</span>
        </div>
      </div>

      <!-- Protocol breakdown mini-bars -->
      <div class="pred-proto-row">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">${proto}</div>
        <div class="pred-proto-bars">
          <div class="pred-proto-bar" title="TCP ${tcpPct}%">
            <div style="height:100%;width:${tcpPct}%;background:#3b82f6;border-radius:3px;"></div>
          </div>
          <div class="pred-proto-bar" title="UDP ${udpPct}%">
            <div style="height:100%;width:${udpPct}%;background:#f59e0b;border-radius:3px;"></div>
          </div>
          <div class="pred-proto-bar" title="ICMP ${icmPct}%">
            <div style="height:100%;width:${icmPct}%;background:#ef4444;border-radius:3px;"></div>
          </div>
          <div class="pred-proto-labels">
            <span style="color:#93c5fd;">TCP ${tcpPct}%</span>
            <span style="color:#fcd34d;">UDP ${udpPct}%</span>
            <span style="color:#fca5a5;">ICMP ${icmPct}%</span>
          </div>
        </div>
      </div>
    </div>`;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BADGE UPDATE
  // ═══════════════════════════════════════════════════════════════════════════
  function _updateBadge(rows) {
    const threats = rows.filter(r =>
      r.risk_label === "Critical" || r.risk_label === "High").length;
    const badge = document.getElementById("predBadge");
    if (!badge) return;
    if (threats > 0) {
      badge.textContent    = threats;
      badge.style.display  = "inline-block";
    } else {
      badge.style.display  = "none";
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════════════════
  function _skeleton() {
    const feed = document.getElementById("pred-feed");
    if (!feed) return;
    feed.innerHTML = Array(3).fill(`
      <div class="pred-card" style="border-left:3px solid var(--border);">
        <div class="skeleton-row"></div>
        <div class="skeleton-row" style="width:75%;margin-top:10px;"></div>
        <div class="skeleton-row" style="width:50%;margin-top:10px;"></div>
      </div>`).join("");
  }

  function _error(msg) {
    const feed = document.getElementById("pred-feed");
    if (feed) feed.innerHTML = `
      <div class="pred-empty" style="color:#f87171;">
        <i class="bi bi-exclamation-triangle-fill pred-empty-icon"></i>
        <div>${msg}</div>
      </div>`;
  }

  function _inferAttack(r, label) {
    if (label === "Low") return "Normal Traffic";
    const total  = Math.max(r.total_packets || 1, 1);
    const icmpR  = (r.icmp_packets || 0) / total;
    const bps    = r.bytes_per_second || 0;
    const src    = r.unique_src_ips   || 1;
    const dur    = Math.max(r.duration_seconds || 1, 0.001);
    if (label === "Medium") return icmpR > 0.3 ? "ICMP Probe" : "Suspicious Activity";
    if (icmpR > 0.40)  return "ICMP Flood";
    if (bps   > 500000) return "DDoS / Volumetric";
    if (src   > 50)     return "Port Scan";
    if (dur < 1 && total > 500) return "Burst Attack";
    return "Network Anomaly";
  }

  function _ago(dateStr) {
    if (!dateStr) return "—";
    const s = Math.floor((Date.now() - new Date(dateStr)) / 1000);
    if (s < 60)    return `${s}s ago`;
    if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function _trunc(str, n) {
    return str && str.length > n ? str.slice(0, n) + "…" : (str || "—");
  }

  function _esc(str) {
    return (str || "").replace(/"/g, "&quot;");
  }

})();
