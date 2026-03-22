// frontend/js/live_capture.js — Live capture UI logic + WebSocket client

(function () {
  "use strict";

  let ws = null;
  let packetCount = 0;
  let startTime = null;
  let statsInterval = null;
  const MAX_ROWS = 800;

  // ── Initialisation ──────────────────────────────────────────────────────
  window.initLiveCapture = async function () {
    packetCount = 0;
    startTime = null;
    _updateLiveStats({ total_packets: 0, duration_seconds: 0, threats_detected: 0, packets_per_sec: 0, ml_predictions: 0, unique_src_ips: 0, unique_dst_ips: 0 });
    await _loadInterfaces();
    await _syncCaptureState();
  };

  // ── Load available interfaces ───────────────────────────────────────────
  async function _loadInterfaces() {
    const sel = document.getElementById("liveIfaceSelect");
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading…</option>';

    const r = await API.request("/live-capture/interfaces");
    if (!r || !r.ok) {
      sel.innerHTML = '<option value="">⚠ Failed to load interfaces</option>';
      return;
    }
    const data = await r.json();
    if (data.error) {
      sel.innerHTML = `<option value="">⚠ ${data.error}</option>`;
      _showCaptureError(data.error);
      return;
    }
    const ifaces = data.interfaces || [];
    if (!ifaces.length) {
      sel.innerHTML = '<option value="">No interfaces found</option>';
      return;
    }
    sel.innerHTML = '<option value="">(Auto-detect)</option>' +
      ifaces.map(i => {
        const label = i.description
          ? `${i.name} — ${i.description}${i.ip ? ` (${i.ip})` : ""}`
          : i.name;
        return `<option value="${i.name}">${label}</option>`;
      }).join("");
  }

  // ── Sync with backend state ─────────────────────────────────────────────
  async function _syncCaptureState() {
    const r = await API.request("/live-capture/status");
    if (!r || !r.ok) return;
    const st = await r.json();
    if (st.running) {
      _setUI("running");
      startTime = Date.now() - (st.duration_seconds * 1000);
      packetCount = st.total_packets;
      _startStatsTimer();
      _connectWebSocket();
    } else {
      _setUI("stopped");
    }
  }

  // ── Start / Stop ────────────────────────────────────────────────────────
  window.startLiveCapture = async function () {
    const iface = document.getElementById("liveIfaceSelect")?.value || null;
    const filter = document.getElementById("liveBpfFilter")?.value || null;

    _clearError();
    const r = await API.request("/live-capture/start", {
      method: "POST",
      body: JSON.stringify({ interface: iface, bpf_filter: filter }),
    });
    if (!r) { _showCaptureError("Cannot connect to server"); return; }
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      _showCaptureError(d.detail || "Failed to start capture");
      return;
    }

    packetCount = 0;
    startTime = Date.now();
    _clearFeed();
    _setUI("running");
    _startStatsTimer();
    _connectWebSocket();
  };

  window.stopLiveCapture = async function () {
    const r = await API.request("/live-capture/stop", { method: "POST" });
    _disconnectWebSocket();
    _stopStatsTimer();
    _setUI("stopped");
    if (r && r.ok) {
      const data = await r.json();
      const s = data.summary || {};
      _updateLiveStats(s);
    }
  };

  // ── WebSocket ───────────────────────────────────────────────────────────
  function _connectWebSocket() {
    _disconnectWebSocket();
    const token = Auth.getToken();
    if (!token) return;

    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${new URL(API_BASE).host}/ws/live-capture?token=${token}`;
    ws = new WebSocket(wsUrl);

    ws.onmessage = (evt) => {
      try {
        const pkt = JSON.parse(evt.data);
        if (pkt.type === "ping") return;
        _appendPacketRow(pkt);
      } catch (e) { /* ignore malformed */ }
    };

    ws.onclose = () => { ws = null; };
    ws.onerror = () => { ws = null; };
  }

  function _disconnectWebSocket() {
    if (ws) { try { ws.close(); } catch (e) {} ws = null; }
  }

  // ── Packet Feed ─────────────────────────────────────────────────────────
  function _appendPacketRow(pkt) {
    packetCount++;
    const tbody = document.getElementById("liveFeedBody");
    if (!tbody) return;

    const tr = document.createElement("tr");
    tr.className = `live-feed-row risk-${pkt.risk || "low"}`;
    tr.style.cursor = "pointer";
    tr.onclick = () => _showPacketDetail(pkt);

    const time = new Date(pkt.timestamp).toLocaleTimeString("en-IN", {
      hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
      fractionalSecondDigits: 3,
    });

    const prediction = pkt.prediction || "—";
    const predClass = prediction !== "—" && prediction !== "normal" ? "threat-label" : "normal-label";

    tr.innerHTML = `
      <td class="live-feed-time">${time}</td>
      <td>${pkt.src || "—"}</td>
      <td>${pkt.dst || "—"}</td>
      <td><span class="live-proto-badge ${pkt.protocol?.toLowerCase() || ""}">${pkt.protocol || "—"}</span></td>
      <td class="text-right">${pkt.length ?? "—"}</td>
      <td>${pkt.info || ""}</td>
      <td><span class="${predClass}">${prediction}</span></td>
      <td><span class="live-risk-badge ${pkt.risk || "low"}">${(pkt.risk || "low").toUpperCase()}</span></td>
    `;

    tbody.appendChild(tr);

    // Circular buffer
    while (tbody.children.length > MAX_ROWS) {
      tbody.removeChild(tbody.firstChild);
    }

    // Auto-scroll
    const feed = document.getElementById("liveFeedWrap");
    if (feed) feed.scrollTop = feed.scrollHeight;

    // Update feed count badge
    const badge = document.getElementById("liveFeedCount");
    if (badge) badge.textContent = packetCount.toLocaleString();
  }

  function _clearFeed() {
    const tbody = document.getElementById("liveFeedBody");
    if (tbody) tbody.innerHTML = "";
    packetCount = 0;
    const badge = document.getElementById("liveFeedCount");
    if (badge) badge.textContent = "0";
  }

  // ── Packet Detail Inspector ─────────────────────────────────────────────
  function _showPacketDetail(pkt) {
    const panel = document.getElementById("packetDetailPanel");
    const content = document.getElementById("packetDetailContent");
    if (!panel || !content) return;

    const fields = [
      ["Timestamp", pkt.timestamp],
      ["Source", pkt.src],
      ["Destination", pkt.dst],
      ["Protocol", pkt.protocol],
      ["Length", `${pkt.length} bytes`],
      ["Info", pkt.info],
      ["Flags", pkt.flags || "N/A"],
      ["ML Prediction", pkt.prediction || "None"],
      ["Risk Level", (pkt.risk || "low").toUpperCase()],
    ];

    content.innerHTML = `
      <div style="display:grid;grid-template-columns:140px 1fr;gap:4px 16px;">
        ${fields.map(([label, val]) => `
          <span style="color:#64748b;font-weight:600;">${label}:</span>
          <span style="color:${label === 'Risk Level' && val === 'HIGH' ? '#ef4444' : '#e2e8f0'}">${val || "—"}</span>
        `).join("")}
      </div>
    `;
    panel.style.display = "block";
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ── Stats Timer ─────────────────────────────────────────────────────────
  function _startStatsTimer() {
    _stopStatsTimer();
    statsInterval = setInterval(async () => {
      const r = await API.request("/live-capture/status");
      if (!r || !r.ok) return;
      const s = await r.json();
      _updateLiveStats(s);
      if (!s.running) {
        _stopStatsTimer();
        _setUI("stopped");
      }
    }, 2000);
  }

  function _stopStatsTimer() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
  }

  function _updateLiveStats(s) {
    const el = (id, val) => {
      const e = document.getElementById(id);
      if (e) e.textContent = val;
    };
    el("liveStatPackets", (s.total_packets || 0).toLocaleString());
    el("liveStatDuration", _fmtDuration(s.duration_seconds || 0));
    el("liveStatThreats", s.threats_detected || 0);
    el("liveStatPPS", Math.round(s.packets_per_sec || 0));
    el("liveStatMLPred", (s.ml_predictions || 0).toLocaleString());
    el("liveStatIPs", ((s.unique_src_ips || 0) + (s.unique_dst_ips || 0)));
  }

  function _fmtDuration(sec) {
    if (!sec || sec < 0) return "0s";
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    return m ? `${m}m ${s}s` : `${s}s`;
  }

  // ── UI State ────────────────────────────────────────────────────────────
  function _setUI(state) {
    const isRunning = state === "running";
    const btnStart = document.getElementById("btnCaptureStart");
    const btnStop  = document.getElementById("btnCaptureStop");
    const status   = document.getElementById("captureStatusBadge");

    if (btnStart) btnStart.disabled = isRunning;
    if (btnStop)  btnStop.disabled  = !isRunning;
    if (status) {
      status.className = `capture-status-badge ${isRunning ? "running" : "stopped"}`;
      status.innerHTML = isRunning
        ? '<span class="capture-pulse"></span> Capturing'
        : '<i class="bi bi-stop-circle me-1"></i> Stopped';
    }
    const sel = document.getElementById("liveIfaceSelect");
    const flt = document.getElementById("liveBpfFilter");
    if (sel) sel.disabled = isRunning;
    if (flt) flt.disabled = isRunning;
  }

  // ── Export ──────────────────────────────────────────────────────────────
  window.exportLiveCapture = async function (format) {
    const token = Auth.getToken();
    if (!token) {
      _showCaptureError("Not authenticated — please log in again");
      return;
    }

    let url;
    if (format === "pcap") {
      url = `${API_BASE}/live-capture/export/pcap?limit=10000`;
    } else {
      url = `${API_BASE}/live-capture/export?format=${format}&limit=5000`;
    }

    // Show feedback
    const feedbackEl = document.getElementById("captureError");
    if (feedbackEl) {
      feedbackEl.textContent = `⏳ Preparing ${format.toUpperCase()} export...`;
      feedbackEl.style.display = "block";
      feedbackEl.style.color = "#60a5fa";
      feedbackEl.style.borderColor = "#2563eb";
    }

    try {
      const r = await fetch(url, {
        headers: { "Authorization": `Bearer ${token}` },
      });

      if (!r.ok) {
        let errMsg = `Export failed (HTTP ${r.status})`;
        try {
          const d = await r.json();
          errMsg = d.detail || errMsg;
        } catch (e) {}
        _showCaptureError(errMsg);
        return;
      }

      const blob = await r.blob();
      if (blob.size === 0) {
        _showCaptureError("No packets captured to export");
        return;
      }

      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const ext = format === "pcap" ? "pcap" : format;
      a.download = `live_capture_${ts}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);

      // Success feedback
      if (feedbackEl) {
        feedbackEl.textContent = `✅ ${format.toUpperCase()} exported successfully!`;
        feedbackEl.style.color = "#4ade80";
        feedbackEl.style.borderColor = "#16a34a";
        setTimeout(() => { feedbackEl.style.display = "none"; }, 3000);
      }
    } catch (e) {
      _showCaptureError("Export failed: " + (e.message || "Network error"));
    }
  };

  // ── Error handling ─────────────────────────────────────────────────────
  function _showCaptureError(msg) {
    const el = document.getElementById("captureError");
    if (el) {
      el.textContent = msg;
      el.style.display = "block";
      el.style.color = "#f87171";
      el.style.borderColor = "#dc2626";
    }
  }

  function _clearError() {
    const el = document.getElementById("captureError");
    if (el) el.style.display = "none";
  }

  // ── Analyze Captured Packets ──────────────────────────────────────────
  window.analyzeLiveCapture = async function () {
    _clearError();
    const btn = document.getElementById("btnAnalyze");
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analyzing...'; }

    try {
      const r = await API.request("/live-capture/analyze", { method: "POST" });
      if (!r) { _showCaptureError("Cannot connect to server"); return; }
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        _showCaptureError(d.detail || `Analysis failed (HTTP ${r.status})`);
        return;
      }

      const data = await r.json();
      _renderAnalysisResults(data);
    } catch (e) {
      _showCaptureError("Analysis failed: " + (e.message || "Unknown error"));
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-cpu-fill"></i> Analyze'; }
    }
  };

  function _renderAnalysisResults(data) {
    const panel = document.getElementById("analysisResultsPanel");
    const summary = document.getElementById("analysisResultsSummary");
    const tableDiv = document.getElementById("analysisResultsTable");
    if (!panel || !summary || !tableDiv) return;

    // Summary stats
    const threatColor = data.threats_detected > 0 ? "#ef4444" : "#4ade80";
    summary.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;">
        <div style="background:#0f172a;border-radius:8px;padding:16px;text-align:center;">
          <div style="font-size:28px;font-weight:700;color:#60a5fa;">${data.total_packets}</div>
          <div style="font-size:12px;color:#94a3b8;">Packets Analyzed</div>
        </div>
        <div style="background:#0f172a;border-radius:8px;padding:16px;text-align:center;">
          <div style="font-size:28px;font-weight:700;color:${threatColor};">${data.threats_detected}</div>
          <div style="font-size:12px;color:#94a3b8;">Threats Detected</div>
        </div>
        <div style="background:#0f172a;border-radius:8px;padding:16px;text-align:center;">
          <div style="font-size:28px;font-weight:700;color:#f59e0b;">${data.threat_rate}%</div>
          <div style="font-size:12px;color:#94a3b8;">Threat Rate</div>
        </div>
        <div style="background:#0f172a;border-radius:8px;padding:16px;text-align:center;">
          <div style="font-size:14px;font-weight:600;color:#c084fc;margin-top:6px;">${data.model_used || "N/A"}</div>
          <div style="font-size:12px;color:#94a3b8;">Model Used</div>
        </div>
      </div>
      ${Object.keys(data.attack_breakdown || {}).length > 0 ? `
        <div style="margin-top:12px;background:#0f172a;border-radius:8px;padding:12px;">
          <div style="font-weight:600;color:#e2e8f0;margin-bottom:8px;">Attack Breakdown:</div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;">
            ${Object.entries(data.attack_breakdown).sort((a,b) => b[1]-a[1]).map(([type, count]) =>
              `<span style="background:#1e293b;color:#f87171;padding:4px 10px;border-radius:4px;font-size:13px;">
                ${type}: <b>${count}</b>
              </span>`
            ).join("")}
          </div>
        </div>
      ` : ""}
    `;

    // Results table (threats only first, then normal)
    const threats = (data.packets || []).filter(p => p.is_threat);
    const normals = (data.packets || []).filter(p => !p.is_threat);
    const sorted = [...threats, ...normals].slice(0, 200);

    tableDiv.innerHTML = `
      <table class="data-table" style="width:100%;">
        <thead>
          <tr>
            <th>Source</th><th>Destination</th><th>Protocol</th>
            <th>Length</th><th>Prediction</th><th>Confidence</th><th>Threat</th>
          </tr>
        </thead>
        <tbody>
          ${sorted.map(p => `
            <tr style="background:${p.is_threat ? '#1e0101' : 'transparent'};">
              <td><code style="font-size:11px;">${p.src || "—"}</code></td>
              <td><code style="font-size:11px;">${p.dst || "—"}</code></td>
              <td><span class="live-proto-badge ${(p.protocol||"").toLowerCase()}">${p.protocol || "—"}</span></td>
              <td class="text-right">${p.length || "—"}</td>
              <td><span style="color:${p.is_threat ? '#ef4444' : '#4ade80'};font-weight:600;">${p.prediction}</span></td>
              <td>${(p.confidence * 100).toFixed(1)}%</td>
              <td>${p.is_threat ? '<span style="color:#ef4444;">⚠ YES</span>' : '<span style="color:#4ade80;">✓ No</span>'}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;

    panel.style.display = "block";
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

})();
