// frontend/js/live_capture.js — Live capture UI logic + WebSocket client

(function () {
  "use strict";

  let ws = null;
  let packetCount = 0;
  let startTime = null;
  let statsInterval = null;
  const MAX_ROWS = 500;

  // ── Initialisation ──────────────────────────────────────────────────────
  window.initLiveCapture = async function () {
    packetCount = 0;
    startTime = null;
    _updateLiveStats(0, 0, 0, 0);
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
      _updateLiveStats(s.total_packets || packetCount,
        s.duration_seconds || 0, s.threats_detected || 0, 0);
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
        if (pkt.type === "ping") return;  // keepalive
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

    const time = new Date(pkt.timestamp).toLocaleTimeString("en-IN", {
      hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
      fractionalSecondDigits: 3,
    });

    tr.innerHTML = `
      <td class="live-feed-time">${time}</td>
      <td>${pkt.src || "—"}</td>
      <td>${pkt.dst || "—"}</td>
      <td><span class="live-proto-badge ${pkt.protocol?.toLowerCase() || ""}">${pkt.protocol || "—"}</span></td>
      <td class="text-right">${pkt.length ?? "—"}</td>
      <td>${pkt.info || ""}</td>
      <td><span class="live-risk-badge ${pkt.risk || "low"}">${(pkt.risk || "low").toUpperCase()}</span></td>
    `;

    tbody.appendChild(tr);

    // Circular buffer — remove oldest rows
    while (tbody.children.length > MAX_ROWS) {
      tbody.removeChild(tbody.firstChild);
    }

    // Auto-scroll
    const feed = document.getElementById("liveFeedWrap");
    if (feed) feed.scrollTop = feed.scrollHeight;
  }

  function _clearFeed() {
    const tbody = document.getElementById("liveFeedBody");
    if (tbody) tbody.innerHTML = "";
    packetCount = 0;
  }

  // ── Stats Timer ─────────────────────────────────────────────────────────
  function _startStatsTimer() {
    _stopStatsTimer();
    statsInterval = setInterval(async () => {
      const r = await API.request("/live-capture/status");
      if (!r || !r.ok) return;
      const s = await r.json();
      _updateLiveStats(s.total_packets, s.duration_seconds,
        s.threats_detected, s.packets_per_sec);
      if (!s.running) {
        _stopStatsTimer();
        _setUI("stopped");
      }
    }, 2000);
  }

  function _stopStatsTimer() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
  }

  function _updateLiveStats(packets, duration, threats, pps) {
    const el = (id, val) => {
      const e = document.getElementById(id);
      if (e) e.textContent = val;
    };
    el("liveStatPackets", packets.toLocaleString());
    el("liveStatDuration", _fmtDuration(duration));
    el("liveStatThreats", threats);
    el("liveStatPPS", Math.round(pps));
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
    const controls = document.getElementById("captureControls");

    if (btnStart) btnStart.disabled = isRunning;
    if (btnStop)  btnStop.disabled  = !isRunning;
    if (status) {
      status.className = `capture-status-badge ${isRunning ? "running" : "stopped"}`;
      status.innerHTML = isRunning
        ? '<span class="capture-pulse"></span> Capturing'
        : '<i class="bi bi-stop-circle me-1"></i> Stopped';
    }
    // Disable interface/filter while running
    const sel = document.getElementById("liveIfaceSelect");
    const flt = document.getElementById("liveBpfFilter");
    if (sel) sel.disabled = isRunning;
    if (flt) flt.disabled = isRunning;
  }

  // ── Export ──────────────────────────────────────────────────────────────
  window.exportLiveCapture = async function (format) {
    const token = Auth.getToken();
    if (!token) return;
    const url = `${API_BASE}/live-capture/export?format=${format}&limit=5000`;
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        _showCaptureError(d.detail || "Export failed");
        return;
      }
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `live_capture.${format}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      _showCaptureError("Export failed: " + e.message);
    }
  };

  // ── Error handling ─────────────────────────────────────────────────────
  function _showCaptureError(msg) {
    const el = document.getElementById("captureError");
    if (el) { el.textContent = msg; el.style.display = "block"; }
  }

  function _clearError() {
    const el = document.getElementById("captureError");
    if (el) el.style.display = "none";
  }

})();
