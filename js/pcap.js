// js/pcap.js  —  PCAP Analysis UI Logic  (ML risk scoring + attack type)

(function () {
  "use strict";

  let _selectedFile = null;

  const RISK_COLORS = {
    Critical: {
      bar: "#ef4444", text: "#fca5a5",
      bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.35)"
    },
    High: {
      bar: "#f59e0b", text: "#fcd34d",
      bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.35)"
    },
    Medium: {
      bar: "#3b82f6", text: "#93c5fd",
      bg: "rgba(59,130,246,0.12)", border: "rgba(59,130,246,0.35)"
    },
    Low: {
      bar: "#22c55e", text: "#86efac",
      bg: "rgba(34,197,94,0.12)", border: "rgba(34,197,94,0.35)"
    },
  };

  const HISTORY_RISK_STYLE = {
    Critical: "color:#fca5a5;",
    High:     "color:#fcd34d;",
    Medium:   "color:#93c5fd;",
    Low:      "color:#86efac;",
  };

  // ══════════════════════════════════════════════════════════════════════════
  // DRAG & DROP
  // ══════════════════════════════════════════════════════════════════════════
  window.pcapDragOver = function (e) {
    e.preventDefault();
    document.getElementById("pcap-dropzone").classList.add("dragover");
  };

  window.pcapDragLeave = function () {
    document.getElementById("pcap-dropzone").classList.remove("dragover");
  };

  window.pcapDrop = function (e) {
    e.preventDefault();
    pcapDragLeave();
    if (e.dataTransfer.files[0]) pcapFileSelected(e.dataTransfer.files[0]);
  };

  // ══════════════════════════════════════════════════════════════════════════
  // FILE SELECTION
  // ══════════════════════════════════════════════════════════════════════════
  window.pcapFileSelected = function (file) {
    const allowed = [".pcap", ".pcapng", ".cap"];
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) {
      pcapShowError(`Unsupported type: ${ext}. Allowed: .pcap  .pcapng  .cap`);
      return;
    }
    _selectedFile = file;
    document.getElementById("pcap-file-name").textContent  = file.name;
    document.getElementById("pcap-file-size").textContent  = "(" + (file.size / 1024).toFixed(1) + " KB)";
    document.getElementById("pcap-file-info").style.display   = "flex";
    document.getElementById("pcap-analyse-btn").style.display = "inline-flex";
    document.getElementById("pcap-result-card").style.display = "none";
    const err = document.getElementById("pcap-error-banner");
    if (err) err.style.display = "none";
  };

  window.pcapClearFile = function () {
    _selectedFile = null;
    document.getElementById("pcap-file-input").value          = "";
    document.getElementById("pcap-file-info").style.display   = "none";
    document.getElementById("pcap-analyse-btn").style.display = "none";
  };

  // ══════════════════════════════════════════════════════════════════════════
  // UPLOAD & ANALYSE
  // ══════════════════════════════════════════════════════════════════════════
  window.pcapAnalyse = async function () {
    if (!_selectedFile) return;

    const btn  = document.getElementById("pcap-analyse-btn");
    const prog = document.getElementById("pcap-progress");
    const bar  = document.getElementById("pcap-progress-bar");

    btn.disabled = true;
    prog.style.display = "block";
    document.getElementById("pcap-result-card").style.display = "none";

    let pct = 0;
    const ticker = setInterval(() => {
      pct = Math.min(pct + 5, 88);
      bar.style.width = pct + "%";
    }, 150);

    const res = await API.analyzePcap(_selectedFile);

    clearInterval(ticker);
    bar.style.width = "100%";
    await new Promise(r => setTimeout(r, 300));
    prog.style.display = "none";
    bar.style.width    = "0%";
    btn.disabled       = false;

    if (!res || !res.ok) {
      pcapShowError(res?.data?.detail || "Analysis failed. Please try again.");
      return;
    }

    pcapRenderResult(res.data);
    loadPcapHistory(res.data?.result?.id ?? null);
  };

  // ══════════════════════════════════════════════════════════════════════════
  // RENDER RESULT CARD
  // ══════════════════════════════════════════════════════════════════════════
  function pcapRenderResult(payload) {
  try {
    const r     = payload.result;
    const isDup = payload.duplicate;

    const safeStr = v  => (v != null ? String(v) : "—");
    const safeFix = (v, d) => (v != null ? Number(v).toFixed(d) : "—");
    const safeLoc = v  => (v != null ? Number(v).toLocaleString() : "—");

    const features = [
      { label:"Total Packets",  value:safeLoc(r.total_packets),                                            icon:"bi-box-seam",         color:"blue"   },
      { label:"Total Bytes",    value:safeFix(r.total_bytes != null ? r.total_bytes/1024 : null, 1)+" KB", icon:"bi-hdd",              color:"purple" },
      { label:"Duration",       value:safeFix(r.duration_seconds, 2)+" s",                                 icon:"bi-stopwatch",        color:"teal"   },
      { label:"Source IPs",     value:safeStr(r.unique_src_ips),                                            icon:"bi-pc-display",       color:"blue"   },
      { label:"Dest IPs",       value:safeStr(r.unique_dst_ips),                                            icon:"bi-bullseye",         color:"yellow" },
      { label:"Protocols",      value:r.top_protocols || "—",                                               icon:"bi-diagram-3",        color:"purple" },
      { label:"Avg Pkt Size",   value:safeFix(r.avg_packet_size, 1)+" B",                                  icon:"bi-rulers",           color:"teal"   },
      { label:"Max Pkt Size",   value:safeLoc(r.max_packet_size)+" B",                                     icon:"bi-graph-up-arrow",   color:"yellow" },
      { label:"TCP Packets",    value:safeLoc(r.tcp_packets),                                               icon:"bi-arrow-left-right", color:"blue"   },
      { label:"UDP Packets",    value:safeLoc(r.udp_packets),                                               icon:"bi-broadcast",        color:"yellow" },
      { label:"ICMP Packets",   value:safeLoc(r.icmp_packets),                                              icon:"bi-lightning-charge", color:"red"    },
      { label:"Bytes / Second", value:safeFix(r.bytes_per_second, 1),                                      icon:"bi-speedometer2",     color:"green"  },
    ];

    const labelColors = { Critical:"#fca5a5", High:"#fcd34d", Medium:"#93c5fd", Low:"#86efac" };
    const lbl   = r.risk_label  || "Unknown";
    const score = r.risk_score  != null ? (r.risk_score * 100).toFixed(1) + "%" : "—";
    const atk   = r.attack_type || "—";
    const mdl   = r.model_used  || "Heuristic";
    const clr   = labelColors[lbl] || "#94a3b8";

    const card = document.getElementById("pcap-result-card");
    if (!card) { pcapShowError("Result container missing from page — check dashboard.html."); return; }

    card.innerHTML = `
      <div class="pcap-result-header">
        <div class="pcap-result-title">
          <i class="bi bi-file-earmark-binary-fill me-2" style="color:var(--accent-blue);"></i>
          <span id="pcap-result-filename" style="font-weight:700;color:var(--text-white);">
            ${safeStr(r.filename)}
          </span>
        </div>
        <span id="pcap-result-badge" class="pcap-badge ${isDup ? "warning" : "success"}">
          ${isDup ? "♻️ Cached Result" : "✅ Analysis Complete"}
        </span>
      </div>
      <div style="font-size:.71rem;color:var(--text-muted);margin-bottom:16px;
                  word-break:break-all;font-family:monospace;">
        SHA256: ${safeStr(r.sha256)}
      </div>

      <!-- Risk card -->
      <div class="pcap-risk-card" style="border-left:4px solid ${clr};margin-bottom:20px;">
        <div class="pcap-risk-header">
          <i class="bi bi-shield-fill" style="color:${clr};font-size:1.3rem;"></i>
          <div>
            <div class="pcap-risk-label" style="color:${clr};">${lbl}</div>
            <div class="pcap-risk-sub">ML Risk Classification</div>
          </div>
          <div class="ms-auto text-end">
            <div style="font-size:1.4rem;font-weight:700;color:${clr};">${score}</div>
            <div style="font-size:.68rem;color:var(--text-muted);">Risk Score</div>
          </div>
        </div>
        <div class="pcap-risk-meta">
          <div class="pcap-risk-meta-item"><span>Attack Type</span><strong style="color:${clr};">${atk}</strong></div>
          <div class="pcap-risk-meta-item"><span>Model</span><strong>${mdl}</strong></div>
          <div class="pcap-risk-meta-item"><span>First Seen</span>
            <strong>${r.first_seen ? r.first_seen.substring(0,19).replace("T"," ") : "—"}</strong></div>
          <div class="pcap-risk-meta-item"><span>Last Seen</span>
            <strong>${r.last_seen ? r.last_seen.substring(0,19).replace("T"," ") : "—"}</strong></div>
        </div>
      </div>

      <!-- 12 feature cards -->
      <div class="pcap-features-grid">
        ${features.map(f => `
          <div class="pcap-feat-card ${f.color}">
            <div class="pcap-feat-icon"><i class="bi ${f.icon}"></i></div>
            <div class="pcap-feat-val">${f.value}</div>
            <div class="pcap-feat-label">${f.label}</div>
          </div>`).join("")}
      </div>`;

    card.style.display = "block";
    setTimeout(() => card.scrollIntoView({ behavior: "smooth", block: "start" }), 80);

  } catch (err) {
    console.error("[PCAP] render error:", err);
    pcapShowError("Could not render result: " + err.message);
  }
}



  // ── History Table ─────────────────────────────────────────────────────────
  window.loadPcapHistory = async function (highlightId = null) {
  const tbody = document.getElementById("pcap-history-body");
  if (!tbody) return;

  const rows = await API.getPcapHistory(50);
  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="tbl-empty">
      No analyses yet — upload a PCAP file above to get started.</td></tr>`;
    return;
  }

  const C = { Critical:"#fca5a5", High:"#fcd34d", Medium:"#93c5fd", Low:"#86efac" };
  tbody.innerHTML = rows.map(r => {
    const isNew = highlightId && r.id === highlightId;
    return `<tr class="${isNew ? "row-highlight" : ""}">
      <td style="color:var(--text-muted);font-size:.75rem;">#${r.id}</td>
      <td style="font-weight:600;max-width:160px;overflow:hidden;text-overflow:ellipsis;
                 white-space:nowrap;color:var(--text-main);" title="${r.filename}">${r.filename}</td>
      <td class="tbl-right">${(r.total_packets   || 0).toLocaleString()}</td>
      <td class="tbl-right">${((r.file_size      || 0)/1024).toFixed(1)}</td>
      <td class="tbl-right">${(r.duration_seconds|| 0).toFixed(2)}</td>
      <td style="color:var(--text-muted);font-size:.75rem;">${r.top_protocols || "—"}</td>
      <td class="tbl-right">${(r.bytes_per_second|| 0).toFixed(1)}</td>
      <td><span style="font-weight:700;font-size:.78rem;
                       color:${C[r.risk_label]||"var(--text-muted)"};">${r.risk_label||"—"}</span></td>
      <td style="color:var(--text-muted);font-size:.75rem;">${r.attack_type||"—"}</td>
      <td style="color:var(--text-muted);font-size:.73rem;">
        ${r.created_at ? r.created_at.substring(0,16).replace("T"," ") : "—"}</td>
    </tr>`;
  }).join("");

  if (highlightId) {
    setTimeout(() => {
      tbody.querySelector(".row-highlight")?.classList.remove("row-highlight");
    }, 2500);
  }
};



  // ══════════════════════════════════════════════════════════════════════════
  // ERROR BANNER
  // ══════════════════════════════════════════════════════════════════════════
  function pcapShowError(msg) {
    let el = document.getElementById("pcap-error-banner");
    if (!el) {
      el = document.createElement("div");
      el.id        = "pcap-error-banner";
      el.className = "pcap-error-banner";
      const card   = document.getElementById("pcap-upload-card");
      if (card) card.appendChild(el);
    }
    el.innerHTML     = `<i class="bi bi-exclamation-triangle-fill"></i> ${msg}`;
    el.style.display = "flex";
    setTimeout(() => { el.style.display = "none"; }, 6000);
  }

})();
