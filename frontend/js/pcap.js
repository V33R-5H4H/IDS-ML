// js/pcap.js  —  PCAP Analysis UI Logic  (with ML risk scoring)

(function () {
  let _selectedFile = null;

  // ── Drag & Drop ─────────────────────────────────────────────────────────────
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

  window.pcapFileSelected = function (file) {
    const allowed = [".pcap", ".pcapng", ".cap"];
    const ext     = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) {
      pcapShowError(`Unsupported type: ${ext}. Allowed: .pcap .pcapng .cap`);
      return;
    }
    _selectedFile = file;
    document.getElementById("pcap-file-name").textContent = file.name;
    document.getElementById("pcap-file-size").textContent =
      "(" + (file.size / 1024).toFixed(1) + " KB)";
    document.getElementById("pcap-file-info").style.display  = "flex";
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

  // ── Upload & Analyse ─────────────────────────────────────────────────────────
  window.pcapAnalyse = async function () {
    if (!_selectedFile) return;
    const btn  = document.getElementById("pcap-analyse-btn");
    const prog = document.getElementById("pcap-progress");
    const bar  = document.getElementById("pcap-progress-bar");

    btn.disabled = true;
    prog.style.display = "block";
    document.getElementById("pcap-result-card").style.display = "none";

    // Animate progress bar
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
    loadPcapHistory();
  };

  // ── Render Full Result ───────────────────────────────────────────────────────
  function pcapRenderResult(payload) {
    const r     = payload.result;
    const isDup = payload.duplicate;

    document.getElementById("pcap-result-filename").textContent = r.filename;
    document.getElementById("pcap-result-sha256").textContent   = r.sha256;

    // Badge
    const badge = document.getElementById("pcap-result-badge");
    if (isDup) {
      badge.textContent = "♻️ Cached Result";
      badge.className   = "pcap-badge warning";
    } else {
      badge.textContent = "✅ Analysis Complete";
      badge.className   = "pcap-badge success";
    }

    // 12 stat cards
    const features = [
      { label: "Total Packets",  value: r.total_packets.toLocaleString(),           icon: "bi-box-seam",         color: "blue"   },
      { label: "Total Bytes",    value: (r.total_bytes / 1024).toFixed(1) + " KB",  icon: "bi-hdd",              color: "purple" },
      { label: "Duration",       value: r.duration_seconds.toFixed(2) + " s",       icon: "bi-stopwatch",        color: "teal"   },
      { label: "Source IPs",     value: r.unique_src_ips,                            icon: "bi-pc-display",       color: "blue"   },
      { label: "Dest IPs",       value: r.unique_dst_ips,                            icon: "bi-bullseye",         color: "yellow" },
      { label: "Protocols",      value: r.top_protocols || "—",                      icon: "bi-diagram-3",        color: "purple" },
      { label: "Avg Pkt Size",   value: r.avg_packet_size.toFixed(1) + " B",        icon: "bi-rulers",           color: "teal"   },
      { label: "Max Pkt Size",   value: r.max_packet_size.toLocaleString() + " B",  icon: "bi-graph-up-arrow",   color: "yellow" },
      { label: "TCP Packets",    value: r.tcp_packets.toLocaleString(),              icon: "bi-arrow-left-right", color: "blue"   },
      { label: "UDP Packets",    value: r.udp_packets.toLocaleString(),              icon: "bi-broadcast",        color: "yellow" },
      { label: "ICMP Packets",   value: r.icmp_packets.toLocaleString(),             icon: "bi-lightning-charge", color: "red"    },
      { label: "Bytes / Second", value: r.bytes_per_second.toFixed(1),              icon: "bi-speedometer2",     color: "green"  },
    ];

    document.getElementById("pcap-features-grid").innerHTML = features.map(f => `
      <div class="stat-card ${f.color}">
        <div class="stat-icon"><i class="bi ${f.icon}"></i></div>
        <div class="stat-value">${f.value}</div>
        <div class="stat-label">${f.label}</div>
      </div>
    `).join("");

    // ── Risk Score Block ───────────────────────────────────────────────────────
    const resultBody = document.querySelector("#pcap-result-card [style*='padding:20px']");
    const oldRisk    = document.getElementById("pcap-risk-block");
    if (oldRisk) oldRisk.remove();

    if (r.risk_score !== undefined && r.risk_score !== null) {
      const riskColors = {
        Critical: { bar: "#ef4444", text: "#fca5a5", bg: "rgba(239,68,68,0.12)",  border: "rgba(239,68,68,0.35)"  },
        High:     { bar: "#f59e0b", text: "#fcd34d", bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.35)" },
        Medium:   { bar: "#3b82f6", text: "#93c5fd", bg: "rgba(59,130,246,0.12)", border: "rgba(59,130,246,0.35)" },
        Low:      { bar: "#22c55e", text: "#86efac", bg: "rgba(34,197,94,0.12)",  border: "rgba(34,197,94,0.35)"  },
      };
      const c   = riskColors[r.risk_label] || riskColors.Low;
      const pct = Math.round(r.risk_score * 100);

      const riskEl  = document.createElement("div");
      riskEl.id     = "pcap-risk-block";
      riskEl.style.cssText = `
        margin-top:14px;
        padding:14px 16px;
        border-radius:var(--radius);
        background:${c.bg};
        border:1px solid ${c.border};
      `;
      riskEl.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
          <span style="font-size:0.75rem;font-weight:700;text-transform:uppercase;
                       letter-spacing:0.5px;color:${c.text};">
            <i class="bi bi-shield-exclamation" style="margin-right:5px;"></i>Risk Assessment
          </span>
          <span style="font-size:0.78rem;font-weight:700;padding:4px 12px;border-radius:20px;
                       background:${c.bg};border:1px solid ${c.border};color:${c.text};">
            ${r.risk_label} &nbsp;·&nbsp; ${pct}%
          </span>
        </div>
        <div style="height:6px;background:var(--bg-card2);border-radius:10px;overflow:hidden;">
          <div id="pcap-risk-bar"
               style="height:100%;width:0%;background:${c.bar};
                      border-radius:10px;transition:width 0.7s ease;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:6px;">
          <span style="font-size:0.72rem;color:var(--text-muted);">
            Model: <span style="color:${c.text};font-weight:600;">
              ${r.model_used || "heuristic"}
            </span>
          </span>
          <span style="font-size:0.72rem;color:${c.text};font-weight:600;">${pct} / 100</span>
        </div>
      `;
      resultBody.appendChild(riskEl);

      // Animate bar after paint
      setTimeout(() => {
        const b = document.getElementById("pcap-risk-bar");
        if (b) b.style.width = pct + "%";
      }, 80);
    }

    // ── SHA-256 row (always last) ──────────────────────────────────────────────
    const oldSha = document.getElementById("pcap-sha-block");
    if (oldSha) oldSha.remove();

    const shaEl  = document.createElement("div");
    shaEl.id     = "pcap-sha-block";
    shaEl.style.cssText = `
      background:var(--bg-dark);
      border:1px solid var(--border);
      border-radius:var(--radius);
      padding:10px 14px;
      margin-top:14px;
    `;
    shaEl.innerHTML = `
      <span style="color:var(--text-muted);font-size:0.75rem;font-weight:700;
                   text-transform:uppercase;letter-spacing:0.5px;">SHA-256</span>
      <div style="color:var(--text-muted);font-size:0.75rem;margin-top:4px;
                  word-break:break-all;font-family:monospace;">${r.sha256}</div>
    `;
    resultBody.appendChild(shaEl);

    // Show card and scroll to it
    document.getElementById("pcap-result-card").style.display = "block";
    document.getElementById("pcap-result-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ── History Table ────────────────────────────────────────────────────────────
  window.loadPcapHistory = async function () {
    const tbody = document.getElementById("pcap-history-body");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="9" class="tbl-empty">
      <div class="skeleton-row"></div>
      <div class="skeleton-row" style="width:65%"></div>
    </td></tr>`;

    const rows = await API.getPcapHistory(20);

    if (!rows || rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="tbl-empty">
        No analyses yet — upload your first PCAP above.
      </td></tr>`;
      return;
    }

    const riskColors = {
      Critical: "color:#fca5a5;",
      High:     "color:#fcd34d;",
      Medium:   "color:#93c5fd;",
      Low:      "color:#86efac;",
    };

    tbody.innerHTML = rows.map((r, i) => {
      const riskStyle = riskColors[r.risk_label] || "color:var(--text-muted);";
      const pct       = r.risk_score !== undefined
        ? Math.round(r.risk_score * 100) + "%"
        : "—";
      return `
        <tr>
          <td class="td-muted">${i + 1}</td>
          <td><span style="font-weight:600;color:var(--text-main);">${r.filename}</span></td>
          <td class="td-right">${r.total_packets.toLocaleString()}</td>
          <td class="td-right">${(r.total_bytes / 1024).toFixed(1)}</td>
          <td class="td-right">${r.duration_seconds.toFixed(2)}</td>
          <td>${r.top_protocols.split(",").map(p =>
            `<span class="proto-pill">${p.trim()}</span>`).join("")}
          </td>
          <td class="td-right">${r.bytes_per_second.toFixed(1)}</td>
          <td style="font-weight:700;${riskStyle}">${r.risk_label || "—"} (${pct})</td>
          <td class="td-muted">${r.created_at ? r.created_at.substring(0, 16) : "—"}</td>
        </tr>
      `;
    }).join("");
  };

  // ── Error Banner ─────────────────────────────────────────────────────────────
  function pcapShowError(msg) {
    let el = document.getElementById("pcap-error-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "pcap-error-banner";
      el.className = "pcap-error-banner";
      document.getElementById("pcap-upload-card")
        .querySelector("[style*='padding:20px']")
        .appendChild(el);
    }
    el.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${msg}`;
    el.style.display = "flex";
    setTimeout(() => { el.style.display = "none"; }, 6000);
  }

})();
// js/pcap.js  —  PCAP Analysis UI Logic  (with ML risk scoring)

(function () {
  let _selectedFile = null;

  // ── Drag & Drop ─────────────────────────────────────────────────────────────
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

  window.pcapFileSelected = function (file) {
    const allowed = [".pcap", ".pcapng", ".cap"];
    const ext     = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) {
      pcapShowError(`Unsupported type: ${ext}. Allowed: .pcap .pcapng .cap`);
      return;
    }
    _selectedFile = file;
    document.getElementById("pcap-file-name").textContent = file.name;
    document.getElementById("pcap-file-size").textContent =
      "(" + (file.size / 1024).toFixed(1) + " KB)";
    document.getElementById("pcap-file-info").style.display  = "flex";
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

  // ── Upload & Analyse ─────────────────────────────────────────────────────────
  window.pcapAnalyse = async function () {
    if (!_selectedFile) return;
    const btn  = document.getElementById("pcap-analyse-btn");
    const prog = document.getElementById("pcap-progress");
    const bar  = document.getElementById("pcap-progress-bar");

    btn.disabled = true;
    prog.style.display = "block";
    document.getElementById("pcap-result-card").style.display = "none";

    // Animate progress bar
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
    loadPcapHistory();
  };

  // ── Render Full Result ───────────────────────────────────────────────────────
  function pcapRenderResult(payload) {
    const r     = payload.result;
    const isDup = payload.duplicate;

    document.getElementById("pcap-result-filename").textContent = r.filename;
    document.getElementById("pcap-result-sha256").textContent   = r.sha256;

    // Badge
    const badge = document.getElementById("pcap-result-badge");
    if (isDup) {
      badge.textContent = "♻️ Cached Result";
      badge.className   = "pcap-badge warning";
    } else {
      badge.textContent = "✅ Analysis Complete";
      badge.className   = "pcap-badge success";
    }

    // 12 stat cards
    const features = [
      { label: "Total Packets",  value: r.total_packets.toLocaleString(),           icon: "bi-box-seam",         color: "blue"   },
      { label: "Total Bytes",    value: (r.total_bytes / 1024).toFixed(1) + " KB",  icon: "bi-hdd",              color: "purple" },
      { label: "Duration",       value: r.duration_seconds.toFixed(2) + " s",       icon: "bi-stopwatch",        color: "teal"   },
      { label: "Source IPs",     value: r.unique_src_ips,                            icon: "bi-pc-display",       color: "blue"   },
      { label: "Dest IPs",       value: r.unique_dst_ips,                            icon: "bi-bullseye",         color: "yellow" },
      { label: "Protocols",      value: r.top_protocols || "—",                      icon: "bi-diagram-3",        color: "purple" },
      { label: "Avg Pkt Size",   value: r.avg_packet_size.toFixed(1) + " B",        icon: "bi-rulers",           color: "teal"   },
      { label: "Max Pkt Size",   value: r.max_packet_size.toLocaleString() + " B",  icon: "bi-graph-up-arrow",   color: "yellow" },
      { label: "TCP Packets",    value: r.tcp_packets.toLocaleString(),              icon: "bi-arrow-left-right", color: "blue"   },
      { label: "UDP Packets",    value: r.udp_packets.toLocaleString(),              icon: "bi-broadcast",        color: "yellow" },
      { label: "ICMP Packets",   value: r.icmp_packets.toLocaleString(),             icon: "bi-lightning-charge", color: "red"    },
      { label: "Bytes / Second", value: r.bytes_per_second.toFixed(1),              icon: "bi-speedometer2",     color: "green"  },
    ];

    document.getElementById("pcap-features-grid").innerHTML = features.map(f => `
      <div class="stat-card ${f.color}">
        <div class="stat-icon"><i class="bi ${f.icon}"></i></div>
        <div class="stat-value">${f.value}</div>
        <div class="stat-label">${f.label}</div>
      </div>
    `).join("");

    // ── Risk Score Block ───────────────────────────────────────────────────────
    const resultBody = document.querySelector("#pcap-result-card [style*='padding:20px']");
    const oldRisk    = document.getElementById("pcap-risk-block");
    if (oldRisk) oldRisk.remove();

    if (r.risk_score !== undefined && r.risk_score !== null) {
      const riskColors = {
        Critical: { bar: "#ef4444", text: "#fca5a5", bg: "rgba(239,68,68,0.12)",  border: "rgba(239,68,68,0.35)"  },
        High:     { bar: "#f59e0b", text: "#fcd34d", bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.35)" },
        Medium:   { bar: "#3b82f6", text: "#93c5fd", bg: "rgba(59,130,246,0.12)", border: "rgba(59,130,246,0.35)" },
        Low:      { bar: "#22c55e", text: "#86efac", bg: "rgba(34,197,94,0.12)",  border: "rgba(34,197,94,0.35)"  },
      };
      const c   = riskColors[r.risk_label] || riskColors.Low;
      const pct = Math.round(r.risk_score * 100);

      const riskEl  = document.createElement("div");
      riskEl.id     = "pcap-risk-block";
      riskEl.style.cssText = `
        margin-top:14px;
        padding:14px 16px;
        border-radius:var(--radius);
        background:${c.bg};
        border:1px solid ${c.border};
      `;
      riskEl.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
          <span style="font-size:0.75rem;font-weight:700;text-transform:uppercase;
                       letter-spacing:0.5px;color:${c.text};">
            <i class="bi bi-shield-exclamation" style="margin-right:5px;"></i>Risk Assessment
          </span>
          <span style="font-size:0.78rem;font-weight:700;padding:4px 12px;border-radius:20px;
                       background:${c.bg};border:1px solid ${c.border};color:${c.text};">
            ${r.risk_label} &nbsp;·&nbsp; ${pct}%
          </span>
        </div>
        <div style="height:6px;background:var(--bg-card2);border-radius:10px;overflow:hidden;">
          <div id="pcap-risk-bar"
               style="height:100%;width:0%;background:${c.bar};
                      border-radius:10px;transition:width 0.7s ease;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:6px;">
          <span style="font-size:0.72rem;color:var(--text-muted);">
            Model: <span style="color:${c.text};font-weight:600;">
              ${r.model_used || "heuristic"}
            </span>
          </span>
          <span style="font-size:0.72rem;color:${c.text};font-weight:600;">${pct} / 100</span>
        </div>
      `;
      resultBody.appendChild(riskEl);

      // Animate bar after paint
      setTimeout(() => {
        const b = document.getElementById("pcap-risk-bar");
        if (b) b.style.width = pct + "%";
      }, 80);
    }

    // ── SHA-256 row (always last) ──────────────────────────────────────────────
    const oldSha = document.getElementById("pcap-sha-block");
    if (oldSha) oldSha.remove();

    const shaEl  = document.createElement("div");
    shaEl.id     = "pcap-sha-block";
    shaEl.style.cssText = `
      background:var(--bg-dark);
      border:1px solid var(--border);
      border-radius:var(--radius);
      padding:10px 14px;
      margin-top:14px;
    `;
    shaEl.innerHTML = `
      <span style="color:var(--text-muted);font-size:0.75rem;font-weight:700;
                   text-transform:uppercase;letter-spacing:0.5px;">SHA-256</span>
      <div style="color:var(--text-muted);font-size:0.75rem;margin-top:4px;
                  word-break:break-all;font-family:monospace;">${r.sha256}</div>
    `;
    resultBody.appendChild(shaEl);

    // Show card and scroll to it
    document.getElementById("pcap-result-card").style.display = "block";
    document.getElementById("pcap-result-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ── History Table ────────────────────────────────────────────────────────────
  window.loadPcapHistory = async function () {
    const tbody = document.getElementById("pcap-history-body");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="9" class="tbl-empty">
      <div class="skeleton-row"></div>
      <div class="skeleton-row" style="width:65%"></div>
    </td></tr>`;

    const rows = await API.getPcapHistory(20);

    if (!rows || rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="tbl-empty">
        No analyses yet — upload your first PCAP above.
      </td></tr>`;
      return;
    }

    const riskColors = {
      Critical: "color:#fca5a5;",
      High:     "color:#fcd34d;",
      Medium:   "color:#93c5fd;",
      Low:      "color:#86efac;",
    };

    tbody.innerHTML = rows.map((r, i) => {
      const riskStyle = riskColors[r.risk_label] || "color:var(--text-muted);";
      const pct       = r.risk_score !== undefined
        ? Math.round(r.risk_score * 100) + "%"
        : "—";
      return `
        <tr>
          <td class="td-muted">${i + 1}</td>
          <td><span style="font-weight:600;color:var(--text-main);">${r.filename}</span></td>
          <td class="td-right">${r.total_packets.toLocaleString()}</td>
          <td class="td-right">${(r.total_bytes / 1024).toFixed(1)}</td>
          <td class="td-right">${r.duration_seconds.toFixed(2)}</td>
          <td>${r.top_protocols.split(",").map(p =>
            `<span class="proto-pill">${p.trim()}</span>`).join("")}
          </td>
          <td class="td-right">${r.bytes_per_second.toFixed(1)}</td>
          <td style="font-weight:700;${riskStyle}">${r.risk_label || "—"} (${pct})</td>
          <td class="td-muted">${r.created_at ? r.created_at.substring(0, 16) : "—"}</td>
        </tr>
      `;
    }).join("");
  };

  // ── Error Banner ─────────────────────────────────────────────────────────────
  function pcapShowError(msg) {
    let el = document.getElementById("pcap-error-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "pcap-error-banner";
      el.className = "pcap-error-banner";
      document.getElementById("pcap-upload-card")
        .querySelector("[style*='padding:20px']")
        .appendChild(el);
    }
    el.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${msg}`;
    el.style.display = "flex";
    setTimeout(() => { el.style.display = "none"; }, 6000);
  }

})();
