// js/pcap.js  —  PCAP Analysis UI Logic
// Add this script tag in dashboard.html after api.js:
//   <script src="js/pcap.js"></script>

(function () {
  let _selectedFile = null;

  // ── Drag & Drop ────────────────────────────────────────────────────────────
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
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) {
      pcapShowError(`Unsupported type: ${ext}. Allowed: .pcap .pcapng .cap`);
      return;
    }
    _selectedFile = file;
    document.getElementById("pcap-file-name").textContent = file.name;
    document.getElementById("pcap-file-size").textContent =
      "(" + (file.size / 1024).toFixed(1) + " KB)";
    document.getElementById("pcap-file-info").style.display = "flex";
    document.getElementById("pcap-analyse-btn").style.display = "inline-flex";
    document.getElementById("pcap-result-card").style.display = "none";
    const err = document.getElementById("pcap-error-banner");
    if (err) err.style.display = "none";
  };

  window.pcapClearFile = function () {
    _selectedFile = null;
    document.getElementById("pcap-file-input").value = "";
    document.getElementById("pcap-file-info").style.display = "none";
    document.getElementById("pcap-analyse-btn").style.display = "none";
  };

  // ── Upload & Analyse ───────────────────────────────────────────────────────
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
      pct = Math.min(pct + 6, 88);
      bar.style.width = pct + "%";
    }, 180);

    const res = await API.analyzePcap(_selectedFile);
    clearInterval(ticker);
    bar.style.width = "100%";

    await new Promise(r => setTimeout(r, 350));
    prog.style.display = "none";
    bar.style.width = "0%";
    btn.disabled = false;

    if (!res || !res.ok) {
      pcapShowError(res?.data?.detail || "Analysis failed. Please try again.");
      return;
    }

    pcapRenderResult(res.data);
    loadPcapHistory();
  };

  // ── Render Results ─────────────────────────────────────────────────────────
  function pcapRenderResult(payload) {
    const r     = payload.result;
    const isDup = payload.duplicate;

    document.getElementById("pcap-result-filename").textContent = r.filename;
    document.getElementById("pcap-result-sha256").textContent   = r.sha256;

    const badge = document.getElementById("pcap-result-badge");
    if (isDup) {
      badge.textContent = "♻️ Cached Result";
      badge.className   = "pcap-badge warning";
    } else {
      badge.textContent = "✅ Analysis Complete";
      badge.className   = "pcap-badge success";
    }

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

    document.getElementById("pcap-result-card").style.display = "block";
    document.getElementById("pcap-result-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ── History Table ──────────────────────────────────────────────────────────
  window.loadPcapHistory = async function () {
    const tbody = document.getElementById("pcap-history-body");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="8" class="tbl-empty">
      <div class="skeleton-row"></div>
      <div class="skeleton-row" style="width:70%"></div>
    </td></tr>`;

    const rows = await API.getPcapHistory(20);

    if (!rows || rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="tbl-empty">
        No analyses yet. Upload your first PCAP above.
      </td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map((r, i) => `
      <tr>
        <td class="td-muted">${i + 1}</td>
        <td><span style="font-weight:600;color:var(--text-main)">${r.filename}</span></td>
        <td class="td-right">${r.total_packets.toLocaleString()}</td>
        <td class="td-right">${(r.total_bytes / 1024).toFixed(1)}</td>
        <td class="td-right">${r.duration_seconds.toFixed(2)}</td>
        <td>${r.top_protocols.split(",").map(p =>
          `<span class="proto-pill">${p.trim()}</span>`).join("")}
        </td>
        <td class="td-right">${r.bytes_per_second.toFixed(1)}</td>
        <td class="td-muted">${r.created_at ? r.created_at.substring(0, 19) : "—"}</td>
      </tr>
    `).join("");
  };

  // ── Error Banner ───────────────────────────────────────────────────────────
  function pcapShowError(msg) {
    let el = document.getElementById("pcap-error-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "pcap-error-banner";
      el.className = "pcap-error-banner";
      document.getElementById("pcap-upload-card").appendChild(el);
    }
    el.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${msg}`;
    el.style.display = "flex";
    setTimeout(() => { el.style.display = "none"; }, 6000);
  }

})();
