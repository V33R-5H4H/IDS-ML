// frontend/js/analytics.js — Advanced Analytics Logic
(function () {
  "use strict";

  let charts = {};

  window.loadAdvancedAnalytics = async function () {
    const hours = document.getElementById("analyticsHours")?.value || 24;

    try {
      const resp = await API.request(`/analytics/advanced?hours=${hours}`);
      if (!resp?.ok) return;

      const data = await resp.json();
      
      // Update Stats
      _updateAnalyticsStats(data);

      // Render Charts
      _renderAttackDistChart(data.attack_distribution);
      _renderDetectionTrendChart(data.detection_trends);
      _renderTopTalkersChart(data.top_talkers);
      _renderProtocolChart(data.protocol_breakdown);
      
      // Render Source Comparison
      _renderSourceComparison(data.source_comparison);

    } catch (e) {
      console.error("Failed to load advanced analytics:", e);
    }
  };

  function _updateAnalyticsStats(data) {
    const dist = data.attack_distribution || {};
    const perf = data.model_performance || {};
    
    const el = (id, val) => {
      const e = document.getElementById(id);
      if (e) e.textContent = val;
    };

    el("analyticsTotalPreds", (dist.total_predictions || 0).toLocaleString());
    el("analyticsTotalAttacks", (dist.total_attacks || 0).toLocaleString());
    el("analyticsAttackRate", (dist.attack_rate || 0) + "%");
    el("analyticsAvgConf", ((perf.avg_confidence || 0) * 100).toFixed(1) + "%");
  }

  function _destroyChart(name) {
    if (charts[name]) {
      charts[name].destroy();
      delete charts[name];
    }
  }

  function _renderAttackDistChart(data) {
    _destroyChart("attackDist");
    const ctx = document.getElementById("attackDistChart");
    if (!ctx || !data || !data.distribution) return;

    const labels = Object.keys(data.distribution);
    const values = Object.values(data.distribution);

    if (labels.length === 0) {
      // Empty state
      return;
    }

    const colors = labels.map(l => l === "normal" ? "#4ade80" : "#ef4444");

    charts["attackDist"] = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: 'var(--text-secondary)' } } }
      }
    });
  }

  function _renderDetectionTrendChart(data) {
    _destroyChart("detectionTrend");
    const ctx = document.getElementById("detectionTrendChart");
    if (!ctx || !data || !data.labels) return;

    if (data.labels.length === 0) return;

    charts["detectionTrend"] = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.labels.map(l => new Date(l).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})),
        datasets: [
          {
            label: "Attacks",
            data: data.attacks,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            fill: true,
            tension: 0.4
          },
          {
            label: "Normal",
            data: data.normal,
            borderColor: "#4ade80",
            backgroundColor: "rgba(74, 222, 128, 0.1)",
            fill: true,
            tension: 0.4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'var(--border-color)' } },
          y: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'var(--border-color)' } }
        },
        plugins: { legend: { labels: { color: 'var(--text-secondary)' } } }
      }
    });
  }

  function _renderTopTalkersChart(data) {
    _destroyChart("topTalkers");
    const ctx = document.getElementById("topTalkersChart");
    if (!ctx || !data || !data.top_attack_sources) return;

    const sources = Object.keys(data.top_attack_sources).slice(0, 10);
    const counts = Object.values(data.top_attack_sources).slice(0, 10);

    if (sources.length === 0) return;

    charts["topTalkers"] = new Chart(ctx, {
      type: "bar",
      data: {
        labels: sources,
        datasets: [{
          label: "Attacks originating from IP",
          data: counts,
          backgroundColor: "rgba(239, 68, 68, 0.8)",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        scales: {
          x: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'var(--border-color)' } },
          y: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'transparent' } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  function _renderProtocolChart(data) {
    _destroyChart("protocolChart");
    const ctx = document.getElementById("protocolChart");
    if (!ctx || !data) return;

    const labels = Object.keys(data);
    const values = Object.values(data);

    if (labels.length === 0) return;

    charts["protocolChart"] = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Packets",
          data: values,
          backgroundColor: "#3b82f6",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'transparent' } },
          y: { ticks: { color: 'var(--text-muted)' }, grid: { color: 'var(--border-color)' }, beginAtZero: true }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  function _renderSourceComparison(data) {
    const container = document.getElementById("sourceComparisonContent");
    if (!container || !data) return;

    const pcap = data.pcap || { total: 0, attacks: 0, attack_rate: 0 };
    const live = data.live || { total: 0, attacks: 0, attack_rate: 0 };

    if (pcap.total === 0 && live.total === 0) {
      container.innerHTML = `<p style="text-align:center;color:var(--text-muted);padding-top:40px;">No comparison data yet (requires both PCAP and Live analyses)</p>`;
      return;
    }

    container.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;text-align:center;">
        <div style="background:var(--bg-elevated);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <h4 style="color:var(--text-secondary);margin-bottom:12px;"><i class="bi bi-file-earmark-binary me-2"></i>PCAP Analysis</h4>
          <div style="font-size:24px;font-weight:700;color:var(--text-primary);">${pcap.total.toLocaleString()}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Total Packets</div>
          
          <div style="font-size:20px;font-weight:600;color:#ef4444;">${pcap.attacks.toLocaleString()}</div>
          <div style="font-size:12px;color:var(--text-muted);">Attacks Dectected</div>
          
          <div style="margin-top:12px;display:inline-block;padding:4px 12px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:12px;font-size:12px;font-weight:600;">
            ${pcap.attack_rate}% Threat Rate
          </div>
        </div>

        <div style="background:var(--bg-elevated);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <h4 style="color:var(--text-secondary);margin-bottom:12px;"><i class="bi bi-broadcast me-2"></i>Live Capture</h4>
          <div style="font-size:24px;font-weight:700;color:var(--text-primary);">${live.total.toLocaleString()}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Total Predictions</div>
          
          <div style="font-size:20px;font-weight:600;color:#ef4444;">${live.attacks.toLocaleString()}</div>
          <div style="font-size:12px;color:var(--text-muted);">Attacks Detected</div>
          
          <div style="margin-top:12px;display:inline-block;padding:4px 12px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:12px;font-size:12px;font-weight:600;">
            ${live.attack_rate}% Threat Rate
          </div>
        </div>
      </div>
    `;
  }

})();
