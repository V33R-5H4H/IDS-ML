// js/dashboard.js
let currentUser = null;

// ── Role config ───────────────────────────────────────────────────────────
const ROLES = {
  admin: {
    banner:  { label: "Administrator", icon: "bi-shield-fill", cls: "banner-admin",
               greeting: "Admin Control Panel",
               subtitle: "Full system access — manage users, models and all detections" },
    nav: [
      { section: "dashboard", icon: "bi-speedometer2",          label: "Dashboard" },
      { section: "predictions", icon: "bi-activity",            label: "Predictions", badge: "predBadge" },
      { section: "alerts",    icon: "bi-bell-fill",             label: "Alerts",      badge: "alertBadge", badgeCls: "danger" },
      { section: "pcap",      icon: "bi-file-earmark-binary-fill", label: "PCAP Analysis" },
      { section: "live",      icon: "bi-broadcast",             label: "Live Capture" },
      { separator: "ADMIN" },
      { section: "users",     icon: "bi-people-fill",           label: "Users" },
      { section: "requests",  icon: "bi-person-up",             label: "Access Requests", badge: "reqBadge", badgeCls: "danger" },
      { section: "health",    icon: "bi-heart-pulse-fill",      label: "System Health" },
      { separator: "ACCOUNT" },
      { section: "account",   icon: "bi-person-gear",           label: "My Account" },
    ],
    stats: ["total","attacks","normal","alerts","model","users"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","users","requests","health","account"],
  },
  analyst: {
    banner:  { label: "Analyst", icon: "bi-person-badge-fill", cls: "banner-analyst",
               greeting: "Analyst Workstation",
               subtitle: "Detection analysis, PCAP uploads and alert management" },
    nav: [
      { section: "dashboard",   icon: "bi-speedometer2",           label: "Dashboard" },
      { section: "predictions", icon: "bi-activity",               label: "Predictions", badge: "predBadge" },
      { section: "alerts",      icon: "bi-bell-fill",              label: "Alerts",      badge: "alertBadge", badgeCls: "danger" },
      { section: "pcap",        icon: "bi-file-earmark-binary-fill", label: "PCAP Analysis" },
      { section: "live",        icon: "bi-broadcast",              label: "Live Capture" },
      { separator: "ACCOUNT" },
      { section: "account",     icon: "bi-person-gear",            label: "My Account" },
    ],
    stats: ["total","attacks","normal","alerts","model"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","account"],
  },
  viewer: {
    banner:  { label: "Viewer", icon: "bi-eye-fill", cls: "banner-viewer",
               greeting: "Security Overview",
               subtitle: "Read-only access — view detections and summary reports" },
    nav: [
      { section: "dashboard", icon: "bi-speedometer2",  label: "Dashboard" },
      { section: "reports",   icon: "bi-bar-chart-fill", label: "Reports" },
      { separator: "ACCOUNT" },
      { section: "account",   icon: "bi-person-gear",   label: "My Account" },
    ],
    stats: ["total","attacks","normal"],
    allowedSections: ["dashboard","reports","account"],
  },
};

const STAT_DEFS = {
  total:   { id: "statTotal",   icon: "bi-activity",           label: "Total Predictions", cls: "blue",   trend: "Live",     trendCls: "up" },
  attacks: { id: "statAttacks", icon: "bi-shield-exclamation", label: "Attacks Detected",  cls: "red",    trend: "Active",   trendCls: "danger" },
  normal:  { id: "statNormal",  icon: "bi-check-circle-fill",  label: "Normal Traffic",    cls: "green",  trend: "Stable",   trendCls: "" },
  alerts:  { id: "statAlerts",  icon: "bi-bell-fill",          label: "Active Alerts",     cls: "yellow", trend: "Review",   trendCls: "danger" },
  model:   { id: "statModel",   icon: "bi-cpu-fill",           label: "Active Model",      cls: "purple", trend: "85.9% Acc",trendCls: "" },
  users:   { id: "statUsers",   icon: "bi-people-fill",        label: "Total Users",       cls: "teal",   trend: "Active",   trendCls: "" },
};

// ── INIT ──────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  try {
    if (!Auth.requireAuth()) return;

    currentUser = await API.me();

    if (!currentUser) {
      document.body.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;height:100vh;
                    background:#0b0f1a;flex-direction:column;gap:16px;">
          <div style="font-size:2rem;">⚠️</div>
          <div style="color:#f87171;font-size:1.1rem;font-weight:600;">Could not load user session</div>
          <div style="color:#94a3b8;font-size:.88rem;">
            Backend: <code style="color:#60a5fa;">${typeof API_BASE !== "undefined" ? API_BASE : "unknown"}</code>
          </div>
          <div style="color:#94a3b8;font-size:.85rem;">Check that the backend is running on the correct port.</div>
          <a href="index.html" style="margin-top:8px;padding:10px 24px;background:#3b82f6;
             color:#fff;border-radius:8px;text-decoration:none;font-weight:600;">Back to Login</a>
        </div>`;
      return;
    }

    const role = currentUser.role || "viewer";
    const cfg  = ROLES[role] || ROLES.viewer;

    buildRoleBanner(cfg);
    buildSidebar(cfg);
    buildStatCards(cfg);
    renderTopbarUser(currentUser);
    setupNavigation(cfg);

    await loadDashboardCards(cfg, role);
    renderProfileCard(currentUser);
    await checkAPIHealth();

    if (role === "admin") loadPendingReqBadge();

    // health-base-url
    const hbu  = document.getElementById("health-base-url");
    const hdoc = document.getElementById("health-docs-link");
    if (hbu)  hbu.textContent = typeof API_BASE !== "undefined" ? API_BASE : "—";
    if (hdoc) hdoc.href = `${API_BASE}/docs`;

  } catch (err) {
    document.body.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100vh;
                  background:#0b0f1a;flex-direction:column;gap:16px;padding:24px;">
        <div style="font-size:2rem;">💥</div>
        <div style="color:#f87171;font-size:1.1rem;font-weight:600;">Dashboard Error</div>
        <pre style="color:#fbbf24;background:#1e2330;padding:16px;border-radius:8px;
             font-size:.78rem;max-width:700px;overflow:auto;white-space:pre-wrap;">${err.stack || err.message}</pre>
        <a href="index.html" style="padding:10px 24px;background:#3b82f6;color:#fff;
           border-radius:8px;text-decoration:none;font-weight:600;">Back to Login</a>
      </div>`;
  }
});

// ── BUILDER FUNCTIONS ────────────────────────────────────────────────────
function buildRoleBanner(cfg) {
  const b = cfg.banner;
  document.getElementById("roleBanner").innerHTML =
    `<div class="role-banner-inner ${b.cls}">
       <i class="bi ${b.icon}"></i><span>${b.label}</span>
     </div>`;
}

function buildSidebar(cfg) {
  const nav = document.getElementById("sidebarNav");
  nav.innerHTML = cfg.nav.map(item => {
    if (item.separator) {
      return `<div class="nav-section-label mt-3">${item.separator}</div>`;
    }
    const badge = item.badge
      ? `<span class="nav-badge ${item.badgeCls || ""}" id="${item.badge}" style="display:none;"></span>`
      : "";
    return `<a href="#" class="nav-item" data-section="${item.section}">
              <i class="bi ${item.icon}"></i><span>${item.label}</span>${badge}
            </a>`;
  }).join("");

  const first = nav.querySelector(".nav-item");
  if (first) first.classList.add("active");
}

function buildStatCards(cfg) {
  document.getElementById("statsGrid").innerHTML = cfg.stats.map(key => {
    const s = STAT_DEFS[key];
    return `<div class="stat-card ${s.cls}">
              <div class="stat-icon"><i class="bi ${s.icon}"></i></div>
              <div class="stat-body">
                <div class="stat-value" id="${s.id}">—</div>
                <div class="stat-label">${s.label}</div>
              </div>
              <div class="stat-trend ${s.trendCls}">${s.trend}</div>
            </div>`;
  }).join("");
}

function renderTopbarUser(user) {
  const name = user.display_name || user.username;
  _txt("sidebarUsername", name);
  _txt("sidebarRole",     user.role);
  _txt("userAvatar",      name[0].toUpperCase());
  _txt("topbarUsername",  name);
  const rb = document.getElementById("topbarRole");
  if (rb) { rb.textContent = user.role; rb.className = `role-badge ${user.role}`; }
}

function renderProfileCard(user) {
  const el = document.getElementById("profileBody");
  if (!el) return;
  const name = user.display_name
    ? `${user.display_name} <span style="color:var(--text-muted);font-size:0.8rem;">(${user.username})</span>`
    : user.username;
  el.innerHTML = `
    <div class="info-row"><span class="info-key">Name</span><span class="info-val">${name}</span></div>
    <div class="info-row"><span class="info-key">Email</span><span class="info-val">${user.email || "—"}</span></div>
    <div class="info-row"><span class="info-key">Role</span>
      <span class="info-val"><span class="role-pill ${user.role}">${user.role}</span></span></div>
    <div class="info-row"><span class="info-key">Status</span>
      <span class="info-val"><span class="status-pill active">Active</span></span></div>
    <div class="info-row"><span class="info-key">Member Since</span>
      <span class="info-val">${user.created_at
        ? new Date(user.created_at).toLocaleDateString("en-IN",{day:"2-digit",month:"short",year:"numeric"})
        : "—"}</span></div>`;
}

// ── DASHBOARD CARDS ────────────────────────────────────────────────────────
const skeletons = `<div class="skeleton-row"></div>
  <div class="skeleton-row"></div><div class="skeleton-row"></div>`;

async function loadDashboardCards(cfg, role) {
  document.getElementById("dashGreeting").innerHTML =
    `<i class="bi bi-speedometer2 me-2"></i>${cfg.banner.greeting}`;
  document.getElementById("dashSubtitle").textContent = cfg.banner.subtitle;

  // Reset stat cards
  ["statTotal", "statAttacks", "statNormal", "statAlerts"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = "—";
  });
  const sm = document.getElementById("statModel");
  if (sm) sm.textContent = "RF v1.0";

  if (role === "admin") {
    const users = await API.users();
    const su = document.getElementById("statUsers");
    if (su) su.textContent = users.length;
    document.getElementById("dashCards").innerHTML = adminCards();
  } else if (role === "analyst") {
    document.getElementById("dashCards").innerHTML = analystCards();
  } else {
    document.getElementById("dashCards").innerHTML = viewerCards();
  }
  _loadHealthIntoCard();
  _loadProfileIntoCard();
  // Wire live stats + charts for all roles
  await _loadDashboardStats(role);
}

// ── Live stats loader ──────────────────────────────────────────────────────
async function _loadDashboardStats(role) {
  const stats = await API.getDashboardStats();
  if (!stats) return;

  const el = id => document.getElementById(id);
  if (el("statTotal"))   el("statTotal").textContent   = stats.total;
  if (el("statAttacks")) el("statAttacks").textContent = stats.attacks;
  if (el("statNormal"))  el("statNormal").textContent  = stats.normal;

  // Update chart subtitle
  const sub = el("dash-chart-subtitle");
  if (sub) sub.textContent = `${stats.total} total · ${stats.attacks} threats`;
  const cnt = el("chartDonutTotal");
  if (cnt) cnt.textContent = stats.total;

  // Render charts if canvases exist (admin + analyst only)
  if (el("chartDonut")) _renderDashboardCharts(stats);
}

// ── Chart instances (module-level so we can destroy on re-render) ──────────
const _dc = { donut: null, line: null, attacks: null };

function _renderDashboardCharts(stats) {
  if (_dc.donut)   { _dc.donut.destroy();   _dc.donut   = null; }
  if (_dc.line)    { _dc.line.destroy();    _dc.line    = null; }
  if (_dc.attacks) { _dc.attacks.destroy(); _dc.attacks = null; }

  const donutCtx = document.getElementById("chartDonut")?.getContext("2d");
  if (donutCtx) {
    _dc.donut = new Chart(donutCtx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [
            stats.by_label.Critical, stats.by_label.High,
            stats.by_label.Medium,   stats.by_label.Low,
          ],
          backgroundColor: [
            "rgba(239,68,68,.85)", "rgba(245,158,11,.85)",
            "rgba(59,130,246,.85)", "rgba(34,197,94,.85)",
          ],
          borderWidth: 0,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "72%",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => {
                const pct = stats.total
                  ? Math.round(ctx.parsed / stats.total * 100) : 0;
                return ` ${ctx.label}: ${ctx.parsed}  (${pct}%)`;
              },
            },
          },
        },
      },
    });

    // Custom colour legend
    const legendEl = document.getElementById("chartLegend");
    if (legendEl) {
      const C = ["#ef4444","#f59e0b","#3b82f6","#22c55e"];
      const L = ["Critical","High","Medium","Low"];
      const V = [stats.by_label.Critical,stats.by_label.High,
                 stats.by_label.Medium,  stats.by_label.Low];
      legendEl.innerHTML = L.map((l,i) =>
        `<span style="display:inline-flex;align-items:center;gap:5px;">
           <span style="width:8px;height:8px;border-radius:50%;
                        background:${C[i]};flex-shrink:0;"></span>
           <span style="color:var(--text-muted);">${l}</span>
           <strong style="color:${C[i]};">${V[i]}</strong>
         </span>`).join("");
    }
  }

  const lineCtx = document.getElementById("chartLine")?.getContext("2d");
  if (lineCtx) {
    const labels = stats.last_7_days.map(d =>
      new Date(d.date).toLocaleDateString("en-IN", { month:"short", day:"numeric" }));
    _dc.line = new Chart(lineCtx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Total",
            data: stats.last_7_days.map(d => d.total),
            borderColor: "#3b82f6",
            backgroundColor: "rgba(59,130,246,.08)",
            tension: 0.4, fill: true, pointRadius: 4, pointHoverRadius: 6,
          },
          {
            label: "Attacks",
            data: stats.last_7_days.map(d => d.attacks),
            borderColor: "#ef4444",
            backgroundColor: "rgba(239,68,68,.08)",
            tension: 0.4, fill: true, pointRadius: 4, pointHoverRadius: 6,
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            labels: { color:"#94a3b8", font:{ size:11 }, boxWidth:12, padding:10 },
          },
        },
        scales: {
          x: { grid:{ color:"rgba(255,255,255,.04)" }, ticks:{ color:"#64748b", font:{ size:10 } } },
          y: { beginAtZero:true, grid:{ color:"rgba(255,255,255,.04)" },
               ticks:{ color:"#64748b", precision:0, font:{ size:10 } } },
        },
      },
    });
  }

  // Attack type distribution bar chart
  _renderAttackChart(stats);
  // Top attacks mini-table
  _renderTopAttacksTable(stats);
}

function _renderAttackChart(stats) {
  const ctx = document.getElementById("chartAttacks")?.getContext("2d");
  if (!ctx) return;
  const attacks = stats.top_attacks || [];
  if (!attacks.length) {
    ctx.canvas.parentElement.innerHTML =
      `<div style="display:flex;align-items:center;justify-content:center;height:100%;
                   color:var(--text-muted);font-size:.82rem;gap:8px;flex-direction:column;">
         <i class="bi bi-shield-check" style="font-size:1.6rem;opacity:.3;"></i>
         No attack data yet
       </div>`;
    return;
  }
  const colors = ["#ef4444","#f59e0b","#3b82f6","#a855f7","#14b8a6"];
  _dc.attacks = new Chart(ctx, {
    type: "bar",
    data: {
      labels: attacks.map(a => a.type),
      datasets: [{
        data: attacks.map(a => a.count),
        backgroundColor: attacks.map((_, i) => colors[i % colors.length] + "cc"),
        borderRadius: 4,
        borderSkipped: false,
        barThickness: 18,
      }],
    },
    options: {
      indexAxis: "y",
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: "rgba(255,255,255,.04)" },
             ticks: { color: "#64748b", precision: 0, font: { size: 10 } } },
        y: { grid: { display: false },
             ticks: { color: "#94a3b8", font: { size: 11 } } },
      },
    },
  });
}

function _renderTopAttacksTable(stats) {
  const el = document.getElementById("topAttacksBody");
  if (!el) return;
  const attacks = stats.top_attacks || [];
  if (!attacks.length) {
    el.innerHTML = `<tr><td colspan="3" style="text-align:center;color:var(--text-muted);
      padding:14px;font-size:.82rem;">No attack types detected yet</td></tr>`;
    return;
  }
  const colors = ["#ef4444","#f59e0b","#3b82f6","#a855f7","#14b8a6"];
  const maxCount = attacks[0]?.count || 1;
  el.innerHTML = attacks.map((a, i) => `
    <tr>
      <td style="padding:7px 10px;font-size:.82rem;font-weight:600;color:${colors[i % 5]};">
        ${a.type}
      </td>
      <td style="padding:7px 10px;width:50%;">
        <div style="background:var(--border);border-radius:3px;height:6px;overflow:hidden;">
          <div style="width:${Math.round(a.count / maxCount * 100)}%;height:100%;
                      background:${colors[i % 5]};border-radius:3px;"></div>
        </div>
      </td>
      <td style="padding:7px 10px;text-align:right;font-weight:700;font-size:.82rem;
                 color:var(--text-main);">${a.count}</td>
    </tr>`).join("");
}

function adminCards() {
  return `
  <!-- Row 1: Charts (8/12) + Quick Actions (4/12) -->
  <div class="col-lg-8">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-bar-chart-fill me-2 text-primary"></i>Security Overview
        <span id="dash-chart-subtitle" class="ms-auto"
              style="font-size:.74rem;color:var(--text-muted);"></span>
      </div>
      <div class="info-card-body">
        <div class="dash-charts-grid">
          <!-- Doughnut -->
          <div class="dash-donut-wrap">
            <canvas id="chartDonut"></canvas>
            <div class="dash-donut-center">
              <div id="chartDonutTotal" style="font-size:1.6rem;font-weight:700;
                   color:var(--text-white);line-height:1;">—</div>
              <div style="font-size:.62rem;color:var(--text-muted);
                   text-transform:uppercase;letter-spacing:.5px;margin-top:3px;">Total</div>
            </div>
          </div>
          <!-- Line chart -->
          <div style="height:200px;">
            <canvas id="chartLine"></canvas>
          </div>
        </div>
        <div id="chartLegend" class="dash-legend"></div>
      </div>
    </div>
  </div>

  <!-- Quick Actions -->
  <div class="col-lg-4">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions
      </div>
      <div class="info-card-body p-0">
        <button class="quick-action-btn" onclick="navigateTo('pcap')">
          <i class="bi bi-file-earmark-binary-fill text-primary"></i>
          <div><strong>Upload PCAP</strong><small>Analyse capture file</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('predictions')">
          <i class="bi bi-activity text-info"></i>
          <div><strong>Predictions</strong><small>View risk feed</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('users')">
          <i class="bi bi-people-fill text-danger"></i>
          <div><strong>Manage Users</strong><small>Roles, activate, delete</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('requests')">
          <i class="bi bi-person-up text-warning"></i>
          <div><strong>Access Requests</strong><small>Review pending roles</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('health')">
          <i class="bi bi-heart-pulse-fill text-success"></i>
          <div><strong>System Health</strong><small>API & DB status</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
      </div>
    </div>
  </div>

  <!-- Row 2: Attack Distribution + Top Attacks -->
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-shield-exclamation me-2 text-danger"></i>Attack Distribution
      </div>
      <div class="info-card-body" style="height:200px;">
        <canvas id="chartAttacks"></canvas>
      </div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-bullseye me-2 text-warning"></i>Top Attack Types
      </div>
      <div class="info-card-body p-0">
        <table style="width:100%;border-collapse:collapse;">
          <tbody id="topAttacksBody">
            <tr><td colspan="3" class="tbl-empty">
              <div class="skeleton-row"></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Row 3: Health + Profile + Permissions -->
  <div class="col-lg-4">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Health
        <a href="#" class="card-link ms-auto"
           onclick="navigateTo('health');return false;">
          Full Details <i class="bi bi-arrow-right"></i>
        </a>
      </div>
      <div class="info-card-body" id="healthBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-person-fill me-2 text-primary"></i>My Profile
        <a href="#" class="card-link ms-auto"
           onclick="navigateTo('account');return false;">
          Edit <i class="bi bi-pencil"></i>
        </a>
      </div>
      <div class="info-card-body" id="profileBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-key-fill me-2 text-warning"></i>Permissions — Admin
      </div>
      <div class="info-card-body">
        <div class="permissions-grid">${adminPerms()}</div>
      </div>
    </div>
  </div>`;
}


function analystCards() {
  return `
  <div class="col-lg-8">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-bar-chart-fill me-2 text-primary"></i>Security Overview
        <span id="dash-chart-subtitle" class="ms-auto"
              style="font-size:.74rem;color:var(--text-muted);"></span>
      </div>
      <div class="info-card-body">
        <div class="dash-charts-grid">
          <div class="dash-donut-wrap">
            <canvas id="chartDonut"></canvas>
            <div class="dash-donut-center">
              <div id="chartDonutTotal"
                   style="font-size:1.6rem;font-weight:700;color:var(--text-white);line-height:1;">—</div>
              <div style="font-size:.62rem;color:var(--text-muted);
                   text-transform:uppercase;letter-spacing:.5px;margin-top:3px;">Total</div>
            </div>
          </div>
          <div style="height:200px;"><canvas id="chartLine"></canvas></div>
        </div>
        <div id="chartLegend" class="dash-legend"></div>
      </div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions
      </div>
      <div class="info-card-body p-0">
        <button class="quick-action-btn" onclick="navigateTo('pcap')">
          <i class="bi bi-file-earmark-binary-fill text-primary"></i>
          <div><strong>Upload PCAP</strong><small>Analyse capture file</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('predictions')">
          <i class="bi bi-activity text-info"></i>
          <div><strong>Predictions</strong><small>View risk feed</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('alerts')">
          <i class="bi bi-bell-fill text-danger"></i>
          <div><strong>Alerts</strong><small>Active threat alerts</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
        <button class="quick-action-btn" onclick="navigateTo('account')">
          <i class="bi bi-person-gear text-purple"></i>
          <div><strong>My Account</strong><small>Edit profile & password</small></div>
          <i class="bi bi-chevron-right ms-auto"></i>
        </button>
      </div>
    </div>
  </div>

  <!-- Attack Distribution + Top Attacks -->
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-shield-exclamation me-2 text-danger"></i>Attack Distribution
      </div>
      <div class="info-card-body" style="height:200px;">
        <canvas id="chartAttacks"></canvas>
      </div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-bullseye me-2 text-warning"></i>Top Attack Types
      </div>
      <div class="info-card-body p-0">
        <table style="width:100%;border-collapse:collapse;">
          <tbody id="topAttacksBody">
            <tr><td colspan="3" class="tbl-empty">
              <div class="skeleton-row"></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-heart-pulse-fill me-2 text-success"></i>API Status
      </div>
      <div class="info-card-body" id="healthBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-person-badge-fill me-2" style="color:var(--accent-blue)"></i>My Profile
        <a href="#" class="card-link ms-auto"
           onclick="navigateTo('account');return false;">
          Edit <i class="bi bi-pencil"></i>
        </a>
      </div>
      <div class="info-card-body" id="profileBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-12">
    <div class="info-card">
      <div class="info-card-header">
        <i class="bi bi-key-fill me-2 text-primary"></i>Permissions — Analyst
      </div>
      <div class="info-card-body">
        <div class="permissions-grid">${analystPerms()}</div>
      </div>
    </div>
  </div>`;
}


function viewerCards() {
  return `
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Status
      </div>
      <div class="info-card-body" id="healthBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="info-card h-100">
      <div class="info-card-header">
        <i class="bi bi-eye-fill me-2 text-success"></i>My Profile
        <a href="#" class="card-link ms-auto"
           onclick="navigateTo('account');return false;">
          Edit <i class="bi bi-pencil"></i>
        </a>
      </div>
      <div class="info-card-body" id="profileBody">${skeletons}</div>
    </div>
  </div>
  <div class="col-12">
    <div class="info-card">
      <div class="info-card-header">
        <i class="bi bi-bar-chart-fill me-2 text-info"></i>Security Reports
        <a href="#" class="card-link ms-auto"
           onclick="navigateTo('reports');return false;">
          View Reports <i class="bi bi-arrow-right"></i>
        </a>
      </div>
      <div class="info-card-body">
        <div class="viewer-notice">
          <i class="bi bi-eye-fill"></i>
          <div><strong>Read-Only Access</strong>
          <p>View detection summaries and security reports.
             Use <strong>My Account → Request Access</strong>
             to request elevated permissions.</p></div>
        </div>
      </div>
    </div>
  </div>
  <div class="col-12">
    <div class="info-card">
      <div class="info-card-header">
        <i class="bi bi-key-fill me-2 text-primary"></i>Permissions — Viewer
      </div>
      <div class="info-card-body">
        <div class="permissions-grid">${viewerPerms()}</div>
      </div>
    </div>
  </div>`;
}


// ── Permissions ───────────────────────────────────────────────────────────
function perm(icon, label, allowed) {
  return `<div class="perm-item ${allowed ? "allowed" : "denied"}">
    <i class="bi ${allowed ? "bi-check-circle-fill" : "bi-x-circle-fill"}"></i>
    <i class="bi ${icon} perm-feat-icon"></i>
    <span>${label}</span>
  </div>`;
}
// ── Permissions helpers ────────────────────────────────────────────────────────
function _permRow(ok, text) {
  return `<div class="perm-item ${ok ? "allowed" : "denied"}">
    <i class="bi ${ok ? "bi-check-circle-fill" : "bi-x-circle-fill"}"></i>
    <span>${text}</span>
  </div>`;
}
function adminPerms() {
  return [
    [true,  "Upload & analyse PCAP files"],
    [true,  "View ML predictions feed"],
    [true,  "Manage users & roles"],
    [true,  "Approve / reject access requests"],
    [true,  "Reset user passwords"],
    [true,  "View system health"],
    [true,  "View security reports"],
  ].map(([ok, t]) => _permRow(ok, t)).join("");
}
function analystPerms() {
  return [
    [true,  "Upload & analyse PCAP files"],
    [true,  "View ML predictions feed"],
    [false, "Manage users & roles"],
    [false, "Approve / reject access requests"],
    [false, "Reset user passwords"],
    [true,  "View system health"],
    [true,  "View security reports"],
  ].map(([ok, t]) => _permRow(ok, t)).join("");
}
function viewerPerms() {
  return [
    [false, "Upload & analyse PCAP files"],
    [false, "View ML predictions feed"],
    [false, "Manage users & roles"],
    [false, "Approve / reject access requests"],
    [false, "Reset user passwords"],
    [false, "View system health"],
    [true,  "View security reports"],
  ].map(([ok, t]) => _permRow(ok, t)).join("");
}

// ── Health mini-card ───────────────────────────────────────────────────────────
async function _loadHealthIntoCard() {
  const el = document.getElementById("healthBody");
  if (!el) return;
  const h = await API.health();
  if (!h) {
    el.innerHTML = `<div class="health-row">
      <span class="health-dot red"></span><span>Backend unreachable</span>
    </div>`;
    return;
  }
  el.innerHTML = `
    <div class="health-row">
      <span class="health-dot green"></span><span>API</span>
      <span class="ms-auto" style="color:#22c55e;font-size:.75rem;font-weight:600;">Online</span>
    </div>
    <div class="health-row">
      <span class="health-dot green"></span><span>Version</span>
      <span class="ms-auto" style="color:var(--text-muted);font-size:.75rem;">${h.version || "2.0.0"}</span>
    </div>
    <div class="health-row">
      <span class="health-dot green"></span><span>Auth</span>
      <span class="ms-auto" style="color:var(--text-muted);font-size:.75rem;">JWT / bcrypt</span>
    </div>`;
}

// ── Profile mini-card ──────────────────────────────────────────────────────────
function _loadProfileIntoCard() {
  const el = document.getElementById("profileBody");
  if (!el || !currentUser) return;
  const roleColors = { admin:"#ef4444", analyst:"#3b82f6", viewer:"#22c55e" };
  const clr = roleColors[currentUser.role] || "#94a3b8";
  el.innerHTML = `
    <div class="health-row">
      <span style="color:var(--text-muted);font-size:.75rem;">Username</span>
      <span class="ms-auto" style="font-weight:600;color:var(--text-white);font-size:.82rem;">
        ${currentUser.username}</span>
    </div>
    <div class="health-row">
      <span style="color:var(--text-muted);font-size:.75rem;">Email</span>
      <span class="ms-auto" style="color:var(--text-muted);font-size:.75rem;
            max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
            title="${currentUser.email}">${currentUser.email}</span>
    </div>
    <div class="health-row">
      <span style="color:var(--text-muted);font-size:.75rem;">Role</span>
      <span class="ms-auto" style="font-weight:700;font-size:.75rem;color:${clr};
            text-transform:capitalize;">${currentUser.role}</span>
    </div>
    <div class="health-row">
      <span style="color:var(--text-muted);font-size:.75rem;">Last login</span>
      <span class="ms-auto" style="color:var(--text-muted);font-size:.72rem;">
        ${currentUser.last_login
          ? new Date(currentUser.last_login).toLocaleDateString("en-IN",
              { day:"numeric", month:"short", hour:"2-digit", minute:"2-digit" })
          : "First session"}
      </span>
    </div>`;
}


// ── API HEALTH ────────────────────────────────────────────────────────────
async function checkAPIHealth() {
  const data = await API.health();
  const ok   = data && data.status === "ok";
  const dot  = document.getElementById("apiStatus");
  if (dot) dot.innerHTML = ok
    ? `<span class="status-dot green d-inline-block me-1"></span>Online`
    : `<span class="status-dot red d-inline-block me-1"></span>Offline`;

  const html = ok ? `
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>API Server</span>
      <span class="info-val text-success">Online</span></div>
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Database</span>
      <span class="info-val text-success">Connected</span></div>
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Auth Service</span>
      <span class="info-val text-success">Running</span></div>
    <div class="info-row"><span class="info-key">Version</span>
      <span class="info-val">${data.version || "—"}</span></div>` :
    `<div class="info-row"><span class="info-key" style="color:var(--accent-red);">
       <i class="bi bi-exclamation-triangle me-1"></i>API Unreachable</span></div>`;

  ["healthBody","fullHealthBody"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  });
}

// ── NAVIGATION ────────────────────────────────────────────────────────────
function setupNavigation(cfg) {
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault();
      navigateTo(item.dataset.section, cfg);
    });
  });
}

function navigateTo(section, cfg) {
  cfg = cfg || ROLES[currentUser?.role] || ROLES.viewer;

  if (!cfg.allowedSections.includes(section)) {
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
    const d = document.getElementById("section-denied");
    if (d) d.classList.add("active");
    const m = document.getElementById("deniedMsg");
    if (m) m.textContent = `The "${section}" section requires higher privileges.`;
    _txt("pageTitle", "Access Denied");
    return;
  }

  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const an = document.querySelector(`.nav-item[data-section="${section}"]`);
  if (an) an.classList.add("active");

  document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
  const t = document.getElementById(`section-${section}`);
  if (t) t.classList.add("active");

  const titles = {
    dashboard:"Dashboard", predictions:"Predictions", alerts:"Alerts",
    pcap:"PCAP Analysis", live:"Live Capture", reports:"Reports",
    users:"User Management", requests:"Access Requests",
    health:"System Health", account:"My Account"
  };
  _txt("pageTitle", titles[section] || section);

  if (section === "users")    loadUsers();
  if (section === "requests") { loadRoleRequests("pending"); loadPasswordResets(); }
  if (section === "health")   { checkAPIHealth(); loadModelSelector(); }
  if (section === "account")  initAccountSection(currentUser);
  if (section === "pcap")     { if (typeof loadPcapHistory === "function") loadPcapHistory(); }
  if (section === 'predictions') { if (typeof loadPredictions === 'function') loadPredictions(); }
  if (section === 'reports') { if (typeof loadReports === 'function') loadReports(); }
  if (section === 'live') { if (typeof initLiveCapture === 'function') initLiveCapture(); }
}

// ── USERS TABLE ───────────────────────────────────────────────────────────
async function loadUsers() {
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" class="tbl-empty">
    <span class="spinner-sm"></span> Loading users…</td></tr>`;

  const users = await API.users();
  const badge = document.getElementById("userCountBadge");
  if (badge) { badge.textContent = users.length; badge.style.display = users.length ? "inline-block" : "none"; }

  if (!users.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="tbl-empty">No users found</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => {
    const isMe = u.username === currentUser?.username;
    return `<tr id="user-row-${u.id}">
      <td style="color:var(--text-muted);font-size:0.8rem;">${u.id}</td>
      <td>
        <div style="display:flex;align-items:center;gap:9px;">
          <div class="user-avatar" style="width:32px;height:32px;font-size:0.8rem;border-radius:8px;flex-shrink:0;">
            ${(u.display_name || u.username)[0].toUpperCase()}
          </div>
          <div>
            <div style="font-weight:700;color:var(--text-main);">
              ${u.display_name || u.username}
              ${isMe ? `<span style="background:rgba(59,130,246,.15);color:#60a5fa;
                font-size:0.62rem;padding:1px 6px;border-radius:20px;margin-left:4px;">You</span>` : ""}
            </div>
            <div style="font-size:0.72rem;color:var(--text-muted);">${u.email}</div>
          </div>
        </div>
      </td>
      <td><span class="role-pill ${u.role}">${u.role}</span></td>
      <td><span class="status-pill ${u.is_active ? "active" : "inactive"}">
        ${u.is_active ? "Active" : "Inactive"}</span></td>
      <td style="color:var(--text-muted);font-size:0.78rem;">
        ${u.created_at ? new Date(u.created_at).toLocaleDateString("en-IN",{day:"2-digit",month:"short",year:"numeric"}) : "—"}
      </td>
      <td style="color:var(--text-muted);font-size:0.78rem;">
        ${u.last_login ? new Date(u.last_login).toLocaleString("en-IN") : "Never"}
      </td>
      <td>
        ${isMe ? `<span style="color:var(--text-muted);font-size:0.78rem;">your account</span>` : `
        <div class="user-actions">
          <button class="btn-sm-action role" onclick="openRoleModal(${u.id},'${u.username}','${u.role}')">
            <i class="bi bi-arrow-repeat"></i>Role</button>
          ${u.is_active
            ? `<button class="btn-sm-action deact" onclick="toggleActive(${u.id},'${u.username}',false)">
                 <i class="bi bi-pause-circle"></i>Deactivate</button>`
            : `<button class="btn-sm-action act" onclick="toggleActive(${u.id},'${u.username}',true)">
                 <i class="bi bi-play-circle"></i>Activate</button>`}
          <button class="btn-sm-action pwd" onclick="openPwdModal(${u.id},'${u.username}')">
            <i class="bi bi-key"></i>Password</button>
          <button class="btn-sm-action del" onclick="openDeleteModal(${u.id},'${u.username}')">
            <i class="bi bi-trash3"></i>Delete</button>
        </div>`}
      </td>
    </tr>`;
  }).join("");
}

// ── ROLE REQUESTS ─────────────────────────────────────────────────────────
let reqFilter = "pending";

async function loadPendingReqBadge() {
  const reqs  = await API.getRoleRequests("pending");
  const badge = document.getElementById("reqBadge");
  if (!badge) return;
  badge.textContent   = reqs.length;
  badge.style.display = reqs.length > 0 ? "inline-block" : "none";
}

async function loadRoleRequests(status = "pending") {
  reqFilter = status;
  document.querySelectorAll(".req-filter-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.status === status));
  const list = document.getElementById("reqList");
  if (!list) return;
  list.innerHTML = `<div style="text-align:center;padding:24px;">
    <span class="spinner-sm"></span> Loading…</div>`;

  const reqs = await API.getRoleRequests(status);
  if (!reqs.length) {
    list.innerHTML = `<div style="text-align:center;padding:32px;color:var(--text-muted);">
      <i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:8px;opacity:.4;"></i>
      No ${status} access requests</div>`;
    return;
  }

  list.innerHTML = reqs.map(r => {
    const isPending = r.status === "pending";
    return `<div class="req-card ${r.status}" id="req-card-${r.id}">
      <div class="req-card-top">
        <div class="req-card-user">
          <div class="req-avatar">${r.username[0].toUpperCase()}</div>
          <div>
            <div class="req-card-uname">${r.username}</div>
            <div class="req-card-meta">${timeSince(r.created_at)} ago · Request #${r.id}</div>
          </div>
        </div>
        <span class="req-badge ${r.status}">
          <i class="bi ${r.status==="pending"?"bi-hourglass-split":r.status==="approved"?"bi-check-circle-fill":"bi-x-circle-fill"}"></i>
          ${r.status.charAt(0).toUpperCase() + r.status.slice(1)}
        </span>
      </div>
      <div class="req-card-body">
        <div class="req-role-arrow">
          <span class="role-pill ${r.current_role}" style="font-size:0.72rem;">${r.current_role}</span>
          <span class="arr"><i class="bi bi-arrow-right"></i></span>
          <span class="role-pill ${r.requested_role}" style="font-size:0.72rem;">${r.requested_role}</span>
        </div>
        ${r.reason ? `<div class="req-reason-box">${r.reason}</div>` : ""}
      </div>
      <div class="req-card-actions">
        ${isPending ? `
          <button class="btn-approve" onclick="reviewRequest(${r.id},'approve')">
            <i class="bi bi-check-lg"></i>Approve</button>
          <button class="btn-reject" onclick="reviewRequest(${r.id},'reject')">
            <i class="bi bi-x-lg"></i>Reject</button>` :
          `<span class="req-reviewed-by">
            <i class="bi bi-person-check"></i>Reviewed by ${r.reviewed_by || "—"}</span>`}
      </div>
    </div>`;
  }).join("");
}

async function reviewRequest(reqId, action) {
  const card = document.getElementById(`req-card-${reqId}`);
  const btns = card?.querySelectorAll("button");
  if (btns) btns.forEach(b => b.disabled = true);

  const result = action === "approve"
    ? await API.approveRoleRequest(reqId)
    : await API.rejectRoleRequest(reqId);

  if (result.ok) {
    showToast(result.data.message || `Request ${action}d`, "success");
    loadRoleRequests(reqFilter);
    loadPendingReqBadge();
    const me = await API.me();
    if (me) { currentUser = me; renderTopbarUser(currentUser); }
  } else {
    showToast(result.data?.detail || "Action failed", "error");
    if (btns) btns.forEach(b => b.disabled = false);
  }
}

// ── PASSWORD RESETS ───────────────────────────────────────────────────────
let pendingResolveId = null;

async function loadPasswordResets() {
  const wrap  = document.getElementById("pwdResetTable");
  const badge = document.getElementById("pwdResetBadge");
  if (!wrap) return;

  wrap.innerHTML = `<div style="text-align:center;padding:18px;">
    <span class="spinner-sm"></span> Loading…</div>`;

  let res;
  try { res = await API.getPasswordResets(); }
  catch(e) {
    wrap.innerHTML = `<p style="color:#f87171;padding:12px;">Error: ${e.message}</p>`;
    return;
  }

  if (!res) { wrap.innerHTML = `<p style="color:#f87171;padding:12px;">Could not reach server.</p>`; return; }
  if (!res.ok) { wrap.innerHTML = `<p style="color:#f87171;padding:12px;">${res.status} — Request failed</p>`; return; }

  const reqs    = await res.json();
  const pending = reqs.filter(r => r.status === "pending");
  if (badge) { badge.textContent = pending.length; badge.style.display = pending.length ? "inline-block" : "none"; }

  if (!reqs.length) {
    wrap.innerHTML = `<div style="text-align:center;padding:28px;color:var(--text-muted);">
      <i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:8px;opacity:.4;"></i>
      No password reset requests</div>`;
    return;
  }

  wrap.innerHTML = `<div class="table-wrap">
    <table class="requests-table">
      <thead><tr>
        <th>User</th><th>Identifier</th><th>Reason</th>
        <th>Status</th><th>Submitted</th><th>Actions</th>
      </tr></thead>
      <tbody>
        ${reqs.map(r => `<tr>
          <td style="font-weight:600;">${r.username || "—"}</td>
          <td style="color:var(--text-muted);font-size:0.8rem;">${r.identifier}</td>
          <td style="color:var(--text-muted);font-size:0.8rem;max-width:200px;">${r.reason || "—"}</td>
          <td><span class="req-pill ${r.status}">${r.status}</span></td>
          <td style="color:var(--text-muted);font-size:0.78rem;">
            ${r.created_at ? new Date(r.created_at).toLocaleString("en-IN") : "—"}</td>
          <td>
            ${r.status === "pending" ? `
              <button class="btn-action approve" onclick="openResolveModal(${r.id},'${r.identifier}')">
                <i class="bi bi-key"></i>Set Password</button>
              <button class="btn-action reject" onclick="dismissReset(${r.id})">
                <i class="bi bi-x"></i>Dismiss</button>` :
              `<span style="color:var(--text-muted);font-size:0.78rem;">${r.status}</span>`}
          </td>
        </tr>`).join("")}
      </tbody>
    </table>
  </div>`;
}

function openResolveModal(id, identifier) {
  pendingResolveId = id;
  document.getElementById("resolveModalUser").textContent = `Set new password for: ${identifier}`;
  document.getElementById("resolvePwd").value = "";
  const alertEl = document.getElementById("resolveAlert");
  if (alertEl) alertEl.style.display = "none";
  document.getElementById("resolveModal").style.display = "flex";
  setTimeout(() => document.getElementById("resolvePwd")?.focus(), 100);
}

function closeResolveModal() {
  document.getElementById("resolveModal").style.display = "none";
  pendingResolveId = null;
}

async function confirmResolve() {
  const pwd = document.getElementById("resolvePwd").value;
  const alertEl = document.getElementById("resolveAlert");
  if (pwd.length < 6) {
    alertEl.textContent = "Password must be at least 6 characters.";
    alertEl.style.display = "block";
    return;
  }
  const btn = document.getElementById("resolveBtn");
  btn.disabled = true;
  const res = await API.resolvePasswordReset(pendingResolveId, pwd);
  btn.disabled = false;
  if (res && res.ok) {
    closeResolveModal();
    showToast("Password reset successfully!", "success");
    loadPasswordResets();
  } else {
    const d = res ? await res.json().catch(() => ({})) : {};
    alertEl.textContent = d.detail || "Failed to set password.";
    alertEl.style.display = "block";
  }
}

async function dismissReset(id) {
  const res = await API.dismissPasswordReset(id);
  if (res && res.ok) {
    showToast("Request dismissed.", "success");
    loadPasswordResets();
  } else {
    showToast("Failed to dismiss.", "error");
  }
}

// ── USER MODALS ───────────────────────────────────────────────────────────
function closeModal() {
  const m = document.getElementById("idsModal");
  if (m) m.remove();
}

function openModal(html) {
  closeModal();
  const overlay = document.createElement("div");
  overlay.id        = "idsModal";
  overlay.className = "ids-modal-overlay";
  overlay.innerHTML = `<div class="ids-modal">${html}</div>`;
  overlay.addEventListener("click", e => { if (e.target === overlay) closeModal(); });
  document.body.appendChild(overlay);
}

function openAddUserModal() {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-person-plus-fill text-primary"></i>Add New User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div class="input-group-custom">
      <label class="form-label-custom">Username</label>
      <input id="musername" class="form-input-custom" placeholder="Enter username"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Email</label>
      <input id="memail" type="email" class="form-input-custom" placeholder="user@example.com"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Password</label>
      <input id="mpassword" type="password" class="form-input-custom" placeholder="Min. 6 characters"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Role</label>
      <select id="mrole" class="ids-select">
        <option value="viewer">Viewer — Read-only</option>
        <option value="analyst">Analyst — Detection & PCAP</option>
        <option value="admin">Admin — Full access</option>
      </select>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitAddUser()">
        <i class="bi bi-person-check me-1"></i>Create User</button>
    </div>`);
}

async function submitAddUser() {
  const username = document.getElementById("musername").value.trim();
  const email    = document.getElementById("memail").value.trim();
  const password = document.getElementById("mpassword").value;
  const role     = document.getElementById("mrole").value;
  if (!username || !email || !password) return modalAlert("All fields are required.", "error");
  const result = await API.createUser(username, email, password, role);
  if (result.ok) {
    closeModal();
    showToast(`User ${username} created as ${role}!`, "success");
    loadUsers();
  } else {
    modalAlert(result.data?.detail || "Failed to create user.", "error");
  }
}

function openRoleModal(userId, username, currentRole) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-arrow-repeat" style="color:var(--accent-blue);"></i>Change Role</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:14px;">
      Update role for <strong style="color:var(--text-main);">${username}</strong></p>
    <div class="input-group-custom">
      <label class="form-label-custom">New Role</label>
      <select id="mnewRole" class="ids-select">
        <option value="viewer"  ${currentRole==="viewer" ?"selected":""}>Viewer</option>
        <option value="analyst" ${currentRole==="analyst"?"selected":""}>Analyst</option>
        <option value="admin"   ${currentRole==="admin"  ?"selected":""}>Admin</option>
      </select>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitRoleChange(${userId},'${username}')">
        <i class="bi bi-check2 me-1"></i>Update Role</button>
    </div>`);
}

async function submitRoleChange(userId, username) {
  const role   = document.getElementById("mnewRole").value;
  const result = await API.changeRole(userId, role);
  if (result.ok) { closeModal(); showToast(`${username} is now ${role}`, "success"); loadUsers(); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

function openPwdModal(userId, username) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-key-fill text-warning"></i>Reset Password</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:14px;">
      Set new password for <strong style="color:var(--text-main);">${username}</strong></p>
    <div class="input-group-custom">
      <label class="form-label-custom">New Password</label>
      <input id="mnewPwd" type="password" class="form-input-custom" placeholder="Min. 6 characters"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Confirm Password</label>
      <input id="mconfirmPwd" type="password" class="form-input-custom" placeholder="Repeat password"/>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitResetPwd(${userId},'${username}')">
        <i class="bi bi-check2 me-1"></i>Reset</button>
    </div>`);
}

async function submitResetPwd(userId, username) {
  const pwd1 = document.getElementById("mnewPwd").value;
  const pwd2 = document.getElementById("mconfirmPwd").value;
  if (pwd1.length < 6) return modalAlert("Password must be at least 6 characters.", "error");
  if (pwd1 !== pwd2)   return modalAlert("Passwords do not match.", "error");
  const result = await API.resetPassword(userId, pwd1);
  if (result.ok) { closeModal(); showToast(`Password reset for ${username}`, "success"); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

function openDeleteModal(userId, username) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-trash3-fill text-danger"></i>Delete User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div style="text-align:center;padding:10px 0 20px;">
      <div style="font-size:2.5rem;margin-bottom:12px;">🗑️</div>
      <p style="font-weight:700;font-size:1rem;color:var(--text-main);">
        Permanently delete <span style="color:var(--accent-red);">${username}</span>?</p>
      <p style="color:var(--text-muted);font-size:0.85rem;">This cannot be undone.</p>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-danger" onclick="submitDelete(${userId},'${username}')">
        <i class="bi bi-trash3 me-1"></i>Delete Permanently</button>
    </div>`);
}

async function submitDelete(userId, username) {
  const result = await API.deleteUser(userId);
  if (result.ok) { closeModal(); showToast(`${username} deleted`, "success"); loadUsers(); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

async function toggleActive(userId, username, activate) {
  const ok = activate ? await API.activateUser(userId) : await API.deactivateUser(userId);
  if (ok) { showToast(`${username} ${activate?"activated":"deactivated"}`, "success"); loadUsers(); }
  else showToast("Action failed", "error");
}

function modalAlert(msg, type) {
  const el = document.getElementById("modalAlert");
  if (!el) return;
  el.textContent = msg;
  el.className   = `alert-area ${type}`;
}

// ── MISC ──────────────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb   = document.getElementById("sidebar");
  const main = document.getElementById("mainContent");
  if (window.innerWidth < 768) {
    sb.classList.toggle("open");
  } else {
    sb.classList.toggle("collapsed");
    main.classList.toggle("expanded");
  }
}

async function refreshData() {
  await checkAPIHealth();
  renderProfileCard(currentUser);
  showToast("Refreshed", "success");
}

function showToast(msg, type = "success") {
  const el = document.getElementById("toastEl");
  if (!el) return;
  document.getElementById("toastIcon").className =
    type === "success" ? "bi bi-check-circle-fill" : "bi bi-x-circle-fill";
  document.getElementById("toastMsg").textContent = msg;
  el.className = `ids-toast ${type}`;
  setTimeout(() => { el.className = "ids-toast d-none"; }, 3500);
}

function timeSince(dateStr) {
  const s = Math.floor((Date.now() - new Date(dateStr)) / 1000);
  if (s < 60)   return `${s}s`;
  if (s < 3600) return `${Math.floor(s/60)}m`;
  if (s < 86400)return `${Math.floor(s/3600)}h`;
  return `${Math.floor(s/86400)}d`;
}

function _txt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── MODEL MANAGEMENT ──────────────────────────────────────────────────────────
async function loadModelSelector() {
  try {
    const models = await API.getModels();
    const active = await API.getActiveModel();

    // Update active model info
    if (active) {
      _txt("activeModelName", active.model_name || active.key || "—");
      _txt("activeModelAccuracy", active.accuracy
        ? `${(active.accuracy * 100).toFixed(1)}%`
        : "—");
      _txt("activeModelType", active.model_type || "—");
      _txt("activeModelDataset", active.dataset || "—");
    }

    // Populate dropdown
    const sel = document.getElementById("modelSelector");
    if (sel && models.length > 0) {
      sel.innerHTML = models.map(m => {
        const acc = m.accuracy ? ` (${(m.accuracy * 100).toFixed(1)}%)` : "";
        const selected = m.is_active ? "selected" : "";
        return `<option value="${m.key}" ${selected}>${m.name}${acc}</option>`;
      }).join("");
    } else if (sel) {
      sel.innerHTML = `<option value="">No models available</option>`;
    }

    // Build model comparison list
    const listEl = document.getElementById("modelList");
    if (listEl && models.length > 1) {
      listEl.innerHTML = `
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">
          Available Models (${models.length})
        </div>
        ${models.map(m => `
          <div class="health-row" style="padding:6px 0;">
            <span style="display:flex;align-items:center;gap:8px;">
              <span class="health-dot ${m.is_active ? 'green' : 'gray'}"></span>
              <span>${m.name}</span>
            </span>
            <span style="font-size:0.85rem; color:var(--text-muted);">
              ${m.accuracy ? (m.accuracy * 100).toFixed(1) + '%' : '—'}
              · ${m.type || '?'} · ${m.dataset || '?'}
            </span>
          </div>
        `).join("")}
      `;
    } else if (listEl) {
      listEl.innerHTML = "";
    }
  } catch (e) {
    console.warn("Model selector load failed:", e);
  }
}

async function switchSelectedModel() {
  const sel = document.getElementById("modelSelector");
  if (!sel || !sel.value) return;

  if (currentUser && currentUser.role !== "admin") {
    showToast("Only admins can switch models", "warning");
    return;
  }

  const key = sel.value;
  const result = await API.switchModel(key);
  if (result.ok) {
    showToast(`Switched to ${result.data.model?.model_name || key}`, "success");
    loadModelSelector();
  } else {
    showToast(result.data?.detail || "Failed to switch model", "error");
  }
}

async function refreshModelList() {
  if (currentUser && currentUser.role !== "admin") {
    showToast("Only admins can refresh models", "warning");
    return;
  }

  const result = await API.refreshModels();
  if (result.ok) {
    showToast("Models refreshed", "success");
    loadModelSelector();
  } else {
    showToast(result.data?.detail || "Failed to refresh", "error");
  }
}
