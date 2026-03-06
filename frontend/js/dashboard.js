// js/dashboard.js — Role-based dashboard

//const API_BASE = "http://localhost:8000";
let currentUser = null;

// ── Role Definitions ─────────────────────────────────────────────────────────
const ROLES = {
  admin: {
    banner:    { label: "Administrator", icon: "bi-shield-fill",       cls: "banner-admin"   },
    greeting:  "Admin Control Panel",
    subtitle:  "Full system access — manage users, models and all detections",
    nav: [
      { section: "dashboard",   icon: "bi-speedometer2",          label: "Dashboard"       },
      { section: "predictions", icon: "bi-activity",              label: "Predictions",   badge: "predBadge"  },
      { section: "alerts",      icon: "bi-bell-fill",             label: "Alerts",        badge: "alertBadge", badgeCls: "danger" },
      { section: "pcap",        icon: "bi-file-earmark-binary-fill", label: "PCAP Analysis" },
      { section: "live",        icon: "bi-broadcast",             label: "Live Capture"   },
      { separator: "ADMIN" },
      { section: "users",       icon: "bi-people-fill",           label: "Users"          },
      { section: "health",      icon: "bi-heart-pulse-fill",      label: "System Health"  },
    ],
    stats: ["total","attacks","normal","alerts","model","users"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","users","health"]
  },

  analyst: {
    banner:    { label: "Analyst",        icon: "bi-person-badge-fill",  cls: "banner-analyst" },
    greeting:  "Analyst Workstation",
    subtitle:  "Detection analysis, PCAP uploads and alert management",
    nav: [
      { section: "dashboard",   icon: "bi-speedometer2",          label: "Dashboard"       },
      { section: "predictions", icon: "bi-activity",              label: "Predictions",   badge: "predBadge"  },
      { section: "alerts",      icon: "bi-bell-fill",             label: "Alerts",        badge: "alertBadge", badgeCls: "danger" },
      { section: "pcap",        icon: "bi-file-earmark-binary-fill", label: "PCAP Analysis" },
      { section: "live",        icon: "bi-broadcast",             label: "Live Capture"   },
    ],
    stats: ["total","attacks","normal","alerts","model"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live"]
  },

  viewer: {
    banner:    { label: "Viewer",         icon: "bi-eye-fill",           cls: "banner-viewer"  },
    greeting:  "Security Overview",
    subtitle:  "Read-only access — view detections and summary reports",
    nav: [
      { section: "dashboard",   icon: "bi-speedometer2",          label: "Dashboard"       },
      { section: "reports",     icon: "bi-bar-chart-fill",        label: "Reports"         },
    ],
    stats: ["total","attacks","normal"],
    allowedSections: ["dashboard","reports"]
  }
};

// ── Stat card definitions ─────────────────────────────────────────────────────
const STAT_DEFS = {
  total:   { id: "statTotal",   icon: "bi-activity",           label: "Total Predictions", cls: "blue",   trend: "Live",      trendCls: "up"     },
  attacks: { id: "statAttacks", icon: "bi-shield-exclamation", label: "Attacks Detected",  cls: "red",    trend: "Active",    trendCls: "up"     },
  normal:  { id: "statNormal",  icon: "bi-check-circle-fill",  label: "Normal Traffic",    cls: "green",  trend: "Stable",    trendCls: ""       },
  alerts:  { id: "statAlerts",  icon: "bi-bell-fill",          label: "Active Alerts",     cls: "yellow", trend: "Review",    trendCls: "danger" },
  model:   { id: "statModel",   icon: "bi-cpu-fill",           label: "Active Model",      cls: "purple", trend: "85.9% Acc", trendCls: ""       },
  users:   { id: "statUsers",   icon: "bi-people-fill",        label: "Total Users",       cls: "teal",   trend: "Active",    trendCls: ""       },
};

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  if (!Auth.requireAuth()) return;

  currentUser = await API.me();
  if (!currentUser) { logout(); return; }

  const role = currentUser.role;
  const cfg  = ROLES[role] || ROLES.viewer;

  buildRoleBanner(cfg);
  buildSidebar(cfg);
  buildStatCards(cfg);
  renderUserInfo(currentUser);
  await checkAPIHealth();
  await loadDashboardCards(cfg, role);
  setupNavigation(cfg);
});

// ── Role banner ───────────────────────────────────────────────────────────────
function buildRoleBanner(cfg) {
  const b = cfg.banner;
  document.getElementById("roleBanner").innerHTML = `
    <div class="role-banner-inner ${b.cls}">
      <i class="bi ${b.icon}"></i>
      <span>${b.label}</span>
    </div>`;
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function buildSidebar(cfg) {
  const nav = document.getElementById("sidebarNav");
  let html = "";
  cfg.nav.forEach(item => {
    if (item.separator) {
      html += `<div class="nav-section-label mt-3">${item.separator}</div>`;
      return;
    }
    const badge = item.badge
      ? `<span class="nav-badge ${item.badgeCls || ""}" id="${item.badge}">0</span>`
      : "";
    html += `
      <a href="#" class="nav-item" data-section="${item.section}">
        <i class="bi ${item.icon}"></i>
        <span>${item.label}</span>
        ${badge}
      </a>`;
  });
  nav.innerHTML = html;
  // Mark dashboard active
  const first = nav.querySelector(".nav-item");
  if (first) first.classList.add("active");
}

// ── Stat cards ────────────────────────────────────────────────────────────────
function buildStatCards(cfg) {
  const grid = document.getElementById("statsGrid");
  grid.innerHTML = cfg.stats.map(key => {
    const s = STAT_DEFS[key];
    return `
      <div class="stat-card ${s.cls}">
        <div class="stat-icon"><i class="bi ${s.icon}"></i></div>
        <div class="stat-body">
          <div class="stat-value" id="${s.id}">—</div>
          <div class="stat-label">${s.label}</div>
        </div>
        <div class="stat-trend ${s.trendCls}">${s.trend}</div>
      </div>`;
  }).join("");
}

// ── Dashboard cards (role-specific) ──────────────────────────────────────────
async function loadDashboardCards(cfg, role) {
  const container = document.getElementById("dashCards");
  const greeting  = document.getElementById("dashGreeting");
  const subtitle  = document.getElementById("dashSubtitle");

  greeting.innerHTML = `<i class="bi bi-speedometer2 me-2"></i>${cfg.greeting}`;
  subtitle.textContent = cfg.subtitle;

  // Stat values — placeholders until weeks 2+
  if (document.getElementById("statTotal"))   document.getElementById("statTotal").textContent   = "0";
  if (document.getElementById("statAttacks")) document.getElementById("statAttacks").textContent = "0";
  if (document.getElementById("statNormal"))  document.getElementById("statNormal").textContent  = "0";
  if (document.getElementById("statAlerts"))  document.getElementById("statAlerts").textContent  = "0";
  if (document.getElementById("statModel"))   document.getElementById("statModel").textContent   = "RF v1.0";

  // Admin: users count
  if (role === "admin") {
    const users = await API.users();
    if (document.getElementById("statUsers"))
      document.getElementById("statUsers").textContent = users.length || "3";
    container.innerHTML = adminCards();
    return;
  }

  // Analyst
  if (role === "analyst") {
    container.innerHTML = analystCards();
    return;
  }

  // Viewer
  container.innerHTML = viewerCards();
}

// ── Admin cards ───────────────────────────────────────────────────────────────
function adminCards() {
  return `
    <!-- System Health -->
    <div class="col-lg-4">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Health
          <a href="#" class="card-link ms-auto" onclick="navigateTo('health');return false;">
            Full Details <i class="bi bi-arrow-right"></i>
          </a>
        </div>
        <div class="info-card-body" id="healthBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- My Profile -->
    <div class="col-lg-4">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-person-fill me-2 text-primary"></i>My Profile
        </div>
        <div class="info-card-body" id="profileBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="col-lg-4">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions
        </div>
        <div class="info-card-body">
          <button class="quick-action-btn" onclick="navigateTo('users')">
            <i class="bi bi-people-fill"></i>
            <div><strong>Manage Users</strong><small>Add, view, deactivate</small></div>
            <i class="bi bi-chevron-right ms-auto"></i>
          </button>
          <button class="quick-action-btn" onclick="navigateTo('health')">
            <i class="bi bi-heart-pulse-fill text-success"></i>
            <div><strong>System Health</strong><small>Full diagnostics</small></div>
            <i class="bi bi-chevron-right ms-auto"></i>
          </button>
          <button class="quick-action-btn" onclick="window.open('http://localhost:8000/docs','_blank')">
            <i class="bi bi-code-slash text-info"></i>
            <div><strong>API Docs</strong><small>Swagger UI</small></div>
            <i class="bi bi-box-arrow-up-right ms-auto"></i>
          </button>
        </div>
      </div>
    </div>

    <!-- Permissions Overview -->
    <div class="col-12 mt-1">
      <div class="info-card">
        <div class="info-card-header">
          <i class="bi bi-key-fill me-2 text-warning"></i>Your Permissions — Admin (Full Access)
        </div>
        <div class="info-card-body">
          <div class="permissions-grid">
            ${adminPerms()}
          </div>
        </div>
      </div>
    </div>`;
}

// ── Analyst cards ─────────────────────────────────────────────────────────────
function analystCards() {
  return `
    <!-- Status -->
    <div class="col-lg-6">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-heart-pulse-fill me-2 text-success"></i>API Status
        </div>
        <div class="info-card-body" id="healthBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- My Profile -->
    <div class="col-lg-6">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-person-badge-fill me-2" style="color:var(--primary)"></i>My Profile
        </div>
        <div class="info-card-body" id="profileBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="col-lg-6">
      <div class="info-card">
        <div class="info-card-header">
          <i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions
        </div>
        <div class="info-card-body">
          <button class="quick-action-btn" onclick="navigateTo('pcap')">
            <i class="bi bi-file-earmark-binary-fill text-primary"></i>
            <div><strong>Upload PCAP</strong><small>Analyse packet capture</small></div>
            <i class="bi bi-chevron-right ms-auto"></i>
          </button>
          <button class="quick-action-btn" onclick="navigateTo('live')">
            <i class="bi bi-broadcast text-success"></i>
            <div><strong>Live Capture</strong><small>Start real-time monitoring</small></div>
            <i class="bi bi-chevron-right ms-auto"></i>
          </button>
          <button class="quick-action-btn" onclick="navigateTo('alerts')">
            <i class="bi bi-bell-fill text-warning"></i>
            <div><strong>View Alerts</strong><small>Review security alerts</small></div>
            <i class="bi bi-chevron-right ms-auto"></i>
          </button>
        </div>
      </div>
    </div>

    <!-- Permissions -->
    <div class="col-lg-6">
      <div class="info-card">
        <div class="info-card-header">
          <i class="bi bi-key-fill me-2" style="color:var(--primary)"></i>Your Permissions — Analyst
        </div>
        <div class="info-card-body">
          <div class="permissions-grid">
            ${analystPerms()}
          </div>
        </div>
      </div>
    </div>`;
}

// ── Viewer cards ──────────────────────────────────────────────────────────────
function viewerCards() {
  return `
    <!-- Status -->
    <div class="col-lg-6">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Status
        </div>
        <div class="info-card-body" id="healthBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- My Profile -->
    <div class="col-lg-6">
      <div class="info-card h-100">
        <div class="info-card-header">
          <i class="bi bi-eye-fill me-2 text-success"></i>My Profile
        </div>
        <div class="info-card-body" id="profileBody"><div class="skeleton-row"></div></div>
      </div>
    </div>

    <!-- Read-only notice -->
    <div class="col-12">
      <div class="viewer-notice">
        <i class="bi bi-eye-fill"></i>
        <div>
          <strong>Read-Only Access</strong>
          <p>You have view-only access to this system. Contact your administrator to request elevated permissions.</p>
        </div>
      </div>
    </div>

    <!-- Permissions -->
    <div class="col-12">
      <div class="info-card">
        <div class="info-card-header">
          <i class="bi bi-key-fill me-2 text-success"></i>Your Permissions — Viewer
        </div>
        <div class="info-card-body">
          <div class="permissions-grid">
            ${viewerPerms()}
          </div>
        </div>
      </div>
    </div>`;
}

// ── Permission pill helpers ───────────────────────────────────────────────────
function perm(icon, label, allowed) {
  return `
    <div class="perm-item ${allowed ? 'allowed' : 'denied'}">
      <i class="bi ${allowed ? 'bi-check-circle-fill' : 'bi-x-circle-fill'}"></i>
      <i class="bi ${icon} perm-feat-icon"></i>
      <span>${label}</span>
    </div>`;
}
function adminPerms() {
  return [
    perm("bi-people-fill",            "Manage Users",       true),
    perm("bi-cpu-fill",               "Switch ML Model",    true),
    perm("bi-file-earmark-binary-fill","Upload PCAP",       true),
    perm("bi-broadcast",              "Live Capture",       true),
    perm("bi-bell-fill",              "Manage Alerts",      true),
    perm("bi-activity",               "View Predictions",   true),
    perm("bi-heart-pulse-fill",       "System Health",      true),
    perm("bi-gear-fill",              "System Settings",    true),
  ].join("");
}
function analystPerms() {
  return [
    perm("bi-people-fill",            "Manage Users",       false),
    perm("bi-cpu-fill",               "Switch ML Model",    true),
    perm("bi-file-earmark-binary-fill","Upload PCAP",       true),
    perm("bi-broadcast",              "Live Capture",       true),
    perm("bi-bell-fill",              "Acknowledge Alerts", true),
    perm("bi-activity",               "View Predictions",   true),
    perm("bi-heart-pulse-fill",       "System Health",      false),
    perm("bi-gear-fill",              "System Settings",    false),
  ].join("");
}
function viewerPerms() {
  return [
    perm("bi-people-fill",            "Manage Users",       false),
    perm("bi-cpu-fill",               "Switch ML Model",    false),
    perm("bi-file-earmark-binary-fill","Upload PCAP",       false),
    perm("bi-broadcast",              "Live Capture",       false),
    perm("bi-bell-fill",              "Acknowledge Alerts", false),
    perm("bi-activity",               "View Predictions",   true),
    perm("bi-heart-pulse-fill",       "System Health",      false),
    perm("bi-bar-chart-fill",         "View Reports",       true),
  ].join("");
}

// ── Render user info ──────────────────────────────────────────────────────────
function renderUserInfo(user) {
  document.getElementById("sidebarUsername").textContent = user.username;
  document.getElementById("sidebarRole").textContent     = user.role;
  document.getElementById("userAvatar").textContent      = user.username[0].toUpperCase();
  document.getElementById("topbarUsername").textContent  = user.username;

  const rb = document.getElementById("topbarRole");
  rb.textContent = user.role;
  rb.className   = `role-badge ${user.role}`;

  const profileBody = document.getElementById("profileBody");
  if (profileBody) {
    profileBody.innerHTML = `
      <div class="info-row">
        <span class="info-key">Username</span>
        <span class="info-val">${user.username}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Email</span>
        <span class="info-val">${user.email}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Role</span>
        <span class="info-val"><span class="role-pill ${user.role}">${user.role}</span></span>
      </div>
      <div class="info-row">
        <span class="info-key">Status</span>
        <span class="info-val"><span class="status-pill active">Active</span></span>
      </div>
      <div class="info-row">
        <span class="info-key">Member since</span>
        <span class="info-val">${new Date(user.created_at).toLocaleDateString("en-IN",{
          day:"2-digit",month:"short",year:"numeric"})}</span>
      </div>`;
  }
}

// ── API Health ────────────────────────────────────────────────────────────────
async function checkAPIHealth() {
  const data = await API.health();
  const dot  = document.getElementById("apiStatus");
  const healthHTML = data && data.status === "ok"
    ? `
      <div class="info-row">
        <span class="info-key"><span class="status-dot green d-inline-block me-2"></span>API Server</span>
        <span class="info-val text-success">Online</span>
      </div>
      <div class="info-row">
        <span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Database</span>
        <span class="info-val text-success">Connected</span>
      </div>
      <div class="info-row">
        <span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Auth Service</span>
        <span class="info-val text-success">Running</span>
      </div>
      <div class="info-row">
        <span class="info-key">Version</span>
        <span class="info-val">${data.version}</span>
      </div>`
    : `<div class="info-row"><span class="info-key text-danger">❌ API Unreachable</span></div>`;

  dot.innerHTML = data && data.status === "ok"
    ? `<span class="status-dot green"></span> Online`
    : `<span class="status-dot"></span> Offline`;

  document.querySelectorAll("#healthBody, #fullHealthBody").forEach(el => {
    if (el) el.innerHTML = healthHTML;
  });
}

// ── Navigation ────────────────────────────────────────────────────────────────
function setupNavigation(cfg) {
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault();
      navigateTo(item.dataset.section, cfg);
    });
  });
}

function navigateTo(section, cfg) {
  cfg = cfg || (ROLES[currentUser?.role] || ROLES.viewer);

  // Check access
  if (!cfg.allowedSections.includes(section)) {
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
    document.getElementById("section-denied").classList.add("active");
    document.getElementById("deniedMsg").textContent =
      `The "${section}" section requires higher privileges. Please contact your administrator.`;
    document.getElementById("pageTitle").textContent = "Access Denied";
    return;
  }

  // Update nav active state
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const activeNav = document.querySelector(`.nav-item[data-section="${section}"]`);
  if (activeNav) activeNav.classList.add("active");

  // Show section
  document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
  const target = document.getElementById(`section-${section}`);
  if (target) target.classList.add("active");

  // Page title
  const titles = {
    dashboard:"Dashboard", predictions:"Predictions", alerts:"Alerts",
    pcap:"PCAP Analysis", live:"Live Capture", reports:"Reports",
    users:"User Management", health:"System Health"
  };
  document.getElementById("pageTitle").textContent = titles[section] || section;

  // Load section data
  if (section === "users") loadUsers();
  if (section === "health") checkAPIHealth();
}

// ── Users table ───────────────────────────────────────────────────────────────
async function loadUsers() {
  const tbody = document.getElementById("usersTableBody");
  tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4">
    <div class="spinner-border text-primary spinner-border-sm"></div> Loading...
  </td></tr>`;

  const users = await API.users();
  if (!users || !users.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4 text-muted">No users found</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${u.id}</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="user-avatar" style="width:28px;height:28px;font-size:0.7rem;border-radius:6px">
            ${u.username[0].toUpperCase()}
          </div>
          <strong>${u.username}</strong>
          ${u.username === currentUser?.username
            ? '<span class="coming-badge" style="font-size:0.65rem;padding:2px 6px">You</span>' : ''}
        </div>
      </td>
      <td style="color:var(--text-muted)">${u.email || '—'}</td>
      <td><span class="role-pill ${u.role}">${u.role}</span></td>
      <td><span class="status-pill ${u.is_active ? 'active':'inactive'}">
        ${u.is_active ? 'Active':'Inactive'}
      </span></td>
      <td style="color:var(--text-muted);font-size:0.8rem">
        ${u.last_login ? new Date(u.last_login).toLocaleString("en-IN") : 'Never'}
      </td>
      <td>
        ${u.username !== currentUser?.username
          ? `<button class="btn-action" onclick="deactivateUser(${u.id},'${u.username}')">
               <i class="bi bi-person-dash me-1"></i>Deactivate
             </button>`
          : '<span style="color:var(--text-muted);font-size:0.8rem">—</span>'}
      </td>
    </tr>`).join("");
}

async function deactivateUser(id, username) {
  if (!confirm(`Deactivate user "${username}"?`)) return;
  const ok = await API.deactivateUser(id);
  if (ok) { showToast(`"${username}" deactivated`, "success"); loadUsers(); }
  else      showToast("Failed to deactivate", "error");
}

// ── Refresh ───────────────────────────────────────────────────────────────────
async function refreshData() {
  await checkAPIHealth();
  showToast("Refreshed", "success");
}

// ── Sidebar toggle ────────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb   = document.getElementById("sidebar");
  const main = document.getElementById("mainContent");
  if (window.innerWidth <= 768) { sb.classList.toggle("open"); }
  else { sb.classList.toggle("collapsed"); main.classList.toggle("expanded"); }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg, type = "success") {
  const el = document.getElementById("toastEl");
  document.getElementById("toastIcon").className =
    type === "success" ? "bi bi-check-circle-fill" : "bi bi-x-circle-fill";
  document.getElementById("toastMsg").textContent = msg;
  el.className = `ids-toast ${type}`;
  setTimeout(() => { el.className = "ids-toast d-none"; }, 3500);
}
