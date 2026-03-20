// js/dashboard.js
let currentUser = null;

const ROLES = {
  admin: {
    banner:   {label:"Administrator", icon:"bi-shield-fill",        cls:"banner-admin"},
    greeting: "Admin Control Panel",
    subtitle: "Full system access — manage users, models and all detections",
    nav: [
      {section:"dashboard",   icon:"bi-speedometer2",             label:"Dashboard"},
      {section:"predictions", icon:"bi-activity",                 label:"Predictions",  badge:"predBadge"},
      {section:"alerts",      icon:"bi-bell-fill",                label:"Alerts",       badge:"alertBadge", badgeCls:"danger"},
      {section:"pcap",        icon:"bi-file-earmark-binary-fill", label:"PCAP Analysis"},
      {section:"live",        icon:"bi-broadcast",                label:"Live Capture"},
      {separator:"ADMIN"},
      {section:"users",       icon:"bi-people-fill",              label:"Users"},
      {section:"requests",    icon:"bi-person-up",                label:"Access Requests", badge:"reqBadge", badgeCls:"danger"},
      {section:"health",      icon:"bi-heart-pulse-fill",         label:"System Health"},
      {separator:"ACCOUNT"},
      {section:"account",     icon:"bi-person-gear",              label:"My Account"},
    ],
    stats: ["total","attacks","normal","alerts","model","users"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","users","requests","health","account"]
  },
  analyst: {
    banner:   {label:"Analyst", icon:"bi-person-badge-fill", cls:"banner-analyst"},
    greeting: "Analyst Workstation",
    subtitle: "Detection analysis, PCAP uploads and alert management",
    nav: [
      {section:"dashboard",   icon:"bi-speedometer2",             label:"Dashboard"},
      {section:"predictions", icon:"bi-activity",                 label:"Predictions", badge:"predBadge"},
      {section:"alerts",      icon:"bi-bell-fill",                label:"Alerts",      badge:"alertBadge", badgeCls:"danger"},
      {section:"pcap",        icon:"bi-file-earmark-binary-fill", label:"PCAP Analysis"},
      {section:"live",        icon:"bi-broadcast",                label:"Live Capture"},
      {separator:"ACCOUNT"},
      {section:"account",     icon:"bi-person-gear",              label:"My Account"},
    ],
    stats: ["total","attacks","normal","alerts","model"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","account"]
  },
  viewer: {
    banner:   {label:"Viewer", icon:"bi-eye-fill", cls:"banner-viewer"},
    greeting: "Security Overview",
    subtitle: "Read-only access — view detections and summary reports",
    nav: [
      {section:"dashboard", icon:"bi-speedometer2",   label:"Dashboard"},
      {section:"reports",   icon:"bi-bar-chart-fill", label:"Reports"},
      {separator:"ACCOUNT"},
      {section:"account",   icon:"bi-person-gear",    label:"My Account"},
    ],
    stats: ["total","attacks","normal"],
    allowedSections: ["dashboard","reports","account"]
  }
};

const STAT_DEFS = {
  total:   {id:"statTotal",   icon:"bi-activity",           label:"Total Predictions", cls:"blue",   trend:"Live",      trendCls:"up"},
  attacks: {id:"statAttacks", icon:"bi-shield-exclamation", label:"Attacks Detected",  cls:"red",    trend:"Active",    trendCls:"up"},
  normal:  {id:"statNormal",  icon:"bi-check-circle-fill",  label:"Normal Traffic",    cls:"green",  trend:"Stable",    trendCls:""},
  alerts:  {id:"statAlerts",  icon:"bi-bell-fill",          label:"Active Alerts",     cls:"yellow", trend:"Review",    trendCls:"danger"},
  model:   {id:"statModel",   icon:"bi-cpu-fill",           label:"Active Model",      cls:"purple", trend:"85.9% Acc", trendCls:""},
  users:   {id:"statUsers",   icon:"bi-people-fill",        label:"Total Users",       cls:"teal",   trend:"Active",    trendCls:""},
};

// ══════════════════════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", async () => {
  try {
    if (!Auth.requireAuth()) return;

    console.log("[IDS-ML] API_BASE =", typeof API_BASE !== "undefined" ? API_BASE : "UNDEFINED");

    currentUser = await API.me();
    console.log("[IDS-ML] currentUser =", currentUser);

    if (!currentUser) {
      console.error("[IDS-ML] API.me() returned null — token may be expired or backend unreachable");
      document.body.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;height:100vh;
                    background:#0f1117;flex-direction:column;gap:16px">
          <div style="font-size:2rem">⚠️</div>
          <div style="color:#f87171;font-size:1.1rem;font-weight:600">Could not load user session</div>
          <div style="color:#94a3b8;font-size:.88rem">
            Backend: <code style="color:#60a5fa">${typeof API_BASE !== "undefined" ? API_BASE : "unknown"}</code>
          </div>
          <div style="color:#94a3b8;font-size:.85rem">Check that the backend is running on the correct port.</div>
          <a href="index.html" style="margin-top:8px;padding:10px 24px;background:#3b82f6;
             color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
            ← Back to Login
          </a>
        </div>`;
      return;
    }

    const role = currentUser.role;
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

  } catch(err) {
    console.error("[IDS-ML] Dashboard init error:", err);
    document.body.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100vh;
                  background:#0f1117;flex-direction:column;gap:16px;padding:24px">
        <div style="font-size:2rem">💥</div>
        <div style="color:#f87171;font-size:1.1rem;font-weight:600">Dashboard Error</div>
        <pre style="color:#fbbf24;background:#1e2330;padding:16px;border-radius:8px;
                    font-size:.78rem;max-width:700px;overflow:auto;white-space:pre-wrap">${err.stack || err.message}</pre>
        <a href="index.html" style="padding:10px 24px;background:#3b82f6;color:#fff;
           border-radius:8px;text-decoration:none;font-weight:600">← Back to Login</a>
      </div>`;
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// BUILDER FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════
function buildRoleBanner(cfg) {
  const b = cfg.banner;
  document.getElementById("roleBanner").innerHTML =
    `<div class="role-banner-inner ${b.cls}"><i class="bi ${b.icon}"></i><span>${b.label}</span></div>`;
}

function buildSidebar(cfg) {
  const nav = document.getElementById("sidebarNav");
  nav.innerHTML = cfg.nav.map(item => {
    if (item.separator) return `<div class="nav-section-label mt-3">${item.separator}</div>`;
    const badge = item.badge
      ? `<span class="nav-badge ${item.badgeCls||""}" id="${item.badge}">0</span>` : "";
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
  document.getElementById("sidebarUsername").textContent = user.display_name || user.username;
  document.getElementById("sidebarRole").textContent     = user.role;
  document.getElementById("userAvatar").textContent      = (user.display_name||user.username)[0].toUpperCase();
  document.getElementById("topbarUsername").textContent  = user.display_name || user.username;
  const rb = document.getElementById("topbarRole");
  rb.textContent = user.role; rb.className = `role-badge ${user.role}`;
}

function renderProfileCard(user) {
  const el = document.getElementById("profileBody"); if (!el) return;
  const name = user.display_name
    ? `${user.display_name} <span style="color:var(--text-muted);font-size:0.8rem">(${user.username})</span>`
    : user.username;
  el.innerHTML = `
    <div class="info-row"><span class="info-key">Name</span><span class="info-val">${name}</span></div>
    <div class="info-row"><span class="info-key">Email</span><span class="info-val">${user.email}</span></div>
    <div class="info-row"><span class="info-key">Role</span>
      <span class="info-val"><span class="role-pill ${user.role}">${user.role}</span></span></div>
    <div class="info-row"><span class="info-key">Status</span>
      <span class="info-val"><span class="status-pill active">Active</span></span></div>
    <div class="info-row"><span class="info-key">Member Since</span>
      <span class="info-val">${new Date(user.created_at).toLocaleDateString("en-IN",{day:"2-digit",month:"short",year:"numeric"})}</span></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
// API HEALTH
// ══════════════════════════════════════════════════════════════════════════════
async function checkAPIHealth() {
  const data = await API.health();
  const ok   = data && data.status === "ok";
  const dot  = document.getElementById("apiStatus");
  if (dot) dot.innerHTML = ok
    ? `<span class="status-dot green"></span> Online`
    : `<span class="status-dot"></span> Offline`;
  const html = ok ? `
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>API Server</span><span class="info-val text-success">Online</span></div>
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Database</span><span class="info-val text-success">Connected</span></div>
    <div class="info-row"><span class="info-key"><span class="status-dot green d-inline-block me-2"></span>Auth Service</span><span class="info-val text-success">Running</span></div>
    <div class="info-row"><span class="info-key">Version</span><span class="info-val">${data.version}</span></div>`
    : `<div class="info-row"><span class="info-key" style="color:var(--danger)">❌ API Unreachable</span></div>`;
  ["healthBody","fullHealthBody"].forEach(id => {
    const el = document.getElementById(id); if (el) el.innerHTML = html;
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// DASHBOARD CARDS
// ══════════════════════════════════════════════════════════════════════════════
const skeletons = `<div class="skeleton-row"></div><div class="skeleton-row"></div><div class="skeleton-row"></div>`;

async function loadDashboardCards(cfg, role) {
  document.getElementById("dashGreeting").innerHTML   = `<i class="bi bi-speedometer2 me-2"></i>${cfg.greeting}`;
  document.getElementById("dashSubtitle").textContent = cfg.subtitle;
  ["statTotal","statAttacks","statNormal","statAlerts"].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = "0";
  });
  const sm = document.getElementById("statModel"); if (sm) sm.textContent = "RF v1.0";
  if (role === "admin") {
    const users = await API.users();
    const su = document.getElementById("statUsers"); if (su) su.textContent = users.length || "3";
    document.getElementById("dashCards").innerHTML = adminCards();
  } else if (role === "analyst") {
    document.getElementById("dashCards").innerHTML = analystCards();
  } else {
    document.getElementById("dashCards").innerHTML = viewerCards();
  }
}

function adminCards() { return `
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Health
      <a href="#" class="card-link ms-auto" onclick="navigateTo('health');return false;">Full Details <i class="bi bi-arrow-right"></i></a>
    </div>
    <div class="info-card-body" id="healthBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-person-fill me-2 text-primary"></i>My Profile
      <a href="#" class="card-link ms-auto" onclick="navigateTo('account');return false;">Edit <i class="bi bi-pencil"></i></a>
    </div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions</div>
    <div class="info-card-body">
      <button class="quick-action-btn" onclick="navigateTo('users')">
        <i class="bi bi-people-fill text-danger"></i>
        <div><strong>Manage Users</strong><small>Roles, deactivate, delete</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
      <button class="quick-action-btn" onclick="navigateTo('requests')">
        <i class="bi bi-person-up text-warning"></i>
        <div><strong>Access Requests</strong><small>Review pending role upgrades</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
      <button class="quick-action-btn" onclick="navigateTo('account')">
        <i class="bi bi-person-gear text-info"></i>
        <div><strong>My Account</strong><small>Edit profile & password</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
    </div>
  </div></div>
  <div class="col-12 mt-1"><div class="info-card">
    <div class="info-card-header"><i class="bi bi-key-fill me-2 text-warning"></i>Your Permissions — Admin (Full Access)</div>
    <div class="info-card-body"><div class="permissions-grid">${adminPerms()}</div></div>
  </div></div>`; }

function analystCards() { return `
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-heart-pulse-fill me-2 text-success"></i>API Status</div>
    <div class="info-card-body" id="healthBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-person-badge-fill me-2" style="color:var(--primary)"></i>My Profile
      <a href="#" class="card-link ms-auto" onclick="navigateTo('account');return false;">Edit <i class="bi bi-pencil"></i></a>
    </div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-12"><div class="info-card">
    <div class="info-card-header"><i class="bi bi-key-fill me-2 text-primary"></i>Your Permissions — Analyst</div>
    <div class="info-card-body"><div class="permissions-grid">${analystPerms()}</div></div>
  </div></div>`; }

function viewerCards() { return `
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Status</div>
    <div class="info-card-body" id="healthBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-eye-fill me-2 text-success"></i>My Profile
      <a href="#" class="card-link ms-auto" onclick="navigateTo('account');return false;">Edit <i class="bi bi-pencil"></i></a>
    </div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-12">
    <div class="viewer-notice">
      <i class="bi bi-eye-fill"></i>
      <div><strong>Read-Only Access</strong>
        <p>You have view-only access. Use <strong>My Account → Request Access</strong> to request elevated permissions.</p>
      </div>
    </div>
  </div>`; }

// ── Permissions ───────────────────────────────────────────────────────────────
function perm(icon, label, allowed) {
  return `<div class="perm-item ${allowed?'allowed':'denied'}">
    <i class="bi ${allowed?'bi-check-circle-fill':'bi-x-circle-fill'}"></i>
    <i class="bi ${icon} perm-feat-icon"></i><span>${label}</span>
  </div>`;
}
function adminPerms()  { return [
  perm("bi-people-fill","Manage Users",true), perm("bi-cpu-fill","Switch ML Model",true),
  perm("bi-file-earmark-binary-fill","Upload PCAP",true), perm("bi-broadcast","Live Capture",true),
  perm("bi-bell-fill","Manage Alerts",true), perm("bi-activity","View Predictions",true),
  perm("bi-person-up","Role Requests",true), perm("bi-gear-fill","System Settings",true),
].join(""); }
function analystPerms(){ return [
  perm("bi-people-fill","Manage Users",false), perm("bi-cpu-fill","Switch ML Model",true),
  perm("bi-file-earmark-binary-fill","Upload PCAP",true), perm("bi-broadcast","Live Capture",true),
  perm("bi-bell-fill","Acknowledge Alerts",true), perm("bi-activity","View Predictions",true),
  perm("bi-person-up","Role Requests",false), perm("bi-gear-fill","System Settings",false),
].join(""); }
function viewerPerms() { return [
  perm("bi-people-fill","Manage Users",false), perm("bi-cpu-fill","Switch ML Model",false),
  perm("bi-file-earmark-binary-fill","Upload PCAP",false), perm("bi-broadcast","Live Capture",false),
  perm("bi-bell-fill","Manage Alerts",false), perm("bi-activity","View Predictions",true),
  perm("bi-person-up","Request Access",true), perm("bi-bar-chart-fill","View Reports",true),
].join(""); }

// ══════════════════════════════════════════════════════════════════════════════
// NAVIGATION  ← ONLY CHANGE: added pcap hook on line marked below
// ══════════════════════════════════════════════════════════════════════════════
function setupNavigation(cfg) {
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault(); navigateTo(item.dataset.section, cfg);
    });
  });
}

function navigateTo(section, cfg) {
  cfg = cfg || ROLES[currentUser?.role] || ROLES.viewer;
  if (!cfg.allowedSections.includes(section)) {
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
    const d = document.getElementById("section-denied"); if (d) d.classList.add("active");
    const m = document.getElementById("deniedMsg");
    if (m) m.textContent = `The "${section}" section requires higher privileges.`;
    document.getElementById("pageTitle").textContent = "Access Denied";
    return;
  }
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const an = document.querySelector(`.nav-item[data-section="${section}"]`);
  if (an) an.classList.add("active");
  document.querySelectorAll(".content-section").forEach(s => s.classList.remove("active"));
  const t = document.getElementById(`section-${section}`); if (t) t.classList.add("active");
  const titles = {
    dashboard:"Dashboard", predictions:"Predictions", alerts:"Alerts",
    pcap:"PCAP Analysis", live:"Live Capture", reports:"Reports",
    users:"User Management", requests:"Access Requests",
    health:"System Health", account:"My Account"
  };
  document.getElementById("pageTitle").textContent = titles[section] || section;
  if (section === "users")    loadUsers();
  if (section === "requests") { loadRoleRequests("pending"); loadPasswordResets(); }
  if (section === "health")   checkAPIHealth();
  if (section === "account")  initAccountSection(currentUser);
  if (section === "pcap")     { if (typeof loadPcapHistory === "function") loadPcapHistory(); } // ← NEW
}

// ══════════════════════════════════════════════════════════════════════════════
// USERS TABLE
// ══════════════════════════════════════════════════════════════════════════════
async function loadUsers() {
  const tbody = document.getElementById("usersTableBody"); if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4">
    <div class="spinner-border text-primary spinner-border-sm"></div> Loading users...
  </td></tr>`;
  const users = await API.users();
  const badge = document.getElementById("userCountBadge");
  if (badge) badge.textContent = `${users.length} users`;
  if (!users.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4 text-muted">No users found</td></tr>`;
    return;
  }
  tbody.innerHTML = users.map(u => {
    const isMe = u.username === currentUser?.username;
    return `<tr id="user-row-${u.id}">
      <td style="color:var(--text-muted);font-size:0.8rem">#${u.id}</td>
      <td>
        <div style="display:flex;align-items:center;gap:9px">
          <div class="user-avatar" style="width:32px;height:32px;font-size:0.8rem;border-radius:8px;flex-shrink:0">
            ${(u.display_name||u.username)[0].toUpperCase()}
          </div>
          <div>
            <div style="font-weight:700;color:var(--text-main)">${u.display_name||u.username}
              ${isMe ? '<span class="coming-badge" style="font-size:0.62rem;padding:1px 6px;margin-left:4px">You</span>' : ""}
            </div>
            <div style="font-size:0.72rem;color:var(--text-muted)">${u.email||"—"}</div>
          </div>
        </div>
      </td>
      <td><span class="role-pill ${u.role}">${u.role}</span></td>
      <td><span class="status-pill ${u.is_active?"active":"inactive"}">${u.is_active?"Active":"Inactive"}</span></td>
      <td style="color:var(--text-muted);font-size:0.78rem">
        ${u.created_at ? new Date(u.created_at).toLocaleDateString("en-IN",{day:"2-digit",month:"short",year:"numeric"}) : "—"}
      </td>
      <td style="color:var(--text-muted);font-size:0.78rem">
        ${u.last_login ? new Date(u.last_login).toLocaleString("en-IN") : "Never"}
      </td>
      <td>
        ${isMe
          ? `<span style="color:var(--text-muted);font-size:0.78rem">— (your account)</span>`
          : `<div class="user-actions">
              <button class="btn-sm-action role" onclick="openRoleModal(${u.id},'${u.username}','${u.role}')">
                <i class="bi bi-arrow-repeat"></i>Role
              </button>
              ${u.is_active
                ? `<button class="btn-sm-action deact" onclick="toggleActive(${u.id},'${u.username}',false)"><i class="bi bi-pause-circle"></i>Deactivate</button>`
                : `<button class="btn-sm-action act"   onclick="toggleActive(${u.id},'${u.username}',true)"><i class="bi bi-play-circle"></i>Activate</button>`}
              <button class="btn-sm-action pwd" onclick="openPwdModal(${u.id},'${u.username}')">
                <i class="bi bi-key"></i>Password
              </button>
              <button class="btn-sm-action del" onclick="openDeleteModal(${u.id},'${u.username}')">
                <i class="bi bi-trash3"></i>Delete
              </button>
             </div>`}
      </td>
    </tr>`;
  }).join("");
}

// ══════════════════════════════════════════════════════════════════════════════
// ROLE REQUESTS (admin)
// ══════════════════════════════════════════════════════════════════════════════
let reqFilter = "pending";

async function loadPendingReqBadge() {
  const reqs  = await API.getRoleRequests("pending");
  const badge = document.getElementById("reqBadge");
  if (!badge) return;
  badge.textContent = reqs.length;
  badge.style.display = reqs.length > 0 ? "" : "none";
}

async function loadRoleRequests(status = "pending") {
  reqFilter = status;
  document.querySelectorAll(".req-filter-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.status === status);
  });

  const list = document.getElementById("reqList"); if (!list) return;
  list.innerHTML = `<div style="text-align:center;padding:24px">
    <div class="spinner-border text-primary spinner-border-sm"></div> Loading...
  </div>`;

  const reqs = await API.getRoleRequests(status);
  if (!reqs.length) {
    list.innerHTML = `<div id="reqListEmpty">
      <i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:8px;opacity:.4"></i>
      No ${status} access requests
    </div>`;
    return;
  }

  list.innerHTML = reqs.map(r => {
    const isPending = r.status === "pending";
    const timeAgo   = timeSince(r.created_at);
    return `<div class="req-card ${r.status}" id="req-card-${r.id}">
      <div class="req-card-top">
        <div class="req-card-user">
          <div class="req-avatar">${r.username[0].toUpperCase()}</div>
          <div>
            <div class="req-card-uname">${r.username}</div>
            <div class="req-card-meta">${timeAgo} ago · Request #${r.id}</div>
          </div>
        </div>
        <span class="req-badge ${r.status}">
          <i class="bi ${r.status==="pending"?"bi-hourglass-split":r.status==="approved"?"bi-check-circle-fill":"bi-x-circle-fill"}"></i>
          ${r.status.charAt(0).toUpperCase()+r.status.slice(1)}
        </span>
      </div>
      <div class="req-card-body">
        <div class="req-role-arrow">
          <span class="from"><span class="role-pill ${r.current_role}" style="font-size:0.72rem">${r.current_role}</span></span>
          <span class="arr"><i class="bi bi-arrow-right"></i></span>
          <span class="to"><span class="role-pill ${r.requested_role}" style="font-size:0.72rem">${r.requested_role}</span></span>
        </div>
      </div>
      ${r.reason ? `<div class="req-reason-box">${r.reason}</div>` : ""}
      <div class="req-card-actions">
        ${isPending ? `
          <button class="btn-approve" onclick="reviewRequest(${r.id},'approve')">
            <i class="bi bi-check-lg"></i>Approve
          </button>
          <button class="btn-reject" onclick="reviewRequest(${r.id},'reject')">
            <i class="bi bi-x-lg"></i>Reject
          </button>` : `
          <span class="req-reviewed-by">
            <i class="bi bi-person-check me-1"></i>Reviewed by ${r.reviewed_by}
          </span>`}
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
    showToast(result.data.message, "success");
    loadRoleRequests(reqFilter);
    loadPendingReqBadge();
    const me = await API.me();
    if (me) { currentUser = me; renderTopbarUser(currentUser); }
  } else {
    showToast(result.data?.detail || "Action failed", "error");
    if (btns) btns.forEach(b => b.disabled = false);
  }
}

function timeSince(dateStr) {
  const s = Math.floor((Date.now() - new Date(dateStr)) / 1000);
  if (s < 60)    return `${s}s`;
  if (s < 3600)  return `${Math.floor(s/60)}m`;
  if (s < 86400) return `${Math.floor(s/3600)}h`;
  return `${Math.floor(s/86400)}d`;
}

// ══════════════════════════════════════════════════════════════════════════════
// SHARED MODALS
// ══════════════════════════════════════════════════════════════════════════════
function closeModal() {
  const m = document.getElementById("idsModal"); if (m) m.remove();
}
function openModal(html) {
  closeModal();
  const overlay = document.createElement("div");
  overlay.id = "idsModal"; overlay.className = "ids-modal-overlay";
  overlay.innerHTML = `<div class="ids-modal">${html}</div>`;
  overlay.addEventListener("click", e => { if (e.target === overlay) closeModal(); });
  document.body.appendChild(overlay);
}

function openAddUserModal() {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-person-plus-fill me-2 text-primary"></i>Add New User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div class="input-group-custom"><label class="form-label-custom">Username</label>
      <input id="m_username" class="form-input-custom" placeholder="Enter username"/></div>
    <div class="input-group-custom"><label class="form-label-custom">Email</label>
      <input id="m_email" type="email" class="form-input-custom" placeholder="user@example.com"/></div>
    <div class="input-group-custom"><label class="form-label-custom">Password</label>
      <input id="m_password" type="password" class="form-input-custom" placeholder="Min. 6 characters"/></div>
    <div class="input-group-custom"><label class="form-label-custom">Role</label>
      <select id="m_role" class="ids-select">
        <option value="viewer">Viewer — Read-only</option>
        <option value="analyst">Analyst — Detection + PCAP</option>
        <option value="admin">Admin — Full access</option>
      </select></div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitAddUser()"><i class="bi bi-person-check me-1"></i>Create User</button>
    </div>`);
}

async function submitAddUser() {
  const username = document.getElementById("m_username").value.trim();
  const email    = document.getElementById("m_email").value.trim();
  const password = document.getElementById("m_password").value;
  const role     = document.getElementById("m_role").value;
  if (!username || !email || !password) return modalAlert("All fields are required.", "error");
  const result = await API.createUser(username, email, password, role);
  if (result.ok) { closeModal(); showToast(`User "${username}" created as ${role}!`, "success"); loadUsers(); }
  else modalAlert(result.data?.detail || "Failed to create user.", "error");
}

function openRoleModal(userId, username, currentRole) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-arrow-repeat me-2" style="color:var(--primary)"></i>Change Role</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:14px">
      Update role for <strong style="color:var(--text-main)">${username}</strong>
    </p>
    <div class="input-group-custom"><label class="form-label-custom">New Role</label>
      <select id="m_newRole" class="ids-select">
        <option value="viewer"  ${currentRole==="viewer"  ?"selected":""}>Viewer</option>
        <option value="analyst" ${currentRole==="analyst" ?"selected":""}>Analyst</option>
        <option value="admin"   ${currentRole==="admin"   ?"selected":""}>Admin</option>
      </select></div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitRoleChange(${userId},'${username}')"><i class="bi bi-check2 me-1"></i>Update Role</button>
    </div>`);
}

async function submitRoleChange(userId, username) {
  const role = document.getElementById("m_newRole").value;
  const result = await API.changeRole(userId, role);
  if (result.ok) { closeModal(); showToast(`"${username}" is now ${role}`, "success"); loadUsers(); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

function openPwdModal(userId, username) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-key-fill me-2 text-warning"></i>Reset Password</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:14px">
      Set a new password for <strong style="color:var(--text-main)">${username}</strong>
    </p>
    <div class="input-group-custom"><label class="form-label-custom">New Password</label>
      <input id="m_newPwd" type="password" class="form-input-custom" placeholder="Min. 6 characters"/></div>
    <div class="input-group-custom"><label class="form-label-custom">Confirm Password</label>
      <input id="m_confirmPwd" type="password" class="form-input-custom" placeholder="Repeat password"/></div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitResetPwd(${userId},'${username}')"><i class="bi bi-check2 me-1"></i>Reset</button>
    </div>`);
}

async function submitResetPwd(userId, username) {
  const pwd1 = document.getElementById("m_newPwd").value;
  const pwd2 = document.getElementById("m_confirmPwd").value;
  if (pwd1.length < 6) return modalAlert("Password must be at least 6 characters.", "error");
  if (pwd1 !== pwd2)   return modalAlert("Passwords do not match.", "error");
  const result = await API.resetPassword(userId, pwd1);
  if (result.ok) { closeModal(); showToast(`Password reset for "${username}"`, "success"); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

function openDeleteModal(userId, username) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-trash3-fill me-2 text-danger"></i>Delete User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div style="text-align:center;padding:10px 0 20px">
      <div style="font-size:2.5rem;margin-bottom:12px">⚠️</div>
      <p style="font-weight:700;font-size:1rem;color:var(--text-main)">
        Permanently delete <span style="color:var(--danger)">"${username}"</span>?
      </p>
      <p style="color:var(--text-muted);font-size:0.85rem">This cannot be undone.</p>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-danger" onclick="submitDelete(${userId},'${username}')">
        <i class="bi bi-trash3 me-1"></i>Delete Permanently
      </button>
    </div>`);
}

async function submitDelete(userId, username) {
  const result = await API.deleteUser(userId);
  if (result.ok) { closeModal(); showToast(`"${username}" deleted`, "success"); loadUsers(); }
  else modalAlert(result.data?.detail || "Failed.", "error");
}

async function toggleActive(userId, username, activate) {
  const ok = activate ? await API.activateUser(userId) : await API.deactivateUser(userId);
  if (ok) { showToast(`"${username}" ${activate?"activated":"deactivated"}`, "success"); loadUsers(); }
  else showToast("Action failed", "error");
}

function modalAlert(msg, type) {
  const el = document.getElementById("modalAlert"); if (!el) return;
  el.textContent = msg; el.className = `alert-area ${type}`;
}

// ══════════════════════════════════════════════════════════════════════════════
// MISC
// ══════════════════════════════════════════════════════════════════════════════
function toggleSidebar() {
  const sb   = document.getElementById("sidebar");
  const main = document.getElementById("mainContent");
  if (window.innerWidth <= 768) sb.classList.toggle("open");
  else { sb.classList.toggle("collapsed"); main.classList.toggle("expanded"); }
}

async function refreshData() {
  await checkAPIHealth();
  renderProfileCard(currentUser);
  showToast("Refreshed", "success");
}

function showToast(msg, type = "success") {
  const el = document.getElementById("toastEl"); if (!el) return;
  document.getElementById("toastIcon").className =
    type === "success" ? "bi bi-check-circle-fill" : "bi bi-x-circle-fill";
  document.getElementById("toastMsg").textContent = msg;
  el.className = `ids-toast ${type}`;
  setTimeout(() => { el.className = "ids-toast d-none"; }, 3500);
}

// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD RESET REQUESTS (admin)
// ══════════════════════════════════════════════════════════════════════════════
let _pendingResolveId = null;

async function loadPasswordResets() {
  const wrap  = document.getElementById("pwdResetTable");
  const badge = document.getElementById("pwdResetBadge");
  if (!wrap) return;

  let res;
  try {
    res = await API.getPasswordResets();
  } catch(e) {
    wrap.innerHTML = `<p style="color:#f87171;padding:12px"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${e.message}</p>`;
    return;
  }
  if (!res) {
    wrap.innerHTML = `<p style="color:#f87171;padding:12px"><i class="bi bi-exclamation-triangle me-2"></i>Could not reach server. Check backend is running.</p>`;
    return;
  }
  if (!res.ok) {
    let errMsg = "Request failed";
    try { const d = await res.json(); errMsg = d.detail || errMsg; } catch {}
    wrap.innerHTML = `<p style="color:#f87171;padding:12px"><i class="bi bi-exclamation-triangle me-2"></i>${res.status}: ${errMsg}</p>`;
    return;
  }
  const reqs    = await res.json();
  const pending = reqs.filter(r => r.status === "pending");

  if (badge) {
    badge.textContent   = pending.length;
    badge.style.display = pending.length > 0 ? "inline-block" : "none";
  }

  if (reqs.length === 0) {
    wrap.innerHTML = `<p style="color:var(--text-muted);padding:12px;font-size:.88rem">
      <i class="bi bi-check-circle me-2 text-success"></i>No password reset requests.</p>`;
    return;
  }

  const rows = reqs.map(r => `
    <tr class="req-row ${r.status}">
      <td><strong>${r.username}</strong><br>
          <span style="color:var(--text-muted);font-size:.78rem">${r.email}</span></td>
      <td style="font-size:.82rem;color:var(--text-muted)">${r.reason || "—"}</td>
      <td><span class="req-pill ${r.status}">${r.status}</span></td>
      <td style="font-size:.78rem;color:var(--text-muted)">
        ${new Date(r.created_at).toLocaleString("en-IN")}</td>
      <td>
        ${r.status === "pending" ? `
          <button class="btn-action approve"
            onclick="openResolveModal(${r.id},'${r.username}')">
            <i class="bi bi-key-fill me-1"></i>Set Password
          </button>
          <button class="btn-action reject"
            onclick="dismissReset(${r.id})">
            Dismiss
          </button>` : `
          <span style="color:var(--text-muted);font-size:.78rem">
            ${r.resolved_by ? `By ${r.resolved_by}` : "—"}
          </span>`}
      </td>
    </tr>`).join("");

  wrap.innerHTML = `
    <table class="requests-table">
      <thead><tr>
        <th>User</th><th>Reason</th><th>Status</th><th>Requested</th><th>Action</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function openResolveModal(id, username) {
  _pendingResolveId = id;
  document.getElementById("resolveModalUser").textContent = `Setting new password for: ${username}`;
  document.getElementById("resolvePwd").value = "";
  document.getElementById("resolveAlert").style.display = "none";
  const m = document.getElementById("resolveModal");
  m.style.display = "flex";
  setTimeout(() => document.getElementById("resolvePwd").focus(), 100);
}

function closeResolveModal() {
  document.getElementById("resolveModal").style.display = "none";
  _pendingResolveId = null;
}

async function confirmResolve() {
  const pwd     = document.getElementById("resolvePwd").value;
  const alertEl = document.getElementById("resolveAlert");
  const btn     = document.getElementById("resolveBtn");

  if (!pwd || pwd.length < 6) {
    alertEl.textContent = "Password must be at least 6 characters.";
    alertEl.style.cssText = "display:block;background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3);padding:8px 12px;border-radius:7px;font-size:.82rem";
    return;
  }

  btn.disabled = true; btn.textContent = "⏳ Saving...";
  const res = await API.resolvePasswordReset(_pendingResolveId, pwd);
  if (res && res.ok) {
    closeResolveModal();
    await loadPasswordResets();
  } else {
    const d = await res?.json().catch(() => ({}));
    alertEl.textContent = d?.detail || "Failed to set password.";
    alertEl.style.cssText = "display:block;background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3);padding:8px 12px;border-radius:7px;font-size:.82rem";
    btn.disabled = false; btn.textContent = "✅ Set Password & Resolve";
  }
}

async function dismissReset(id) {
  if (!confirm("Dismiss this reset request?")) return;
  await API.dismissPasswordReset(id);
  await loadPasswordResets();
}
