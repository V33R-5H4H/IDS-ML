// js/dashboard.js — Role-based dashboard (API_BASE from auth.js)

let currentUser = null;

// ── Role Definitions ──────────────────────────────────────────────────────────
const ROLES = {
  admin: {
    banner:   { label:"Administrator", icon:"bi-shield-fill",        cls:"banner-admin"   },
    greeting: "Admin Control Panel",
    subtitle: "Full system access — manage users, models and all detections",
    nav: [
      { section:"dashboard",   icon:"bi-speedometer2",             label:"Dashboard"                          },
      { section:"predictions", icon:"bi-activity",                 label:"Predictions",  badge:"predBadge"   },
      { section:"alerts",      icon:"bi-bell-fill",                label:"Alerts",       badge:"alertBadge", badgeCls:"danger" },
      { section:"pcap",        icon:"bi-file-earmark-binary-fill", label:"PCAP Analysis"                     },
      { section:"live",        icon:"bi-broadcast",                label:"Live Capture"                      },
      { separator:"ADMIN" },
      { section:"users",       icon:"bi-people-fill",              label:"Users"                             },
      { section:"health",      icon:"bi-heart-pulse-fill",         label:"System Health"                     },
    ],
    stats: ["total","attacks","normal","alerts","model","users"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live","users","health"]
  },
  analyst: {
    banner:   { label:"Analyst",  icon:"bi-person-badge-fill", cls:"banner-analyst" },
    greeting: "Analyst Workstation",
    subtitle: "Detection analysis, PCAP uploads and alert management",
    nav: [
      { section:"dashboard",   icon:"bi-speedometer2",             label:"Dashboard"                         },
      { section:"predictions", icon:"bi-activity",                 label:"Predictions", badge:"predBadge"   },
      { section:"alerts",      icon:"bi-bell-fill",                label:"Alerts",      badge:"alertBadge", badgeCls:"danger" },
      { section:"pcap",        icon:"bi-file-earmark-binary-fill", label:"PCAP Analysis"                    },
      { section:"live",        icon:"bi-broadcast",                label:"Live Capture"                     },
    ],
    stats: ["total","attacks","normal","alerts","model"],
    allowedSections: ["dashboard","predictions","alerts","pcap","live"]
  },
  viewer: {
    banner:   { label:"Viewer",   icon:"bi-eye-fill",          cls:"banner-viewer"  },
    greeting: "Security Overview",
    subtitle: "Read-only access — view detections and summary reports",
    nav: [
      { section:"dashboard", icon:"bi-speedometer2",   label:"Dashboard" },
      { section:"reports",   icon:"bi-bar-chart-fill", label:"Reports"   },
    ],
    stats: ["total","attacks","normal"],
    allowedSections: ["dashboard","reports"]
  }
};

const STAT_DEFS = {
  total:   { id:"statTotal",   icon:"bi-activity",           label:"Total Predictions", cls:"blue",   trend:"Live",      trendCls:"up"    },
  attacks: { id:"statAttacks", icon:"bi-shield-exclamation", label:"Attacks Detected",  cls:"red",    trend:"Active",    trendCls:"up"    },
  normal:  { id:"statNormal",  icon:"bi-check-circle-fill",  label:"Normal Traffic",    cls:"green",  trend:"Stable",    trendCls:""      },
  alerts:  { id:"statAlerts",  icon:"bi-bell-fill",          label:"Active Alerts",     cls:"yellow", trend:"Review",    trendCls:"danger"},
  model:   { id:"statModel",   icon:"bi-cpu-fill",           label:"Active Model",      cls:"purple", trend:"85.9% Acc", trendCls:""      },
  users:   { id:"statUsers",   icon:"bi-people-fill",        label:"Total Users",       cls:"teal",   trend:"Active",    trendCls:""      },
};

// ══════════════════════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", async () => {
  if (!Auth.requireAuth()) return;
  currentUser = await API.me();
  if (!currentUser) { logout(); return; }

  const role = currentUser.role;
  const cfg  = ROLES[role] || ROLES.viewer;

  buildRoleBanner(cfg);
  buildSidebar(cfg);
  buildStatCards(cfg);
  renderTopbarUser(currentUser);
  setupNavigation(cfg);

  // Cards HTML first, then fill data
  await loadDashboardCards(cfg, role);
  renderProfileCard(currentUser);
  await checkAPIHealth();
});

// ══════════════════════════════════════════════════════════════════════════════
// BUILD FUNCTIONS
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
  document.getElementById("sidebarUsername").textContent = user.username;
  document.getElementById("sidebarRole").textContent     = user.role;
  document.getElementById("userAvatar").textContent      = user.username[0].toUpperCase();
  document.getElementById("topbarUsername").textContent  = user.username;
  const rb = document.getElementById("topbarRole");
  rb.textContent = user.role; rb.className = `role-badge ${user.role}`;
}

function renderProfileCard(user) {
  const el = document.getElementById("profileBody");
  if (!el) return;
  el.innerHTML = `
    <div class="info-row"><span class="info-key">Username</span><span class="info-val">${user.username}</span></div>
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
  const dot  = document.getElementById("apiStatus");
  const ok   = data && data.status === "ok";
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
// DASHBOARD CARDS (role-specific)
// ══════════════════════════════════════════════════════════════════════════════
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

// ── Card HTML templates ───────────────────────────────────────────────────────
const skeletons = `<div class="skeleton-row"></div><div class="skeleton-row"></div><div class="skeleton-row"></div>`;

function adminCards() { return `
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Health
      <a href="#" class="card-link ms-auto" onclick="navigateTo('health');return false;">Full Details <i class="bi bi-arrow-right"></i></a>
    </div>
    <div class="info-card-body" id="healthBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-person-fill me-2 text-primary"></i>My Profile</div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-4"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions</div>
    <div class="info-card-body">
      <button class="quick-action-btn" onclick="navigateTo('users')">
        <i class="bi bi-people-fill text-danger"></i>
        <div><strong>Manage Users</strong><small>Add, roles, deactivate, delete</small></div>
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
    <div class="info-card-header"><i class="bi bi-person-badge-fill me-2" style="color:var(--primary)"></i>My Profile</div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-6"><div class="info-card">
    <div class="info-card-header"><i class="bi bi-lightning-fill me-2 text-warning"></i>Quick Actions</div>
    <div class="info-card-body">
      <button class="quick-action-btn" onclick="navigateTo('pcap')">
        <i class="bi bi-file-earmark-binary-fill text-primary"></i>
        <div><strong>Upload PCAP</strong><small>Analyse packet capture</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
      <button class="quick-action-btn" onclick="navigateTo('live')">
        <i class="bi bi-broadcast text-success"></i>
        <div><strong>Live Capture</strong><small>Real-time monitoring</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
      <button class="quick-action-btn" onclick="navigateTo('alerts')">
        <i class="bi bi-bell-fill text-warning"></i>
        <div><strong>View Alerts</strong><small>Review security alerts</small></div>
        <i class="bi bi-chevron-right ms-auto"></i>
      </button>
    </div>
  </div></div>
  <div class="col-lg-6"><div class="info-card">
    <div class="info-card-header"><i class="bi bi-key-fill me-2" style="color:var(--primary)"></i>Your Permissions — Analyst</div>
    <div class="info-card-body"><div class="permissions-grid">${analystPerms()}</div></div>
  </div></div>`; }

function viewerCards() { return `
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-heart-pulse-fill me-2 text-success"></i>System Status</div>
    <div class="info-card-body" id="healthBody">${skeletons}</div>
  </div></div>
  <div class="col-lg-6"><div class="info-card h-100">
    <div class="info-card-header"><i class="bi bi-eye-fill me-2 text-success"></i>My Profile</div>
    <div class="info-card-body" id="profileBody">${skeletons}</div>
  </div></div>
  <div class="col-12">
    <div class="viewer-notice">
      <i class="bi bi-eye-fill"></i>
      <div><strong>Read-Only Access</strong>
        <p>You have view-only access. Contact your administrator to request elevated permissions.</p>
      </div>
    </div>
  </div>
  <div class="col-12"><div class="info-card">
    <div class="info-card-header"><i class="bi bi-key-fill me-2 text-success"></i>Your Permissions — Viewer</div>
    <div class="info-card-body"><div class="permissions-grid">${viewerPerms()}</div></div>
  </div></div>`; }

// ── Permission pills ──────────────────────────────────────────────────────────
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
  perm("bi-heart-pulse-fill","System Health",true), perm("bi-gear-fill","System Settings",true),
].join(""); }
function analystPerms(){ return [
  perm("bi-people-fill","Manage Users",false), perm("bi-cpu-fill","Switch ML Model",true),
  perm("bi-file-earmark-binary-fill","Upload PCAP",true), perm("bi-broadcast","Live Capture",true),
  perm("bi-bell-fill","Acknowledge Alerts",true), perm("bi-activity","View Predictions",true),
  perm("bi-heart-pulse-fill","System Health",false), perm("bi-gear-fill","System Settings",false),
].join(""); }
function viewerPerms() { return [
  perm("bi-people-fill","Manage Users",false), perm("bi-cpu-fill","Switch ML Model",false),
  perm("bi-file-earmark-binary-fill","Upload PCAP",false), perm("bi-broadcast","Live Capture",false),
  perm("bi-bell-fill","Acknowledge Alerts",false), perm("bi-activity","View Predictions",true),
  perm("bi-heart-pulse-fill","System Health",false), perm("bi-bar-chart-fill","View Reports",true),
].join(""); }

// ══════════════════════════════════════════════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════════════════════════════════════════════
function setupNavigation(cfg) {
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", e => { e.preventDefault(); navigateTo(item.dataset.section, cfg); });
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
  const titles = {dashboard:"Dashboard",predictions:"Predictions",alerts:"Alerts",
    pcap:"PCAP Analysis",live:"Live Capture",reports:"Reports",
    users:"User Management",health:"System Health"};
  document.getElementById("pageTitle").textContent = titles[section] || section;
  if (section === "users")  loadUsers();
  if (section === "health") checkAPIHealth();
}

// ══════════════════════════════════════════════════════════════════════════════
// USERS TABLE (full admin management)
// ══════════════════════════════════════════════════════════════════════════════
async function loadUsers() {
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;
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
            ${u.username[0].toUpperCase()}
          </div>
          <div>
            <div style="font-weight:700;color:var(--text-main)">${u.username}
              ${isMe ? '<span class="coming-badge" style="font-size:0.62rem;padding:1px 6px;margin-left:4px">You</span>' : ""}
            </div>
            <div style="font-size:0.72rem;color:var(--text-muted)">${u.email || "—"}</div>
          </div>
        </div>
      </td>
      <td><span class="role-pill ${u.role}">${u.role}</span></td>
      <td>
        <span class="status-pill ${u.is_active ? "active":"inactive"}">
          ${u.is_active ? "Active" : "Inactive"}
        </span>
      </td>
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
                ? `<button class="btn-sm-action deact" onclick="toggleActive(${u.id},'${u.username}',false)">
                     <i class="bi bi-pause-circle"></i>Deactivate
                   </button>`
                : `<button class="btn-sm-action act" onclick="toggleActive(${u.id},'${u.username}',true)">
                     <i class="bi bi-play-circle"></i>Activate
                   </button>`}
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
// MODALS
// ══════════════════════════════════════════════════════════════════════════════
function closeModal() {
  const m = document.getElementById("idsModal"); if (m) m.remove();
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

// ── Add User Modal ────────────────────────────────────────────────────────────
function openAddUserModal() {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-person-plus-fill me-2 text-primary"></i>Add New User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div class="input-group-custom">
      <label class="form-label-custom">Username</label>
      <input id="m_username" class="form-input-custom" placeholder="Enter username"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Email</label>
      <input id="m_email" type="email" class="form-input-custom" placeholder="user@example.com"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Password</label>
      <input id="m_password" type="password" class="form-input-custom" placeholder="Min. 6 characters"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Role</label>
      <select id="m_role" class="ids-select">
        <option value="viewer">Viewer — Read-only access</option>
        <option value="analyst">Analyst — Detection + PCAP</option>
        <option value="admin">Admin — Full access</option>
      </select>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitAddUser()">
        <i class="bi bi-person-check me-1"></i>Create User
      </button>
    </div>`);
}

async function submitAddUser() {
  const username = document.getElementById("m_username").value.trim();
  const email    = document.getElementById("m_email").value.trim();
  const password = document.getElementById("m_password").value;
  const role     = document.getElementById("m_role").value;
  if (!username || !email || !password) {
    return modalAlert("All fields are required.", "error");
  }
  const result = await API.createUser(username, email, password, role);
  if (result.ok) {
    closeModal();
    showToast(`User "${username}" created as ${role}!`, "success");
    loadUsers();
  } else {
    modalAlert(result.data?.detail || "Failed to create user.", "error");
  }
}

// ── Change Role Modal ─────────────────────────────────────────────────────────
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
    <div class="input-group-custom">
      <label class="form-label-custom">New Role</label>
      <select id="m_newRole" class="ids-select">
        <option value="viewer"  ${currentRole==="viewer"  ?"selected":""}>Viewer — Read-only access</option>
        <option value="analyst" ${currentRole==="analyst" ?"selected":""}>Analyst — Detection + PCAP</option>
        <option value="admin"   ${currentRole==="admin"   ?"selected":""}>Admin — Full access</option>
      </select>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitRoleChange(${userId},'${username}')">
        <i class="bi bi-check2 me-1"></i>Update Role
      </button>
    </div>`);
}

async function submitRoleChange(userId, username) {
  const role   = document.getElementById("m_newRole").value;
  const result = await API.changeRole(userId, role);
  if (result.ok) {
    closeModal();
    showToast(`"${username}" is now ${role}`, "success");
    loadUsers();
  } else {
    modalAlert(result.data?.detail || "Failed to change role.", "error");
  }
}

// ── Reset Password Modal ──────────────────────────────────────────────────────
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
    <div class="input-group-custom">
      <label class="form-label-custom">New Password</label>
      <input id="m_newPwd" type="password" class="form-input-custom" placeholder="Min. 6 characters"/>
    </div>
    <div class="input-group-custom">
      <label class="form-label-custom">Confirm Password</label>
      <input id="m_confirmPwd" type="password" class="form-input-custom" placeholder="Repeat password"/>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-primary" onclick="submitResetPwd(${userId},'${username}')">
        <i class="bi bi-check2 me-1"></i>Reset Password
      </button>
    </div>`);
}

async function submitResetPwd(userId, username) {
  const pwd1 = document.getElementById("m_newPwd").value;
  const pwd2 = document.getElementById("m_confirmPwd").value;
  if (pwd1.length < 6) return modalAlert("Password must be at least 6 characters.", "error");
  if (pwd1 !== pwd2)   return modalAlert("Passwords do not match.", "error");
  const result = await API.resetPassword(userId, pwd1);
  if (result.ok) {
    closeModal();
    showToast(`Password reset for "${username}"`, "success");
  } else {
    modalAlert(result.data?.detail || "Failed to reset password.", "error");
  }
}

// ── Delete Modal ──────────────────────────────────────────────────────────────
function openDeleteModal(userId, username) {
  openModal(`
    <div class="ids-modal-header">
      <h5><i class="bi bi-trash3-fill me-2 text-danger"></i>Delete User</h5>
      <button class="ids-modal-close" onclick="closeModal()"><i class="bi bi-x-lg"></i></button>
    </div>
    <div id="modalAlert" class="alert-area d-none mb-3"></div>
    <div style="text-align:center;padding:10px 0 20px">
      <div style="font-size:2.5rem;color:var(--danger);margin-bottom:12px">⚠️</div>
      <p style="color:var(--text-main);font-weight:700;font-size:1rem">
        Permanently delete <span style="color:var(--danger)">"${username}"</span>?
      </p>
      <p style="color:var(--text-muted);font-size:0.85rem">
        This action cannot be undone. All data associated with this user will be removed.
      </p>
    </div>
    <div class="ids-modal-footer">
      <button class="btn-modal-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-modal-danger" onclick="submitDelete(${userId},'${username}')">
        <i class="bi bi-trash3 me-1"></i>Yes, Delete Permanently
      </button>
    </div>`);
}

async function submitDelete(userId, username) {
  const result = await API.deleteUser(userId);
  if (result.ok) {
    closeModal();
    showToast(`"${username}" deleted permanently`, "success");
    loadUsers();
  } else {
    modalAlert(result.data?.detail || "Failed to delete user.", "error");
  }
}

// ── Toggle Activate/Deactivate ────────────────────────────────────────────────
async function toggleActive(userId, username, activate) {
  const ok = activate
    ? await API.activateUser(userId)
    : await API.deactivateUser(userId);
  if (ok) {
    showToast(`"${username}" ${activate ? "activated" : "deactivated"}`, "success");
    loadUsers();
  } else {
    showToast("Action failed", "error");
  }
}

// ── Modal alert helper ────────────────────────────────────────────────────────
function modalAlert(msg, type) {
  const el = document.getElementById("modalAlert");
  if (!el) return;
  el.textContent = msg; el.className = `alert-area ${type}`;
}

// ══════════════════════════════════════════════════════════════════════════════
// MISC
// ══════════════════════════════════════════════════════════════════════════════
function toggleSidebar() {
  const sb   = document.getElementById("sidebar");
  const main = document.getElementById("mainContent");
  if (window.innerWidth <= 768) { sb.classList.toggle("open"); }
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
