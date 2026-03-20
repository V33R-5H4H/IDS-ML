// js/account.js — My Account section
// Builds the entire HTML scaffold into #account-root, then populates values.

// ═══════════════════════════════════════════════════════════════
// INIT  (called by dashboard.js navigateTo('account'))
// ═══════════════════════════════════════════════════════════════
async function initAccountSection(user) {
  if (!user || !user.username) {
    user = await API.me();
    if (user && typeof currentUser !== "undefined") currentUser = user;
  }
  if (!user) { console.error("initAccountSection: user is null"); return; }

  const root = document.getElementById("account-root");
  if (!root) return;

  // Build scaffold (always rebuild so values are fresh)
  root.innerHTML = buildAccountHTML(user);

  // ── Header ──────────────────────────────────────────────────
  const name    = user.display_name || user.username;
  const initial = name[0].toUpperCase();
  _txt("acc_avatarLetter",   initial);
  _txt("acc_username_display",
    user.display_name ? `${user.display_name} (${user.username})` : user.username);

  const roleEl = document.getElementById("acc_role_display");
  if (roleEl) { roleEl.textContent = user.role; roleEl.className = `role-pill ${user.role}`; }

  const joinedEl = document.getElementById("acc_joined_display");
  if (joinedEl) joinedEl.textContent = user.created_at
    ? new Date(user.created_at).toLocaleDateString("en-IN",{day:"2-digit",month:"long",year:"numeric"})
    : "—";

  // ── Profile form ─────────────────────────────────────────────
  _val("acc_username",    user.username);
  _val("acc_displayName", user.display_name || "");
  _val("acc_email",       user.email || "");

  // ── Password fields — clear ──────────────────────────────────
  ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => _val(id, ""));
  const bar = document.getElementById("acc_pwdBar");
  const lbl = document.getElementById("acc_pwdLbl");
  if (bar) { bar.style.width = "0"; bar.style.background = "transparent"; }
  if (lbl) lbl.textContent = "";

  // ── Role request card ────────────────────────────────────────
  await loadAccRoleReqCard(user);
}

// ═══════════════════════════════════════════════════════════════
// HTML BUILDER
// ═══════════════════════════════════════════════════════════════
function buildAccountHTML(user) {
  return `
  <!-- ── Header card ──────────────────────────────────────── -->
  <div class="acc-header-card">
    <div class="acc-avatar-lg" id="acc_avatarLetter">?</div>
    <div class="acc-header-info">
      <div class="acc-display-name">
        <span id="acc_username_display">—</span>
        <span id="acc_role_display" class="role-pill ${user.role}">${user.role}</span>
      </div>
      <div class="acc-meta">
        <span><i class="bi bi-envelope"></i> ${user.email || "—"}</span>
        <span><i class="bi bi-calendar3"></i> Joined <span id="acc_joined_display">—</span></span>
      </div>
    </div>
  </div>

  <!-- ── Tabs ─────────────────────────────────────────────── -->
  <div class="acc-tabs">
    <button class="acc-tab active" id="acc_tab_profile"
            onclick="switchAccTab('profile')">
      <i class="bi bi-person-fill"></i><span>Profile</span>
    </button>
    <button class="acc-tab" id="acc_tab_password"
            onclick="switchAccTab('password')">
      <i class="bi bi-lock-fill"></i><span>Password</span>
    </button>
    <button class="acc-tab" id="acc_tab_access"
            onclick="switchAccTab('access')">
      <i class="bi bi-shield-check"></i><span>Access</span>
    </button>
  </div>

  <!-- ══════════════════════════════════════════════════════
       PROFILE PANEL
  ═══════════════════════════════════════════════════════ -->
  <div class="acc-panel active" id="acc_panel_profile">
    <div class="acc-card">
      <div class="acc-card-header">
        <h4><i class="bi bi-person-fill"></i>Profile Information</h4>
      </div>
      <div class="acc-card-body">
        <div class="form-group">
          <label class="form-label">Username <span style="color:var(--text-muted);font-size:.75rem;">(cannot change)</span></label>
          <input id="acc_username" class="form-input" readonly
                 style="opacity:.6;cursor:not-allowed;" />
        </div>
        <div class="form-group">
          <label class="form-label">Display Name</label>
          <input id="acc_displayName" class="form-input" placeholder="Your display name" />
        </div>
        <div class="form-group">
          <label class="form-label">Email Address</label>
          <input id="acc_email" type="email" class="form-input" placeholder="you@example.com" />
        </div>
        <div id="acc_profileFeedback" class="acc-feedback"></div>
        <button class="btn btn-primary" onclick="submitProfile()" id="acc_profileBtn">
          <i class="bi bi-check2 me-1"></i>Save Changes
        </button>
      </div>
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════
       PASSWORD PANEL
  ═══════════════════════════════════════════════════════ -->
  <div class="acc-panel" id="acc_panel_password">
    <div class="acc-card">
      <div class="acc-card-header">
        <h4><i class="bi bi-lock-fill"></i>Change Password</h4>
      </div>
      <div class="acc-card-body">
        <div class="form-group">
          <label class="form-label">Current Password</label>
          <div class="input-pw-wrap">
            <input type="password" id="acc_curPwd" class="form-input"
                   placeholder="Enter current password" autocomplete="current-password"/>
            <button type="button" class="pw-toggle"
                    onclick="accTogglePw('acc_curPwd',this)" tabindex="-1">
              <i class="bi bi-eye"></i>
            </button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">New Password</label>
          <div class="input-pw-wrap">
            <input type="password" id="acc_newPwd" class="form-input"
                   placeholder="Min. 6 characters" autocomplete="new-password"
                   oninput="accPwStrength(this.value)"/>
            <button type="button" class="pw-toggle"
                    onclick="accTogglePw('acc_newPwd',this)" tabindex="-1">
              <i class="bi bi-eye"></i>
            </button>
          </div>
          <div class="pw-bar-wrap">
            <div class="pw-bar-track">
              <div id="acc_pwdBar" class="pw-bar-fill" style="width:0;"></div>
            </div>
            <span id="acc_pwdLbl" class="pw-lbl"></span>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Confirm New Password</label>
          <div class="input-pw-wrap">
            <input type="password" id="acc_conPwd" class="form-input"
                   placeholder="Repeat new password" autocomplete="new-password"/>
            <button type="button" class="pw-toggle"
                    onclick="accTogglePw('acc_conPwd',this)" tabindex="-1">
              <i class="bi bi-eye"></i>
            </button>
          </div>
        </div>
        <div id="acc_pwdFeedback" class="acc-feedback"></div>
        <button class="btn btn-primary" onclick="submitPassword()" id="acc_pwdBtn">
          <i class="bi bi-lock me-1"></i>Update Password
        </button>
      </div>
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════
       ACCESS PANEL
  ═══════════════════════════════════════════════════════ -->
  <div class="acc-panel" id="acc_panel_access">

    <!-- Role Request card — content replaced by loadAccRoleReqCard() -->
    <div class="acc-card" id="acc_roleReqCard">
      <div class="acc-card-header">
        <h4><i class="bi bi-shield-check"></i>Role Access Request</h4>
      </div>
      <div class="acc-card-body">
        <div class="skeleton-row"></div>
        <div class="skeleton-row"></div>
      </div>
    </div>

    <!-- Danger zone -->
    <div class="acc-card">
      <div class="acc-card-header">
        <h4><i class="bi bi-exclamation-triangle-fill" style="color:var(--accent-red);"></i>
          Session</h4>
      </div>
      <div class="acc-card-body">
        <div class="acc-danger-zone">
          <div class="acc-danger-title"><i class="bi bi-box-arrow-right"></i>Sign Out</div>
          <div class="acc-danger-desc">
            This will clear your session token and return you to the login page.
          </div>
          <button class="btn btn-danger" onclick="handleLogout()">
            <i class="bi bi-box-arrow-right me-1"></i>Sign Out
          </button>
        </div>
      </div>
    </div>

  </div>`;
}

// ═══════════════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════════════
function switchAccTab(tab) {
  document.querySelectorAll(".acc-tab").forEach(t =>
    t.classList.toggle("active", t.id === `acc_tab_${tab}`));
  document.querySelectorAll(".acc-panel").forEach(p =>
    p.classList.toggle("active", p.id === `acc_panel_${tab}`));
}

// ═══════════════════════════════════════════════════════════════
// PROFILE SUBMIT
// ═══════════════════════════════════════════════════════════════
async function submitProfile() {
  const email       = document.getElementById("acc_email")?.value.trim();
  const displayName = document.getElementById("acc_displayName")?.value.trim();
  const btn         = document.getElementById("acc_profileBtn");
  const fb          = document.getElementById("acc_profileFeedback");

  if (!email) return accFeedback(fb, "Email is required.", "error");

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-sm"></span> Saving…`;
  accFeedback(fb, "", "");

  const result = await API.updateProfile(email, displayName);

  if (result.ok) {
    accFeedback(fb, "Profile updated successfully!", "success");
    // Refresh topbar
    const me = await API.me();
    if (me) {
      if (typeof currentUser !== "undefined") currentUser = me;
      if (typeof renderTopbarUser === "function") renderTopbarUser(me);
      _txt("acc_username_display",
        me.display_name ? `${me.display_name} (${me.username})` : me.username);
    }
  } else {
    accFeedback(fb, result.data?.detail || "Failed to update profile.", "error");
  }

  btn.disabled = false;
  btn.innerHTML = `<i class="bi bi-check2 me-1"></i>Save Changes`;
}

// ═══════════════════════════════════════════════════════════════
// PASSWORD SUBMIT
// ═══════════════════════════════════════════════════════════════
async function submitPassword() {
  const curPwd = document.getElementById("acc_curPwd")?.value;
  const newPwd = document.getElementById("acc_newPwd")?.value;
  const conPwd = document.getElementById("acc_conPwd")?.value;
  const btn    = document.getElementById("acc_pwdBtn");
  const fb     = document.getElementById("acc_pwdFeedback");

  if (!curPwd)         return accFeedback(fb, "Enter your current password.", "error");
  if (newPwd.length < 6) return accFeedback(fb, "New password must be at least 6 characters.", "error");
  if (newPwd !== conPwd) return accFeedback(fb, "New passwords do not match.", "error");

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-sm"></span> Updating…`;
  accFeedback(fb, "", "");

  const result = await API.changePassword(curPwd, newPwd);

  if (result.ok) {
    accFeedback(fb, "Password changed successfully!", "success");
    ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => _val(id, ""));
    const bar = document.getElementById("acc_pwdBar");
    const lbl = document.getElementById("acc_pwdLbl");
    if (bar) { bar.style.width = "0"; bar.style.background = "transparent"; }
    if (lbl) lbl.textContent = "";
  } else {
    accFeedback(fb, result.data?.detail || "Failed to change password.", "error");
  }

  btn.disabled = false;
  btn.innerHTML = `<i class="bi bi-lock me-1"></i>Update Password`;
}

// ═══════════════════════════════════════════════════════════════
// ROLE REQUEST CARD
// ═══════════════════════════════════════════════════════════════
async function loadAccRoleReqCard(user) {
  const card = document.getElementById("acc_roleReqCard");
  if (!card) return;

  // Admin — no requests needed
  if (user.role === "admin") {
    card.innerHTML = `
      <div class="acc-card-header">
        <h4><i class="bi bi-shield-fill-check"></i>Role Access</h4>
      </div>
      <div class="acc-card-body">
        <div class="acc-admin-notice">
          <i class="bi bi-info-circle-fill"></i>
          <div>As an <strong>Administrator</strong> you already have the highest access level.
          Role upgrade requests are not applicable to your account.</div>
        </div>
      </div>`;
    return;
  }

  // Check existing request
  const { request } = await API.getMyRoleRequest();

  card.innerHTML = `
    <div class="acc-card-header">
      <h4><i class="bi bi-shield-check"></i>Role Access Request</h4>
    </div>
    <div class="acc-card-body" id="acc_roleReqBody">
      ${renderRoleReqBody(user, request)}
    </div>`;
}

function renderRoleReqBody(user, request) {
  const currentRole = user.role;

  if (request && request.status === "pending") {
    return `
      <div class="pending-req-banner">
        <i class="bi bi-hourglass-split"></i>
        <div>
          <strong>Request Pending</strong><br/>
          Your request to upgrade from
          <span class="role-pill ${currentRole}" style="font-size:.7rem;">${currentRole}</span>
          to
          <span class="role-pill ${request.requested_role}" style="font-size:.7rem;">${request.requested_role}</span>
          is awaiting admin review.
          ${request.reason ? `<div style="margin-top:6px;font-size:.78rem;opacity:.8;">Reason: ${request.reason}</div>` : ""}
        </div>
      </div>
      <div class="acc-role-current">
        <i class="bi bi-person-badge-fill"></i>
        <span>Current role: <strong style="color:var(--text-main);">${currentRole}</strong></span>
      </div>`;
  }

  if (request && request.status === "rejected") {
    return `
      <div style="padding:10px 14px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);
           border-radius:var(--radius-sm);color:#f87171;font-size:.83rem;margin-bottom:14px;">
        <i class="bi bi-x-circle-fill me-1"></i>
        Your previous request was <strong>rejected</strong>.
        You may submit a new one below.
      </div>
      ${roleRequestForm(currentRole)}`;
  }

  return roleRequestForm(currentRole);
}

function roleRequestForm(currentRole) {
  const options = ["viewer","analyst","admin"]
    .filter(r => r !== currentRole)
    .map(r => `<option value="${r}">${r.charAt(0).toUpperCase() + r.slice(1)}</option>`)
    .join("");

  return `
    <div class="acc-role-current">
      <i class="bi bi-person-badge-fill"></i>
      <span>Current role: <strong style="color:var(--text-main);">${currentRole}</strong></span>
    </div>
    <div class="form-group">
      <label class="form-label">Request Role Upgrade To</label>
      <select id="acc_reqRole" class="acc-select">
        ${options}
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Reason <span style="color:var(--text-muted);font-size:.75rem;">(recommended)</span></label>
      <textarea id="acc_reqReason" class="form-input" rows="3"
                placeholder="Explain why you need elevated access…"></textarea>
    </div>
    <div id="acc_reqFeedback" class="acc-feedback"></div>
    <button class="btn btn-primary" onclick="submitRoleReq()" id="acc_reqBtn">
      <i class="bi bi-send me-1"></i>Submit Request
    </button>`;
}

async function submitRoleReq() {
  const role   = document.getElementById("acc_reqRole")?.value;
  const reason = document.getElementById("acc_reqReason")?.value.trim();
  const btn    = document.getElementById("acc_reqBtn");
  const fb     = document.getElementById("acc_reqFeedback");

  if (!role) return;

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-sm"></span> Submitting…`;
  accFeedback(fb, "", "");

  const result = await API.submitRoleRequest(role, reason);

  if (result.ok) {
    accFeedback(fb, "Request submitted! An admin will review it shortly.", "success");
    // Reload the card to show pending state
    const user = typeof currentUser !== "undefined" ? currentUser : await API.me();
    if (user) await loadAccRoleReqCard(user);
  } else {
    accFeedback(fb, result.data?.detail || "Failed to submit request.", "error");
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-send me-1"></i>Submit Request`;
  }
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
function accTogglePw(id, btn) {
  const input = document.getElementById(id);
  const icon  = btn.querySelector("i");
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    icon.className = "bi bi-eye-slash";
  } else {
    input.type = "password";
    icon.className = "bi bi-eye";
  }
}

function accPwStrength(val) {
  const bar = document.getElementById("acc_pwdBar");
  const lbl = document.getElementById("acc_pwdLbl");
  if (!bar || !lbl) return;
  let score = 0;
  if (val.length >= 6)          score++;
  if (val.length >= 10)         score++;
  if (/[A-Z]/.test(val))        score++;
  if (/[0-9]/.test(val))        score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const levels = [
    {w:"0%",  bg:"transparent",txt:""},
    {w:"20%", bg:"#ef4444",    txt:"Weak"},
    {w:"40%", bg:"#f59e0b",    txt:"Fair"},
    {w:"60%", bg:"#f59e0b",    txt:"Good"},
    {w:"80%", bg:"#22c55e",    txt:"Strong"},
    {w:"100%",bg:"#14b8a6",    txt:"Excellent"},
  ];
  const lvl = levels[Math.min(score, 5)];
  bar.style.width      = lvl.w;
  bar.style.background = lvl.bg;
  lbl.textContent      = lvl.txt;
  lbl.style.color      = lvl.bg;
}

function accFeedback(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className   = msg ? `acc-feedback ${type}` : "acc-feedback";
  if (!msg) el.style.display = "none";
}

function _val(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}

function _txt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
