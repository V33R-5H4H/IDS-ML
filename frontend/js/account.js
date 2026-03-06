// js/account.js  ─── My Account section

// ══════════════════════════════════════════════════════════════════════════════
// INIT — called by dashboard.js navigateTo('account')
// ══════════════════════════════════════════════════════════════════════════════
async function initAccountSection(user) {
  // Re-fetch if stale or missing (guards against 500 on first load)
  if (!user || !user.username) {
    user = await API.me();
    if (user && typeof currentUser !== "undefined") currentUser = user;
  }
  if (!user) {
    console.error("initAccountSection: user is null");
    return;
  }

  // ── Top header card ────────────────────────────────────────────────────────
  const name    = user.display_name || user.username;
  const initial = name[0].toUpperCase();

  _txt("acc_avatarLetter",   initial);
  _txt("acc_username_display",
    user.display_name ? `${user.display_name} (${user.username})` : user.username);

  const roleEl = document.getElementById("acc_role_display");
  if (roleEl) { roleEl.textContent = user.role; roleEl.className = `role-pill ${user.role}`; }

  const joinedEl = document.getElementById("acc_joined_display");
  if (joinedEl) joinedEl.textContent = user.created_at
    ? new Date(user.created_at).toLocaleDateString("en-IN",
        {day:"2-digit", month:"long", year:"numeric"})
    : "—";

  // ── Profile form ───────────────────────────────────────────────────────────
  _val("acc_username",    user.username);
  _val("acc_displayName", user.display_name || "");
  _val("acc_email",       user.email || "");

  // ── Password fields — clear on every open ─────────────────────────────────
  ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => _val(id, ""));
  const bar = document.getElementById("acc_pwdBar");
  const lbl = document.getElementById("acc_pwdLbl");
  if (bar) { bar.style.width = "0"; bar.style.background = "transparent"; }
  if (lbl) lbl.textContent = "";

  // ── Role request section ───────────────────────────────────────────────────
  const reqCard = document.getElementById("acc_roleReqCard");
  if (reqCard) {
    if (user.role === "admin") {
      // Completely replace card content with admin notice — no form shown
      reqCard.innerHTML = `
        <div class="acc-card-header">
          <i class="bi bi-shield-fill-check" style="color:#60a5fa"></i>
          Administrator Access
        </div>
        <div class="acc-card-body">
          <div class="req-admin-notice">
            <i class="bi bi-shield-fill-check"></i>
            <div>
              <strong>Full Access Granted</strong>
              <p>As an Administrator you already have the highest access level.
                 Role upgrade requests are not applicable to your account.</p>
            </div>
          </div>
        </div>`;
    } else {
      // Restore form for non-admin roles
      reqCard.innerHTML = _roleReqFormHTML();
      await _loadRoleStatus(user);
    }
  }
}

// ── HTML template for non-admin role request card ─────────────────────────────
function _roleReqFormHTML() {
  return `
    <div class="acc-card-header">
      <i class="bi bi-person-up" style="color:#f59e0b"></i> Request Access Upgrade
    </div>
    <div class="acc-card-body">
      <div class="row g-4">
        <div class="col-md-6">
          <div id="acc_alert_role" class="alert-area d-none mb-3"></div>
          <div class="acc-form-group">
            <label>Requested Role</label>
            <select id="req_role" class="acc-select">
              <option value="">— Select a role —</option>
              <option value="analyst">Analyst — Detection + PCAP upload</option>
              <option value="admin">Admin — Full system access</option>
            </select>
          </div>
          <div class="acc-form-group">
            <label>Reason / Justification
              <span style="color:var(--text-muted);font-weight:400">(optional)</span>
            </label>
            <textarea id="req_reason" class="acc-textarea"
              placeholder="Briefly explain why you need elevated access..."></textarea>
          </div>
          <button class="btn-acc-save" id="btn_submitReq" onclick="submitRoleRequest()"
            style="background:linear-gradient(135deg,#f59e0b,#d97706)">
            <i class="bi bi-send-fill"></i>Submit Request
          </button>
        </div>
        <div class="col-md-6">
          <label style="font-size:.78rem;font-weight:700;color:var(--text-muted);
            text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;display:block">
            Current Request Status
          </label>
          <div id="roleReqStatus">
            <div class="req-none">
              <span class="spinner-border spinner-border-sm me-2"></span>Checking...
            </div>
          </div>
        </div>
      </div>
    </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
// PROFILE UPDATE
// ══════════════════════════════════════════════════════════════════════════════
async function saveProfile() {
  const displayName = document.getElementById("acc_displayName")?.value.trim() || "";
  const email       = document.getElementById("acc_email")?.value.trim()       || "";

  if (!email)
    return accAlert("profile","Email cannot be empty.","error");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return accAlert("profile","Enter a valid email address.","error");

  setBtnLoading("btn_saveProfile", true);
  const result = await API.updateProfile(email, displayName);
  setBtnLoading("btn_saveProfile", false);

  if (result.ok) {
    if (typeof currentUser !== "undefined" && currentUser) {
      currentUser.email        = email;
      currentUser.display_name = displayName || null;
    }
    _txt("acc_avatarLetter",
      (displayName || currentUser?.username || "?")[0].toUpperCase());
    _txt("acc_username_display",
      displayName ? `${displayName} (${currentUser?.username})` : currentUser?.username);
    if (typeof renderTopbarUser === "function" && currentUser) renderTopbarUser(currentUser);
    accAlert("profile","✅ Profile updated successfully!","success");
  } else {
    accAlert("profile", result.data?.detail || "Failed to update profile.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD CHANGE
// ══════════════════════════════════════════════════════════════════════════════
function onNewPwdInput() {
  const val = document.getElementById("acc_newPwd")?.value || "";
  const bar = document.getElementById("acc_pwdBar");
  const lbl = document.getElementById("acc_pwdLbl");
  let s = 0;
  if (val.length >= 6)          s++;
  if (val.length >= 10)         s++;
  if (/[A-Z]/.test(val))        s++;
  if (/[0-9]/.test(val))        s++;
  if (/[^A-Za-z0-9]/.test(val)) s++;
  const L = [
    {w:"0",    c:"transparent", t:""},
    {w:"25%",  c:"#ef4444",     t:"Weak"},
    {w:"50%",  c:"#f59e0b",     t:"Fair"},
    {w:"75%",  c:"#3b82f6",     t:"Good"},
    {w:"100%", c:"#22c55e",     t:"Strong"},
  ][Math.min(s,4)];
  if (bar) { bar.style.width = L.w; bar.style.background = L.c; }
  if (lbl) { lbl.textContent = L.t; lbl.style.color = L.c; }
}

async function savePassword() {
  const cur = document.getElementById("acc_curPwd")?.value || "";
  const nw  = document.getElementById("acc_newPwd")?.value || "";
  const con = document.getElementById("acc_conPwd")?.value || "";

  if (!cur||!nw||!con) return accAlert("pwd","All password fields are required.","error");
  if (nw.length < 6)   return accAlert("pwd","New password must be at least 6 characters.","error");
  if (nw !== con)      return accAlert("pwd","New passwords do not match.","error");
  if (nw === cur)      return accAlert("pwd","New password must differ from current.","error");

  setBtnLoading("btn_savePwd", true);
  const result = await API.changePassword(cur, nw);
  setBtnLoading("btn_savePwd", false);

  if (result.ok) {
    ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => _val(id,""));
    const bar = document.getElementById("acc_pwdBar");
    const lbl = document.getElementById("acc_pwdLbl");
    if (bar) { bar.style.width = "0"; bar.style.background = "transparent"; }
    if (lbl) lbl.textContent = "";
    accAlert("pwd","✅ Password changed successfully!","success");
  } else {
    accAlert("pwd", result.data?.detail || "Failed to change password.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ROLE REQUEST STATUS
// ══════════════════════════════════════════════════════════════════════════════
async function _loadRoleStatus(user) {
  const el = document.getElementById("roleReqStatus");
  if (!el) return;
  try {
    const data    = await API.getMyRoleRequest();
    const request = data?.request;
    if (!request) {
      el.innerHTML = `<div class="req-none">
        <i class="bi bi-info-circle me-2"></i>No access request submitted yet.
      </div>`;
      return;
    }
    const C = {
      pending:  {cls:"req-pending",  icon:"bi-hourglass-split",   label:"Pending Review"},
      approved: {cls:"req-approved", icon:"bi-check-circle-fill", label:"Approved"},
      rejected: {cls:"req-rejected", icon:"bi-x-circle-fill",     label:"Rejected"},
    }[request.status] || {cls:"", icon:"bi-question", label:request.status};

    el.innerHTML = `
      <div class="req-status-card ${C.cls}">
        <div class="req-status-header">
          <i class="bi ${C.icon}"></i><span>${C.label}</span>
        </div>
        <div class="req-status-body">
          <div class="req-detail">
            <span>Requested</span>
            <strong>
              <span class="role-pill ${request.current_role}" style="font-size:.72rem">${request.current_role}</span>
              <i class="bi bi-arrow-right mx-1" style="font-size:.7rem;color:var(--text-muted)"></i>
              <span class="role-pill ${request.requested_role}" style="font-size:.72rem">${request.requested_role}</span>
            </strong>
          </div>
          ${request.reason?`<div class="req-detail"><span>Reason</span><em>"${request.reason}"</em></div>`:""}
          <div class="req-detail">
            <span>Submitted</span>
            <span>${new Date(request.created_at).toLocaleString("en-IN")}</span>
          </div>
          ${request.reviewed_by?`
          <div class="req-detail">
            <span>Reviewed by</span>
            <span>${request.reviewed_by}</span>
          </div>`:""}
        </div>
      </div>`;
  } catch {
    el.innerHTML = `<div class="req-none" style="color:var(--danger)">
      <i class="bi bi-exclamation-triangle me-2"></i>Could not load status.
    </div>`;
  }
}

async function submitRoleRequest() {
  const role   = document.getElementById("req_role")?.value        || "";
  const reason = document.getElementById("req_reason")?.value.trim() || "";
  if (!role) return accAlert("role","Please select a role.","error");

  setBtnLoading("btn_submitReq", true);
  const result = await API.submitRoleRequest(role, reason);
  setBtnLoading("btn_submitReq", false);

  if (result.ok) {
    _val("req_reason","");
    accAlert("role","✅ "+result.data.message,"success");
    if (typeof currentUser!=="undefined" && currentUser)
      await _loadRoleStatus(currentUser);
  } else {
    accAlert("role", result.data?.detail||"Failed to submit request.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SHARED UTILS
// ══════════════════════════════════════════════════════════════════════════════
function _txt(id, val) { const e=document.getElementById(id); if(e) e.textContent=val; }
function _val(id, val) { const e=document.getElementById(id); if(e) e.value=val; }

function accAlert(section, msg, type) {
  const el = document.getElementById(`acc_alert_${section}`);
  if (!el) return;
  el.textContent = msg; el.className = `alert-area ${type}`;
  clearTimeout(el._t);
  el._t = setTimeout(()=>{ el.className="alert-area d-none"; }, 4500);
}

function setBtnLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) btn.dataset.orig = btn.innerHTML;
  btn.innerHTML = loading
    ? `<span class="spinner-border spinner-border-sm me-2"></span>Saving...`
    : (btn.dataset.orig || btn.innerHTML);
}

function toggleAccPwd(inputId, iconId) {
  const inp=document.getElementById(inputId);
  const icon=document.getElementById(iconId);
  if(!inp||!icon) return;
  const show = inp.type==="text";
  inp.type       = show ? "password" : "text";
  icon.className = show ? "bi bi-eye" : "bi bi-eye-slash";
}
