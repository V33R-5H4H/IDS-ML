// js/account.js  — My Account page logic (loaded by dashboard.html)

// ══════════════════════════════════════════════════════════════════════════════
// INIT — populate all fields when section opens
// ══════════════════════════════════════════════════════════════════════════════
async function initAccountSection(user) {
  // Profile fields
  document.getElementById("acc_displayName").value = user.display_name || "";
  document.getElementById("acc_email").value       = user.email        || "";
  document.getElementById("acc_username").value    = user.username;
  document.getElementById("acc_role").textContent  = user.role;
  document.getElementById("acc_role").className    = `role-pill ${user.role}`;
  document.getElementById("acc_joined").textContent =
    new Date(user.created_at).toLocaleDateString("en-IN", {day:"2-digit",month:"long",year:"numeric"});

  // Clear password fields
  ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = "";
  });
  const bar = document.getElementById("acc_pwdBar");
  const lbl = document.getElementById("acc_pwdLbl");
  if (bar) bar.style.width = "0"; if (lbl) lbl.textContent = "";

  // Role request status
  await loadMyRoleRequest(user);
}

// ══════════════════════════════════════════════════════════════════════════════
// PROFILE UPDATE
// ══════════════════════════════════════════════════════════════════════════════
async function saveProfile() {
  const displayName = document.getElementById("acc_displayName").value.trim();
  const email       = document.getElementById("acc_email").value.trim();

  if (!email) return accAlert("profile", "Email cannot be empty.", "error");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return accAlert("profile", "Enter a valid email address.", "error");

  setBtnLoading("btn_saveProfile", true);
  const result = await API.updateProfile(email, displayName);
  setBtnLoading("btn_saveProfile", false);

  if (result.ok) {
    // Update in-memory currentUser
    if (typeof currentUser !== "undefined" && currentUser) {
      currentUser.email        = email;
      currentUser.display_name = displayName || null;
    }
    accAlert("profile", "✅ Profile updated successfully!", "success");
  } else {
    accAlert("profile", result.data?.detail || "Failed to update profile.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD CHANGE
// ══════════════════════════════════════════════════════════════════════════════
function onNewPwdInput() {
  const val  = document.getElementById("acc_newPwd").value;
  const bar  = document.getElementById("acc_pwdBar");
  const lbl  = document.getElementById("acc_pwdLbl");
  let score  = 0;
  if (val.length >= 6)          score++;
  if (val.length >= 10)         score++;
  if (/[A-Z]/.test(val))        score++;
  if (/[0-9]/.test(val))        score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const levels = [
    {w:"0%",   c:"transparent", t:""},
    {w:"25%",  c:"#ef4444",     t:"Weak"},
    {w:"50%",  c:"#f59e0b",     t:"Fair"},
    {w:"75%",  c:"#3b82f6",     t:"Good"},
    {w:"100%", c:"#22c55e",     t:"Strong"},
  ];
  const lvl = levels[Math.min(score, 4)];
  if (bar) { bar.style.width = lvl.w; bar.style.background = lvl.c; }
  if (lbl) { lbl.textContent = lvl.t; lbl.style.color = lvl.c; }
}

async function savePassword() {
  const cur  = document.getElementById("acc_curPwd").value;
  const nw   = document.getElementById("acc_newPwd").value;
  const con  = document.getElementById("acc_conPwd").value;

  if (!cur || !nw || !con) return accAlert("pwd", "All password fields are required.", "error");
  if (nw.length < 6)        return accAlert("pwd", "New password must be at least 6 characters.", "error");
  if (nw !== con)           return accAlert("pwd", "New passwords do not match.", "error");

  setBtnLoading("btn_savePwd", true);
  const result = await API.changePassword(cur, nw);
  setBtnLoading("btn_savePwd", false);

  if (result.ok) {
    ["acc_curPwd","acc_newPwd","acc_conPwd"].forEach(id => {
      const el = document.getElementById(id); if(el) el.value = "";
    });
    const bar = document.getElementById("acc_pwdBar");
    const lbl = document.getElementById("acc_pwdLbl");
    if (bar) bar.style.width = "0"; if (lbl) lbl.textContent = "";
    accAlert("pwd", "✅ Password changed successfully!", "success");
  } else {
    accAlert("pwd", result.data?.detail || "Failed to change password.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ROLE REQUEST
// ══════════════════════════════════════════════════════════════════════════════
async function loadMyRoleRequest(user) {
  const statusEl = document.getElementById("roleReqStatus");
  if (!statusEl) return;

  const {request} = await API.getMyRoleRequest();

  if (!request) {
    statusEl.innerHTML = `<div class="req-none">
      <i class="bi bi-info-circle me-2"></i>No pending access request.
    </div>`;
    return;
  }

  const clsMap = {pending:"req-pending", approved:"req-approved", rejected:"req-rejected"};
  const iconMap = {pending:"bi-hourglass-split", approved:"bi-check-circle-fill", rejected:"bi-x-circle-fill"};
  const labelMap = {pending:"Pending Review", approved:"Approved", rejected:"Rejected"};

  statusEl.innerHTML = `
    <div class="req-status-card ${clsMap[request.status]}">
      <div class="req-status-header">
        <i class="bi ${iconMap[request.status]}"></i>
        <span>${labelMap[request.status]}</span>
      </div>
      <div class="req-status-body">
        <div class="req-detail">
          <span>Request</span>
          <strong>${request.current_role} → ${request.requested_role}</strong>
        </div>
        ${request.reason ? `<div class="req-detail"><span>Reason</span><em>"${request.reason}"</em></div>` : ""}
        <div class="req-detail">
          <span>Submitted</span>
          <span>${new Date(request.created_at).toLocaleString("en-IN")}</span>
        </div>
        ${request.reviewed_by ? `
        <div class="req-detail">
          <span>Reviewed by</span>
          <span>${request.reviewed_by} · ${new Date(request.reviewed_at).toLocaleString("en-IN")}</span>
        </div>` : ""}
      </div>
    </div>`;
}

async function submitRoleRequest() {
  const role   = document.getElementById("req_role").value;
  const reason = document.getElementById("req_reason").value.trim();

  if (!role) return accAlert("role", "Please select a role.", "error");

  setBtnLoading("btn_submitReq", true);
  const result = await API.submitRoleRequest(role, reason);
  setBtnLoading("btn_submitReq", false);

  if (result.ok) {
    document.getElementById("req_reason").value = "";
    accAlert("role", "✅ " + result.data.message, "success");
    if (typeof currentUser !== "undefined")
      await loadMyRoleRequest(currentUser);
  } else {
    accAlert("role", result.data?.detail || "Failed to submit request.", "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════════════════
function accAlert(section, msg, type) {
  const el = document.getElementById(`acc_alert_${section}`);
  if (!el) return;
  el.textContent = msg; el.className = `alert-area ${type}`;
  setTimeout(() => { el.className = "alert-area d-none"; }, 4000);
}

function setBtnLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) btn.dataset.orig = btn.innerHTML;
  btn.innerHTML = loading
    ? `<span class="spinner-border spinner-border-sm me-2"></span>Saving...`
    : btn.dataset.orig;
}

function toggleAccPwd(inputId, iconId) {
  const inp  = document.getElementById(inputId);
  const icon = document.getElementById(iconId);
  if (!inp || !icon) return;
  const show = inp.type === "text";
  inp.type       = show ? "password" : "text";
  icon.className = show ? "bi bi-eye" : "bi bi-eye-slash";
}

// Patch: keep avatar letter + header in sync after profile save / init
const _orig_initAccountSection = initAccountSection;
initAccountSection = async function(user) {
  await _orig_initAccountSection(user);
  const al = document.getElementById("acc_avatarLetter");
  if (al) al.textContent = (user.display_name || user.username)[0].toUpperCase();
  const un = document.getElementById("acc_username_display");
  if (un) un.textContent = user.display_name ? `${user.display_name} (${user.username})` : user.username;
  const rl = document.getElementById("acc_role_display");
  if (rl) { rl.textContent = user.role; rl.className = `role-pill ${user.role}`; }
  const jn = document.getElementById("acc_joined_display");
  if (jn) jn.textContent = new Date(user.created_at)
    .toLocaleDateString("en-IN",{day:"2-digit",month:"long",year:"numeric"});
};
