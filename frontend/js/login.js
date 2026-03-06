// js/login.js — Login page logic
document.addEventListener("DOMContentLoaded", () => {
  if (Auth.isLoggedIn()) { window.location.href = "dashboard.html"; return; }
  generateParticles();

  // Show "registered" success banner if redirected from register page
  const params = new URLSearchParams(window.location.search);
  if (params.get("registered") === "1") {
    showAlert("Account created! You can now log in.", "success");
  }
});

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  await doLogin(
    document.getElementById("username").value.trim(),
    document.getElementById("password").value,
    document.getElementById("rememberMe").checked
  );
});

// ── Core login function ────────────────────────────────────────────────────────
async function doLogin(username, password, remember = false) {
  if (!username || !password) {
    return showAlert("Please enter both username and password.", "error");
  }

  setLoading(true);
  hideAlert();

  try {
    const body = new URLSearchParams({ username, password });
    const res  = await fetch(`${API_BASE}/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const data = await res.json();

    // ── 403 → Account deactivated ─────────────────────────────────────────────
    if (res.status === 403 && data.detail === "ACCOUNT_DEACTIVATED") {
      showDeactivatedPopup(username);
      return;
    }

    // ── 401 → Wrong credentials ───────────────────────────────────────────────
    if (!res.ok) {
      showAlert(data.detail || "Login failed. Check your credentials.", "error");
      return;
    }

    // ── Success ───────────────────────────────────────────────────────────────
    Auth.save(data.access_token, remember);
    showAlert("Login successful! Redirecting...", "success");
    setTimeout(() => { window.location.href = "dashboard.html"; }, 800);

  } catch {
    showAlert("Cannot connect to API server. Is it running?", "error");
  } finally {
    setLoading(false);
  }
}

// ── Deactivated Account Popup ─────────────────────────────────────────────────
function showDeactivatedPopup(username) {
  // Remove any existing popup
  const existing = document.getElementById("deactivatedPopup");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id        = "deactivatedPopup";
  overlay.className = "deact-overlay";
  overlay.innerHTML = `
    <div class="deact-modal">
      <!-- Icon -->
      <div class="deact-icon-wrap">
        <div class="deact-icon-ring"></div>
        <i class="bi bi-person-slash deact-icon"></i>
      </div>

      <!-- Content -->
      <h3 class="deact-title">Account Deactivated</h3>
      <p class="deact-username">@${username}</p>
      <p class="deact-body">
        Your account has been deactivated by an administrator
        and you are currently unable to access the system.
      </p>

      <!-- Info box -->
      <div class="deact-info-box">
        <i class="bi bi-info-circle-fill"></i>
        <span>Contact your system administrator to restore access to your account.</span>
      </div>

      <!-- Actions -->
      <div class="deact-actions">
        <a href="mailto:admin@ids-ml.local" class="deact-btn-email">
          <i class="bi bi-envelope-fill me-2"></i>Email Admin
        </a>
        <button class="deact-btn-close" onclick="closeDeactivatedPopup()">
          <i class="bi bi-x-lg me-2"></i>Close
        </button>
      </div>

      <!-- Footer note -->
      <p class="deact-footer">IDS-ML v2.0 &nbsp;•&nbsp; Access Control System</p>
    </div>`;

  // Close on backdrop click
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeDeactivatedPopup();
  });

  document.body.appendChild(overlay);

  // Trigger animation
  requestAnimationFrame(() => overlay.classList.add("visible"));
}

function closeDeactivatedPopup() {
  const el = document.getElementById("deactivatedPopup");
  if (!el) return;
  el.classList.remove("visible");
  el.classList.add("hiding");
  setTimeout(() => el.remove(), 300);
}

// ── Quick login ───────────────────────────────────────────────────────────────
function quickLogin(username, password) {
  document.getElementById("username").value = username;
  document.getElementById("password").value = password;
  doLogin(username, password, false);
}

// ── Toggle password ───────────────────────────────────────────────────────────
function togglePassword() {
  const input   = document.getElementById("password");
  const icon    = document.getElementById("eyeIcon");
  const visible = input.type === "text";
  input.type    = visible ? "password" : "text";
  icon.className = visible ? "bi bi-eye" : "bi bi-eye-slash";
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function setLoading(on) {
  const btn = document.getElementById("loginBtn");
  document.getElementById("btnText").classList.toggle("d-none", on);
  document.getElementById("btnSpinner").classList.toggle("d-none", !on);
  btn.disabled = on;
}
function showAlert(msg, type) {
  const b = document.getElementById("alertBox");
  b.textContent = msg; b.className = `alert-area ${type}`;
}
function hideAlert() {
  document.getElementById("alertBox").className = "alert-area d-none";
}

// ── Particle background ───────────────────────────────────────────────────────
function generateParticles() {
  const c = document.getElementById("particles");
  for (let i = 0; i < 20; i++) {
    const p = document.createElement("div"); p.className = "particle";
    const s = Math.random() * 12 + 4;
    p.style.cssText = `width:${s}px;height:${s}px;left:${Math.random()*100}%;`
      + `animation-duration:${Math.random()*15+8}s;animation-delay:${Math.random()*10}s;`;
    c.appendChild(p);
  }
}
