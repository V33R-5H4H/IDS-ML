// js/login.js
document.addEventListener("DOMContentLoaded", () => {
  if (Auth.isLoggedIn()) {
    window.location.href = "dashboard.html";
    return;
  }
  document.getElementById("loginUsername")?.focus();
});

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  const remember = document.getElementById("rememberMe").checked;
  const btn      = document.getElementById("loginBtn");
  const alert    = document.getElementById("loginAlert");

  if (!username || !password) {
    return showAlert(alert, "Please enter your username and password.", "error");
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-sm"></span> Signing in…`;
  clearAlert(alert);

  try {
    const res = await fetch(`${API_BASE}/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    });

    const data = await res.json();

    if (!res.ok) {
      showAlert(alert, data.detail || "Invalid username or password.", "error");
      return;
    }

    Auth.save(data.access_token, remember);
    window.location.href = "dashboard.html";

  } catch (err) {
    showAlert(alert, "Cannot connect to the server. Is the backend running?", "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-box-arrow-in-right me-2"></i>Sign In`;
  }
}

function togglePw(id, btn) {
  const input = document.getElementById(id);
  const icon  = btn.querySelector("i");
  if (input.type === "password") {
    input.type = "text";
    icon.className = "bi bi-eye-slash";
  } else {
    input.type = "password";
    icon.className = "bi bi-eye";
  }
}

function showForgot() {
  document.getElementById("forgotModal").style.display = "flex";
  document.getElementById("forgotIdentifier")?.focus();
}
function hideForgot() {
  document.getElementById("forgotModal").style.display = "none";
  clearAlert(document.getElementById("forgotAlert"));
}

async function submitForgot() {
  const identifier = document.getElementById("forgotIdentifier").value.trim();
  const reason     = document.getElementById("forgotReason").value.trim();
  const alertEl    = document.getElementById("forgotAlert");

  if (!identifier) return showAlert(alertEl, "Please enter your username or email.", "error");

  try {
    const r = await API.forgotPassword(identifier, reason);
    if (r && r.ok) {
      showAlert(alertEl, "Request submitted! An admin will reset your password.", "success");
    } else {
      const d = r ? await r.json().catch(() => ({})) : {};
      showAlert(alertEl, d.detail || "Failed to submit request.", "error");
    }
  } catch {
    showAlert(alertEl, "Cannot connect to server.", "error");
  }
}

// ── Helpers ──────────────────────────────────────────────────────
function showAlert(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className = `auth-alert ${type}`;
  el.style.display = "block";
}
function clearAlert(el) {
  if (!el) return;
  el.textContent = "";
  el.className = "auth-alert d-none";
}
