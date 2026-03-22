// js/register.js

document.addEventListener("DOMContentLoaded", () => {
  if (typeof Auth !== "undefined" && Auth.isLoggedIn()) {
    window.location.href = "dashboard.html";
    return;
  }
  document.getElementById("regUsername")?.focus();
});

async function handleRegister(e) {
  e.preventDefault();

  const username = document.getElementById("regUsername").value.trim();
  const email    = document.getElementById("regEmail").value.trim();
  const password = document.getElementById("regPassword").value;
  const confirm  = document.getElementById("regConfirm").value;
  const btn      = document.getElementById("registerBtn");

  clearAlert();

  if (!username)          return showAlert("Username is required.", "error");
  if (!email)             return showAlert("Email is required.", "error");
  if (!password)          return showAlert("Password is required.", "error");
  if (password.length < 6)return showAlert("Password must be at least 6 characters.", "error");
  if (password !== confirm)return showAlert("Passwords do not match.", "error");

  btn.disabled = true;
  btn.innerHTML =
    `<span class="spinner-sm"></span> Creating account…`;

  try {
    const result = await API.register(username, email, password);
    if (result.ok) {
      showAlert("Account created! Redirecting to login…", "success");
      setTimeout(() => { window.location.href = "index.html"; }, 1600);
    } else {
      showAlert(result.data?.detail || "Registration failed. Try a different username.", "error");
      btn.disabled = false;
      btn.innerHTML = `<i class="bi bi-person-plus me-2"></i>Create Account`;
    }
  } catch {
    showAlert("Cannot connect to the server. Is the backend running?", "error");
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-person-plus me-2"></i>Create Account`;
  }
}

// ── Password toggle ────────────────────────────────────────────
function togglePw(inputId, btn) {
  const input = document.getElementById(inputId);
  const icon  = btn.querySelector("i");
  if (!input) return;
  if (input.type === "password") {
    input.type     = "text";
    icon.className = "bi bi-eye-slash";
  } else {
    input.type     = "password";
    icon.className = "bi bi-eye";
  }
}

// ── Strength bar ───────────────────────────────────────────────
function updatePwStrength(val) {
  const bar = document.getElementById("regPwBar");
  const lbl = document.getElementById("regPwLabel");
  if (!bar || !lbl) return;

  let score = 0;
  if (val.length >= 6)           score++;
  if (val.length >= 10)          score++;
  if (/[A-Z]/.test(val))         score++;
  if (/[0-9]/.test(val))         score++;
  if (/[^A-Za-z0-9]/.test(val))  score++;

  const levels = [
    { w: "0%",   bg: "transparent", txt: ""          },
    { w: "20%",  bg: "#ef4444",     txt: "Weak"      },
    { w: "40%",  bg: "#f59e0b",     txt: "Fair"      },
    { w: "60%",  bg: "#f59e0b",     txt: "Good"      },
    { w: "80%",  bg: "#22c55e",     txt: "Strong"    },
    { w: "100%", bg: "#14b8a6",     txt: "Excellent" },
  ];
  const lvl = levels[Math.min(score, 5)];
  bar.style.width      = lvl.w;
  bar.style.background = lvl.bg;
  lbl.textContent      = lvl.txt;
  lbl.style.color      = lvl.bg;
}

// ── Alert helpers ──────────────────────────────────────────────
function showAlert(msg, type) {
  const el = document.getElementById("registerAlert");
  if (!el) return;
  el.textContent = msg;
  el.className   = `auth-alert ${type}`;
}

function clearAlert() {
  const el = document.getElementById("registerAlert");
  if (!el) return;
  el.textContent = "";
  el.className   = "auth-alert";
  el.style.display = "none";
}
