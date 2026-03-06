// js/login.js — Login page logic
document.addEventListener("DOMContentLoaded", () => {
  // Already logged in? Go to dashboard
  if (Auth.isLoggedIn()) {
    window.location.href = "dashboard.html";
    return;
  }
  generateParticles();
});

// Handle form submit
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  await doLogin(
    document.getElementById("username").value.trim(),
    document.getElementById("password").value,
    document.getElementById("rememberMe").checked
  );
});

async function doLogin(username, password, remember = false) {
  if (!username || !password) {
    showAlert("Please enter both username and password.", "error");
    return;
  }

  setLoading(true);
  hideAlert();

  try {
    const body = new URLSearchParams({ username, password });
    const res  = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const data = await res.json();

    if (!res.ok) {
      showAlert(data.detail || "Login failed. Check your credentials.", "error");
      return;
    }

    // Save token and redirect
    Auth.save(data.access_token, remember);
    showAlert("Login successful! Redirecting...", "success");
    setTimeout(() => { window.location.href = "dashboard.html"; }, 800);

  } catch (err) {
    showAlert("Cannot connect to API. Is the server running?", "error");
  } finally {
    setLoading(false);
  }
}

// Quick login buttons
function quickLogin(username, password) {
  document.getElementById("username").value = username;
  document.getElementById("password").value = password;
  doLogin(username, password, false);
}

// Toggle password visibility
function togglePassword() {
  const input   = document.getElementById("password");
  const icon    = document.getElementById("eyeIcon");
  const visible = input.type === "text";
  input.type    = visible ? "password" : "text";
  icon.className = visible ? "bi bi-eye" : "bi bi-eye-slash";
}

// UI helpers
function setLoading(on) {
  const btn = document.getElementById("loginBtn");
  document.getElementById("btnText").classList.toggle("d-none", on);
  document.getElementById("btnSpinner").classList.toggle("d-none", !on);
  btn.disabled = on;
}

function showAlert(msg, type) {
  const box = document.getElementById("alertBox");
  box.textContent = msg;
  box.className   = `alert-area ${type}`;
}

function hideAlert() {
  document.getElementById("alertBox").className = "alert-area d-none";
}

// Particle background
function generateParticles() {
  const container = document.getElementById("particles");
  for (let i = 0; i < 20; i++) {
    const p = document.createElement("div");
    p.className = "particle";
    const size = Math.random() * 12 + 4;
    p.style.cssText = `
      width:${size}px; height:${size}px;
      left:${Math.random()*100}%;
      animation-duration:${Math.random()*15+8}s;
      animation-delay:${Math.random()*10}s;
    `;
    container.appendChild(p);
  }
}
