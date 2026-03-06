// js/register.js
document.addEventListener("DOMContentLoaded", () => {
  if (Auth.isLoggedIn()) { window.location.href = "dashboard.html"; return; }
  generateParticles();
  document.getElementById("password").addEventListener("input", updateStrength);
});

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("username").value.trim();
  const email    = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const confirm  = document.getElementById("confirmPassword").value;

  if (!username || !email || !password || !confirm) {
    return showAlert("All fields are required.", "error");
  }
  if (username.length < 3) return showAlert("Username must be at least 3 characters.", "error");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showAlert("Enter a valid email address.", "error");
  if (password.length < 6) return showAlert("Password must be at least 6 characters.", "error");
  if (password !== confirm) return showAlert("Passwords do not match.", "error");

  setLoading(true); hideAlert();

  try {
    const body = JSON.stringify({ username, email, password });
    const res  = await fetch(`${API_BASE}/register`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body
    });
    const data = await res.json();

    if (!res.ok) {
      showAlert(data.detail || "Registration failed.", "error");
      return;
    }
    showAlert("Account created! Redirecting to login...", "success");
    setTimeout(() => { window.location.href = "index.html?registered=1"; }, 1800);
  } catch {
    showAlert("Cannot connect to API. Is the server running?", "error");
  } finally {
    setLoading(false);
  }
});

// Password strength
function updateStrength() {
  const val  = document.getElementById("password").value;
  const fill = document.getElementById("pwdFill");
  const lbl  = document.getElementById("pwdLabel");
  let score  = 0;
  if (val.length >= 6)          score++;
  if (val.length >= 10)         score++;
  if (/[A-Z]/.test(val))        score++;
  if (/[0-9]/.test(val))        score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;

  const levels = [
    { w:"0%",   color:"transparent", text:"" },
    { w:"25%",  color:"#ef4444",     text:"Weak" },
    { w:"50%",  color:"#f59e0b",     text:"Fair" },
    { w:"75%",  color:"#3b82f6",     text:"Good" },
    { w:"100%", color:"#22c55e",     text:"Strong" },
  ];
  const lvl     = levels[Math.min(score, 4)];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.color;
  lbl.textContent       = lvl.text;
  lbl.style.color       = lvl.color;
}

function togglePass(inputId, iconId) {
  const inp  = document.getElementById(inputId);
  const icon = document.getElementById(iconId);
  const show = inp.type === "text";
  inp.type       = show ? "password" : "text";
  icon.className = show ? "bi bi-eye" : "bi bi-eye-slash";
}

function setLoading(on) {
  const btn = document.getElementById("registerBtn");
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
