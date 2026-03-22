// js/auth.js — JWT token management
window.Auth = {

  save(token, remember = false) {
    const store = remember ? localStorage : sessionStorage;
    store.setItem("ids_token", token);
  },

  getToken() {
    return localStorage.getItem("ids_token") || sessionStorage.getItem("ids_token");
  },

  clear() {
    localStorage.removeItem("ids_token");
    sessionStorage.removeItem("ids_token");
  },

  isLoggedIn() {
    const token = this.getToken();
    if (!token) return false;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.exp > Date.now() / 1000;
    } catch { return false; }
  },

  decode() {
    const token = this.getToken();
    if (!token) return null;
    try { return JSON.parse(atob(token.split(".")[1])); }
    catch { return null; }
  },

  headers(extra = {}) {
    return {
      "Authorization": `Bearer ${this.getToken()}`,
      "Content-Type": "application/json",
      ...extra
    };
  },

  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = "index.html";
      return false;
    }
    return true;   // ← was inside the if block before (dead code bug)
  }
};

function handleLogout() {
  Auth.clear();
  window.location.href = "index.html";
}
