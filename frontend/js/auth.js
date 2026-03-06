// js/auth.js — JWT token management
const API_BASE = "http://localhost:8000";

const Auth = {
  // Save token + user info
  save(token, remember = false) {
    const store = remember ? localStorage : sessionStorage;
    store.setItem("ids_token", token);
  },

  // Get token
  getToken() {
    return localStorage.getItem("ids_token") || sessionStorage.getItem("ids_token");
  },

  // Remove token
  clear() {
    localStorage.removeItem("ids_token");
    sessionStorage.removeItem("ids_token");
  },

  // Check if logged in
  isLoggedIn() {
    const token = this.getToken();
    if (!token) return false;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.exp > Date.now() / 1000;
    } catch { return false; }
  },

  // Decode token payload
  decode() {
    const token = this.getToken();
    if (!token) return null;
    try { return JSON.parse(atob(token.split(".")[1])); }
    catch { return null; }
  },

  // Auth headers
  headers(extra = {}) {
    return {
      "Authorization": `Bearer ${this.getToken()}`,
      "Content-Type": "application/json",
      ...extra
    };
  },

  // Redirect to login if not authenticated
  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = "index.html";
      return false;
    }
    return true;
  }
};

// Global logout function
function logout() {
  Auth.clear();
  window.location.href = "index.html";
}
