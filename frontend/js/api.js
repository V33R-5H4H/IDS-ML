// js/api.js — Centralised API calls (API_BASE from auth.js)
const API = {

  async request(path, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        headers: Auth.headers(),
        ...options
      });
      if (res.status === 401) { Auth.clear(); window.location.href = "index.html"; return null; }
      return res;
    } catch (e) { return null; }
  },

  async health() {
    try { const r = await fetch(`${API_BASE}/health`); return await r.json(); }
    catch { return null; }
  },

  async me() {
    const r = await this.request("/me");
    return r && r.ok ? await r.json() : null;
  },

  // ── Public Registration ──────────────────────────────────────────────────
  async register(username, email, password) {
    try {
      const r = await fetch(`${API_BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password })
      });
      return { ok: r.ok, data: await r.json() };
    } catch { return { ok: false, data: { detail: "Cannot connect to server" } }; }
  },

  // ── Admin: List Users ────────────────────────────────────────────────────
  async users() {
    const r = await this.request("/users");
    return r && r.ok ? await r.json() : [];
  },

  // ── Admin: Create User ───────────────────────────────────────────────────
  async createUser(username, email, password, role) {
    const r = await this.request("/admin/users", {
      method: "POST",
      body: JSON.stringify({ username, email, password, role })
    });
    return r ? { ok: r.ok, data: await r.json() } : { ok: false, data: { detail: "Error" } };
  },

  // ── Admin: Change Role ───────────────────────────────────────────────────
  async changeRole(userId, role) {
    const r = await this.request(`/admin/users/${userId}/role`, {
      method: "PATCH",
      body: JSON.stringify({ role })
    });
    return r ? { ok: r.ok, data: await r.json() } : { ok: false, data: { detail: "Error" } };
  },

  // ── Admin: Activate / Deactivate ─────────────────────────────────────────
  async activateUser(id) {
    const r = await this.request(`/admin/users/${id}/activate`, { method: "PATCH" });
    return r && r.ok;
  },
  async deactivateUser(id) {
    const r = await this.request(`/admin/users/${id}/deactivate`, { method: "PATCH" });
    return r && r.ok;
  },

  // ── Admin: Delete User ───────────────────────────────────────────────────
  async deleteUser(id) {
    const r = await this.request(`/admin/users/${id}`, { method: "DELETE" });
    return r ? { ok: r.ok, data: await r.json() } : { ok: false, data: { detail: "Error" } };
  },

  // ── Admin: Reset Password ────────────────────────────────────────────────
  async resetPassword(id, newPassword) {
    const r = await this.request(`/admin/users/${id}/reset-password`, {
      method: "PATCH",
      body: JSON.stringify({ new_password: newPassword })
    });
    return r ? { ok: r.ok, data: await r.json() } : { ok: false, data: { detail: "Error" } };
  }
};
