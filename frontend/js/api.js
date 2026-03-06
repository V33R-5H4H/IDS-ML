// js/api.js — Centralised API calls
const API = {
  // Generic fetch wrapper
  async request(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: Auth.headers(),
      ...options
    });
    if (res.status === 401) { Auth.clear(); window.location.href = "index.html"; return null; }
    return res;
  },

  // GET /health
  async health() {
    try {
      const res = await fetch(`${API_BASE}/health`);
      return await res.json();
    } catch { return null; }
  },

  // GET /me
  async me() {
    const res = await this.request("/me");
    return res ? await res.json() : null;
  },

  // GET /users (admin only)
  async users() {
    const res = await this.request("/users");
    if (!res || !res.ok) return [];
    return await res.json();
  },

  // PATCH /users/:id/deactivate (admin only)
  async deactivateUser(id) {
    const res = await this.request(`/users/${id}/deactivate`, { method: "PATCH" });
    return res && res.ok;
  }
};
