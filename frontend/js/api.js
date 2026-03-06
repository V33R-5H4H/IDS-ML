// js/api.js  (API_BASE declared in auth.js)
const API = {

  async request(path, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        headers: Auth.headers(), ...options
      });
      if (res.status === 401) { Auth.clear(); window.location.href = "index.html"; return null; }
      return res;
    } catch { return null; }
  },

  async health() {
    try { const r = await fetch(`${API_BASE}/health`); return await r.json(); } catch { return null; }
  },

  async me() {
    const r = await this.request("/me");
    return r && r.ok ? await r.json() : null;
  },

  // ── Public Registration ────────────────────────────────────────────────────
  async register(username, email, password) {
    try {
      const r = await fetch(`${API_BASE}/register`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({username, email, password})
      });
      return {ok: r.ok, data: await r.json()};
    } catch { return {ok:false, data:{detail:"Cannot connect to server"}}; }
  },

  // ── Self — profile & password ──────────────────────────────────────────────
  async updateProfile(email, displayName) {
    const r = await this.request("/me/profile", {
      method: "PATCH",
      body: JSON.stringify({email, display_name: displayName})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async changePassword(currentPassword, newPassword) {
    const r = await this.request("/me/password", {
      method: "PATCH",
      body: JSON.stringify({current_password: currentPassword, new_password: newPassword})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  // ── Role requests (self) ───────────────────────────────────────────────────
  async submitRoleRequest(requestedRole, reason) {
    const r = await this.request("/me/role-request", {
      method: "POST",
      body: JSON.stringify({requested_role: requestedRole, reason})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async getMyRoleRequest() {
    const r = await this.request("/me/role-request");
    return r && r.ok ? await r.json() : {request: null};
  },

  // ── Admin: Users ───────────────────────────────────────────────────────────
  async users() {
    const r = await this.request("/users");
    return r && r.ok ? await r.json() : [];
  },

  async createUser(username, email, password, role) {
    const r = await this.request("/admin/users", {
      method: "POST", body: JSON.stringify({username, email, password, role})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async changeRole(userId, role) {
    const r = await this.request(`/admin/users/${userId}/role`, {
      method: "PATCH", body: JSON.stringify({role})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async activateUser(id) {
    const r = await this.request(`/admin/users/${id}/activate`, {method:"PATCH"});
    return r && r.ok;
  },

  async deactivateUser(id) {
    const r = await this.request(`/admin/users/${id}/deactivate`, {method:"PATCH"});
    return r && r.ok;
  },

  async deleteUser(id) {
    const r = await this.request(`/admin/users/${id}`, {method:"DELETE"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async resetPassword(id, newPassword) {
    const r = await this.request(`/admin/users/${id}/reset-password`, {
      method: "PATCH", body: JSON.stringify({new_password: newPassword})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  // ── Admin: Role Requests ───────────────────────────────────────────────────
  async getRoleRequests(status = "pending") {
    const r = await this.request(`/admin/role-requests?status=${status}`);
    return r && r.ok ? await r.json() : [];
  },

  async approveRoleRequest(reqId) {
    const r = await this.request(`/admin/role-requests/${reqId}/approve`, {method:"PATCH"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  async rejectRoleRequest(reqId) {
    const r = await this.request(`/admin/role-requests/${reqId}/reject`, {method:"PATCH"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  }
};
