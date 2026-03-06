// js/api.js  (API_BASE declared in config.js)
window.API = {

  request: async function(path, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        headers: Auth.headers(), ...options
      });
      if (res.status === 401) { Auth.clear(); window.location.href = "index.html"; return null; }
      return res;
    } catch(e) { return null; }
  },

  health: async function() {
    try { const r = await fetch(`${API_BASE}/health`); return await r.json(); } catch(e) { return null; }
  },

  me: async function() {
    const r = await this.request("/me");
    return r && r.ok ? await r.json() : null;
  },

  // ── Public Registration ────────────────────────────────────────────────────
  register: async function(username, email, password) {
    try {
      const r = await fetch(`${API_BASE}/register`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({username, email, password})
      });
      return {ok: r.ok, data: await r.json()};
    } catch(e) { return {ok:false, data:{detail:"Cannot connect to server"}}; }
  },

  // ── Self — profile & password ──────────────────────────────────────────────
  updateProfile: async function(email, displayName) {
    const r = await this.request("/me/profile", {
      method: "PATCH",
      body: JSON.stringify({email, display_name: displayName})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  changePassword: async function(currentPassword, newPassword) {
    const r = await this.request("/me/password", {
      method: "PATCH",
      body: JSON.stringify({current_password: currentPassword, new_password: newPassword})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  // ── Role requests (self) ───────────────────────────────────────────────────
  submitRoleRequest: async function(requestedRole, reason) {
    const r = await this.request("/me/role-request", {
      method: "POST",
      body: JSON.stringify({requested_role: requestedRole, reason})
    });
    return r ? {ok: r.ok, data: await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  getMyRoleRequest: async function() {
    const r = await this.request("/me/role-request");
    return r && r.ok ? await r.json() : {request: null};
  },

  // ── Admin: Users ───────────────────────────────────────────────────────────
  users: async function() {
    const r = await this.request("/users");
    return r && r.ok ? await r.json() : [];
  },

  createUser: async function(username, email, password, role) {
    const r = await this.request("/admin/users", {
      method: "POST", body: JSON.stringify({username, email, password, role})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  changeRole: async function(userId, role) {
    const r = await this.request(`/admin/users/${userId}/role`, {
      method: "PATCH", body: JSON.stringify({role})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  activateUser: async function(id) {
    const r = await this.request(`/admin/users/${id}/activate`, {method:"PATCH"});
    return r && r.ok;
  },

  deactivateUser: async function(id) {
    const r = await this.request(`/admin/users/${id}/deactivate`, {method:"PATCH"});
    return r && r.ok;
  },

  deleteUser: async function(id) {
    const r = await this.request(`/admin/users/${id}`, {method:"DELETE"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  resetPassword: async function(id, newPassword) {
    const r = await this.request(`/admin/users/${id}/reset-password`, {
      method: "PATCH", body: JSON.stringify({new_password: newPassword})
    });
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  // ── Admin: Role Requests ───────────────────────────────────────────────────
  getRoleRequests: async function(status = "pending") {
    const r = await this.request(`/admin/role-requests?status=${status}`);
    return r && r.ok ? await r.json() : [];
  },

  approveRoleRequest: async function(reqId) {
    const r = await this.request(`/admin/role-requests/${reqId}/approve`, {method:"PATCH"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },

  rejectRoleRequest: async function(reqId) {
    const r = await this.request(`/admin/role-requests/${reqId}/reject`, {method:"PATCH"});
    return r ? {ok:r.ok, data:await r.json()} : {ok:false, data:{detail:"Error"}};
  },
  // ── Forgot password (public) ──────────────────────────────────────────────
  forgotPassword: async function(identifier, reason = "") {
    return this.request("/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, reason })
    });
  },

  // ── Admin: password resets ────────────────────────────────────────────────
  getPasswordResets: async function() {
    return this.request("/admin/password-resets");
  },

  resolvePasswordReset: async function(id, new_password) {
    return this.request(`/admin/password-resets/${id}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ new_password })
    });
  },

  dismissPasswordReset: async function(id) {
    return this.request(`/admin/password-resets/${id}/dismiss`, { method: "POST" });
  },

};
