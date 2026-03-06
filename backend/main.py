# backend/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

from backend.database import create_tables, get_db
from backend.models import User, RoleRequest
from backend.auth import (
    create_access_token, hash_password, verify_password,
    get_current_user, Token, UserOut, require_roles
)

DEFAULT_ADMIN = {
    "username": "admin",
    "email":    "admin@ids-ml.local",
    "password": "admin123",
    "role":     "admin",
}

def seed_default_admin(db):
    """Create default admin on first boot if no admin exists."""
    existing = db.query(User).filter(User.username == DEFAULT_ADMIN["username"]).first()
    if existing:
        return  # already seeded
    admin = User(
        username        = DEFAULT_ADMIN["username"],
        email           = DEFAULT_ADMIN["email"],
        hashed_password = hash_password(DEFAULT_ADMIN["password"]),
        role            = DEFAULT_ADMIN["role"],
        is_active       = True,
    )
    db.add(admin)
    db.commit()
    print("\n" + "="*50)
    print("  🔐 DEFAULT ADMIN ACCOUNT CREATED")
    print("="*50)
    print(f"  Username : {DEFAULT_ADMIN['username']}")
    print(f"  Password : {DEFAULT_ADMIN['password']}")
    print(f"  Role     : {DEFAULT_ADMIN['role']}")
    print("  ⚠️  Change this password after first login!")
    print("="*50 + "\n")

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    # Seed default admin (only runs if DB is empty)
    db = next(get_db())
    try:
        seed_default_admin(db)
    finally:
        db.close()
    print("IDS-ML v2.0 API started!")
    yield

app = FastAPI(title="IDS-ML v2.0 API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── Schemas ───────────────────────────────────────────────────────────────────
class PublicRegister(BaseModel):
    username: str
    email: str
    password: str

class UpdateProfile(BaseModel):
    email:        Optional[str] = None
    display_name: Optional[str] = None

class ChangePassword(BaseModel):
    current_password: str
    new_password:     str

class RoleRequestCreate(BaseModel):
    requested_role: str
    reason:         Optional[str] = ""

class RoleUpdate(BaseModel):
    role: str

class AdminCreateUser(BaseModel):
    username: str
    email:    str
    password: str
    role:     str = "viewer"

class ResetPassword(BaseModel):
    new_password: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def user_dict(u):
    return {"id":u.id,"username":u.username,"email":u.email,
            "display_name":u.display_name,"role":u.role,
            "is_active":u.is_active,"created_at":str(u.created_at),
            "last_login":str(u.last_login) if u.last_login else None}

# ── Root / Health ─────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root(): return RedirectResponse(url="/docs")

@app.get("/health", tags=["System"])
async def health():
    return {"status":"ok","version":"2.0.0","message":"IDS-ML v2.0 running!"}

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/login", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password",
                            headers={"WWW-Authenticate":"Bearer"})
    if not user.is_active:
        raise HTTPException(status_code=403, detail="ACCOUNT_DEACTIVATED")
    user.last_login = datetime.utcnow(); db.commit()
    return {"access_token": create_access_token({"sub": user.username}), "token_type": "bearer"}

@app.post("/register", tags=["Auth"], status_code=201)
async def register(data: PublicRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    if len(data.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    u = User(username=data.username, email=data.email,
             hashed_password=hash_password(data.password), role="viewer", is_active=True)
    db.add(u); db.commit(); db.refresh(u)
    return {"message":"Account created! You have been assigned the viewer role.", "username":u.username, "role":u.role}

@app.get("/me", response_model=UserOut, tags=["Auth"])
async def get_me(me: User = Depends(get_current_user)):
    return me

# ══════════════════════════════════════════════════════════════════════════════
# SELF — every logged-in user
# ══════════════════════════════════════════════════════════════════════════════
@app.patch("/me/profile", tags=["Self"])
async def update_profile(data: UpdateProfile, db: Session = Depends(get_db),
                         me: User = Depends(get_current_user)):
    """Update own email and/or display name."""
    if data.email and data.email != me.email:
        if db.query(User).filter(User.email == data.email, User.id != me.id).first():
            raise HTTPException(400, "Email already in use by another account")
        me.email = data.email
    if data.display_name is not None:
        me.display_name = data.display_name.strip() or None
    db.commit(); db.refresh(me)
    return {"message": "Profile updated", "user": user_dict(me)}

@app.patch("/me/password", tags=["Self"])
async def change_password(data: ChangePassword, db: Session = Depends(get_db),
                          me: User = Depends(get_current_user)):
    """Change own password — requires current password."""
    if not verify_password(data.current_password, me.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if len(data.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    if data.current_password == data.new_password:
        raise HTTPException(400, "New password must differ from current password")
    me.hashed_password = hash_password(data.new_password); db.commit()
    return {"message": "Password changed successfully"}

@app.post("/me/role-request", tags=["Self"], status_code=201)
async def request_role(data: RoleRequestCreate, db: Session = Depends(get_db),
                       me: User = Depends(get_current_user)):
    """Submit an access upgrade request for admin review."""
    valid = {"admin","analyst","viewer"}
    if data.requested_role not in valid:
        raise HTTPException(400, "Invalid role")
    if data.requested_role == me.role:
        raise HTTPException(400, f"You already have the '{me.role}' role")

    # Only 1 pending request allowed at a time
    existing = db.query(RoleRequest).filter(
        RoleRequest.user_id == me.id,
        RoleRequest.status  == "pending"
    ).first()
    if existing:
        raise HTTPException(400, "You already have a pending access request. Wait for admin review.")

    req = RoleRequest(user_id=me.id, username=me.username,
                      current_role=me.role, requested_role=data.requested_role,
                      reason=data.reason or "")
    db.add(req); db.commit(); db.refresh(req)
    return {"message": f"Access request submitted for '{data.requested_role}' role. Pending admin review.",
            "request_id": req.id}

@app.get("/me/role-request", tags=["Self"])
async def my_role_request(db: Session = Depends(get_db),
                          me: User = Depends(get_current_user)):
    """Get own pending role request (if any)."""
    req = db.query(RoleRequest).filter(
        RoleRequest.user_id == me.id
    ).order_by(RoleRequest.created_at.desc()).first()
    if not req: return {"request": None}
    return {"request": {"id":req.id,"requested_role":req.requested_role,
            "current_role":req.current_role,"reason":req.reason,
            "status":req.status,"created_at":str(req.created_at),
            "reviewed_by":req.reviewed_by,"reviewed_at":str(req.reviewed_at) if req.reviewed_at else None}}

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/users", tags=["Admin"])
async def list_users(db: Session = Depends(get_db), _=Depends(require_roles("admin"))):
    return [user_dict(u) for u in db.query(User).order_by(User.id).all()]

@app.post("/admin/users", tags=["Admin"], status_code=201)
async def admin_create(data: AdminCreateUser, db: Session = Depends(get_db),
                        _=Depends(require_roles("admin"))):
    if data.role not in ("admin","analyst","viewer"):
        raise HTTPException(400, "Invalid role")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    u = User(username=data.username, email=data.email,
             hashed_password=hash_password(data.password), role=data.role, is_active=True)
    db.add(u); db.commit(); db.refresh(u)
    return {"message": f"User '{u.username}' created as {u.role}", "id": u.id}

@app.patch("/admin/users/{uid}/role", tags=["Admin"])
async def admin_change_role(uid: int, data: RoleUpdate, db: Session = Depends(get_db),
                             me: User = Depends(require_roles("admin"))):
    if data.role not in ("admin","analyst","viewer"):
        raise HTTPException(400, "Invalid role")
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot change your own role")
    old = u.role; u.role = data.role; db.commit()
    return {"message": f"'{u.username}' role: {old} → {data.role}"}

@app.patch("/admin/users/{uid}/activate", tags=["Admin"])
async def admin_activate(uid: int, db: Session = Depends(get_db),
                          me: User = Depends(require_roles("admin"))):
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot modify own account")
    u.is_active = True; db.commit()
    return {"message": f"'{u.username}' activated"}

@app.patch("/admin/users/{uid}/deactivate", tags=["Admin"])
async def admin_deactivate(uid: int, db: Session = Depends(get_db),
                            me: User = Depends(require_roles("admin"))):
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot modify own account")
    u.is_active = False; db.commit()
    return {"message": f"'{u.username}' deactivated"}

@app.delete("/admin/users/{uid}", tags=["Admin"])
async def admin_delete(uid: int, db: Session = Depends(get_db),
                        me: User = Depends(require_roles("admin"))):
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot delete own account")
    db.delete(u); db.commit()
    return {"message": f"'{u.username}' deleted"}

@app.patch("/admin/users/{uid}/reset-password", tags=["Admin"])
async def admin_reset_pwd(uid: int, data: ResetPassword, db: Session = Depends(get_db),
                           _=Depends(require_roles("admin"))):
    if len(data.new_password) < 6: raise HTTPException(400, "Min 6 characters")
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    u.hashed_password = hash_password(data.new_password); db.commit()
    return {"message": f"Password reset for '{u.username}'"}

# ── Admin: Role Requests ──────────────────────────────────────────────────────
@app.get("/admin/role-requests", tags=["Admin"])
async def get_role_requests(status: Optional[str] = None, db: Session = Depends(get_db),
                             _=Depends(require_roles("admin"))):
    q = db.query(RoleRequest)
    if status: q = q.filter(RoleRequest.status == status)
    reqs = q.order_by(RoleRequest.created_at.desc()).all()
    return [{"id":r.id,"user_id":r.user_id,"username":r.username,
             "current_role":r.current_role,"requested_role":r.requested_role,
             "reason":r.reason,"status":r.status,"created_at":str(r.created_at),
             "reviewed_by":r.reviewed_by,
             "reviewed_at":str(r.reviewed_at) if r.reviewed_at else None} for r in reqs]

@app.patch("/admin/role-requests/{req_id}/approve", tags=["Admin"])
async def approve_request(req_id: int, db: Session = Depends(get_db),
                          me: User = Depends(require_roles("admin"))):
    req = db.query(RoleRequest).filter(RoleRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Request not found")
    if req.status != "pending": raise HTTPException(400, f"Request already {req.status}")
    # Apply role change
    user = db.query(User).filter(User.id == req.user_id).first()
    if user: user.role = req.requested_role
    req.status = "approved"; req.reviewed_by = me.username; req.reviewed_at = datetime.utcnow()
    db.commit()
    return {"message": f"Approved: '{req.username}' is now {req.requested_role}"}

@app.patch("/admin/role-requests/{req_id}/reject", tags=["Admin"])
async def reject_request(req_id: int, db: Session = Depends(get_db),
                         me: User = Depends(require_roles("admin"))):
    req = db.query(RoleRequest).filter(RoleRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Request not found")
    if req.status != "pending": raise HTTPException(400, f"Request already {req.status}")
    req.status = "rejected"; req.reviewed_by = me.username; req.reviewed_at = datetime.utcnow()
    db.commit()
    return {"message": f"Rejected access request from '{req.username}'"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
