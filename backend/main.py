# backend/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

from backend.database import create_tables, get_db, verify_connection
from backend.models import User, RoleRequest, PasswordResetRequest
from backend.models_pcap import PcapAnalysis
from backend.auth import (
    create_access_token, hash_password, verify_password,
    get_current_user, Token, UserOut, require_roles
)
from backend.pcap_analyzer import run_analysis, _orm_to_dict

DEFAULT_ADMIN = {
    "username": "admin",
    "email":    "admin@ids-ml.local",
    "password": "admin123",
    "role":     "admin",
}

def seed_default_admin(db):
    existing = db.query(User).filter(User.username == DEFAULT_ADMIN["username"]).first()
    if existing:
        return
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
    try:
        verify_connection()
        create_tables()
        # Ensure PCAP analysis table exists
        from backend.database import engine
        PcapAnalysis.__table__.create(bind=engine, checkfirst=True)
        print("[DB] ✅ Table ensured: pcap_analysis")
        db = next(get_db())
        try:
            seed_default_admin(db)
        finally:
            db.close()
        print("IDS-ML v2.0 API started! ✅")
    except Exception as e:
        print(f"[STARTUP] ❌ Error during startup: {e}")
        print("[STARTUP] API will continue but DB features may not work.")
    yield

app = FastAPI(title="IDS-ML v2.0 API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ══════════════════════════════════════════════════════════════════════════════
# SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════
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

class ForgotPasswordRequest(BaseModel):
    identifier: str
    reason: Optional[str] = ""

class AdminResolveReset(BaseModel):
    new_password: str

# ── PCAP Schemas ──────────────────────────────────────────────────────────────
class PcapResultOut(BaseModel):
    id:               int
    filename:         str
    sha256:           str
    file_size:        int
    total_packets:    int
    total_bytes:      int
    duration_seconds: float
    unique_src_ips:   int
    unique_dst_ips:   int
    top_protocols:    str
    avg_packet_size:  float
    max_packet_size:  int
    tcp_packets:      int
    udp_packets:      int
    icmp_packets:     int
    bytes_per_second: float
    # ML risk scoring  ← NEW
    risk_score:       Optional[float] = None
    risk_label:       Optional[str]   = None
    model_used:       Optional[str]   = None
    # Metadata
    first_seen:       Optional[str]   = None
    last_seen:        Optional[str]   = None
    created_at:       Optional[str]   = None

    class Config:
        from_attributes = True   # Pydantic v2
        # orm_mode = True        # uncomment for Pydantic v1

class PcapAnalysisResponse(BaseModel):
    duplicate: bool
    message:   str
    result:    PcapResultOut

# ── Helpers ───────────────────────────────────────────────────────────────────
def user_dict(u):
    return {"id":u.id,"username":u.username,"email":u.email,
            "display_name":u.display_name,"role":u.role,
            "is_active":u.is_active,"created_at":str(u.created_at),
            "last_login":str(u.last_login) if u.last_login else None}

# ══════════════════════════════════════════════════════════════════════════════
# ROOT / HEALTH
# ══════════════════════════════════════════════════════════════════════════════
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
    identifier = form_data.username.strip()
    user = (
        db.query(User).filter(User.username == identifier).first() or
        db.query(User).filter(User.email    == identifier).first()
    )
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
    return {"message":"Account created! You have been assigned the viewer role.",
            "username":u.username, "role":u.role}

@app.get("/me", response_model=UserOut, tags=["Auth"])
async def get_me(me: User = Depends(get_current_user)):
    return me

# ══════════════════════════════════════════════════════════════════════════════
# SELF — every logged-in user
# ══════════════════════════════════════════════════════════════════════════════
@app.patch("/me/profile", tags=["Self"])
async def update_profile(data: UpdateProfile, db: Session = Depends(get_db),
                         me: User = Depends(get_current_user)):
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
    valid = {"admin","analyst","viewer"}
    if data.requested_role not in valid:
        raise HTTPException(400, "Invalid role")
    if data.requested_role == me.role:
        raise HTTPException(400, f"You already have the '{me.role}' role")
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
    req = db.query(RoleRequest).filter(
        RoleRequest.user_id == me.id
    ).order_by(RoleRequest.created_at.desc()).first()
    if not req: return {"request": None}
    return {"request": {"id":req.id,"requested_role":req.requested_role,
            "current_role":req.current_role,"reason":req.reason,
            "status":req.status,"created_at":str(req.created_at),
            "reviewed_by":req.reviewed_by,
            "reviewed_at":str(req.reviewed_at) if req.reviewed_at else None}}

# ══════════════════════════════════════════════════════════════════════════════
# FORGOT PASSWORD  (public)
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/forgot-password", tags=["Auth"], status_code=201)
async def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    identifier = data.identifier.strip()
    user = (
        db.query(User).filter(User.username == identifier).first() or
        db.query(User).filter(User.email    == identifier).first()
    )
    if not user:
        return {"message": "If that account exists, a reset request has been submitted."}
    existing = db.query(PasswordResetRequest).filter(
        PasswordResetRequest.user_id == user.id,
        PasswordResetRequest.status  == "pending"
    ).first()
    if existing:
        return {"message": "A reset request is already pending. Please wait for admin to process it."}
    req = PasswordResetRequest(
        user_id  = user.id,
        username = user.username,
        email    = user.email,
        reason   = data.reason or ""
    )
    db.add(req); db.commit(); db.refresh(req)
    return {"message": "Reset request submitted. An administrator will set a new temporary password for you."}

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — PASSWORD RESET MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/admin/password-resets", tags=["Admin"])
async def list_reset_requests(db: Session = Depends(get_db),
                               _=Depends(require_roles("admin"))):
    reqs = db.query(PasswordResetRequest).order_by(
        PasswordResetRequest.created_at.desc()).all()
    return [{"id":r.id,"user_id":r.user_id,"username":r.username,
             "email":r.email,"reason":r.reason,"status":r.status,
             "created_at":str(r.created_at),
             "resolved_at":str(r.resolved_at) if r.resolved_at else None,
             "resolved_by":r.resolved_by} for r in reqs]

@app.post("/admin/password-resets/{req_id}/resolve", tags=["Admin"])
async def resolve_reset(req_id: int, data: AdminResolveReset,
                        db: Session = Depends(get_db),
                        me: User = Depends(require_roles("admin"))):
    req = db.query(PasswordResetRequest).filter(PasswordResetRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Reset request not found")
    if req.status != "pending": raise HTTPException(400, f"Request already {req.status}")
    user = db.query(User).filter(User.id == req.user_id).first()
    if not user: raise HTTPException(404, "User not found")
    if len(data.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    user.hashed_password = hash_password(data.new_password)
    req.status      = "resolved"
    req.resolved_at = datetime.utcnow()
    req.resolved_by = me.username
    db.commit()
    return {"message": f"Password reset for '{user.username}'. New temp password set."}

@app.post("/admin/password-resets/{req_id}/dismiss", tags=["Admin"])
async def dismiss_reset(req_id: int, db: Session = Depends(get_db),
                        me: User = Depends(require_roles("admin"))):
    req = db.query(PasswordResetRequest).filter(PasswordResetRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Reset request not found")
    req.status      = "dismissed"
    req.resolved_at = datetime.utcnow()
    db.commit()
    return {"message": "Request dismissed."}

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

# ══════════════════════════════════════════════════════════════════════════════
# PCAP ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
@app.post(
    "/analyze-pcap",
    response_model=PcapAnalysisResponse,
    tags=["PCAP"],
    summary="Upload and analyse a PCAP/PCAPNG/CAP file",
)
async def analyze_pcap(
    file: UploadFile = File(..., description="Network capture file (.pcap/.pcapng/.cap)"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    try:
        return await run_analysis(file, db, PcapAnalysis)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get(
    "/analyze-pcap/history",
    tags=["PCAP"],
    summary="List previous PCAP analyses (newest first)",
)
async def pcap_history(
    limit: int = 20,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    rows = (
        db.query(PcapAnalysis)
        .order_by(PcapAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_orm_to_dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
