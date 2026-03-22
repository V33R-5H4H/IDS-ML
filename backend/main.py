# backend/main.py
import asyncio
import csv
import io
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, WebSocket, WebSocketDisconnect, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timedelta
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
from backend.live_capture import capture_manager, get_interfaces as _get_interfaces
from backend.model_manager import model_manager
from backend.retraining import retraining_manager

# ══════════════════════════════════════════════════════════════════════════════
# DEFAULT ADMIN SEED
# ══════════════════════════════════════════════════════════════════════════════
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
    print("\n" + "=" * 50)
    print(" 🔐 DEFAULT ADMIN ACCOUNT CREATED")
    print("=" * 50)
    print(f" Username : {DEFAULT_ADMIN['username']}")
    print(f" Password : {DEFAULT_ADMIN['password']}")
    print(f" Role     : {DEFAULT_ADMIN['role']}")
    print(" ⚠️  Change this password after first login!")
    print("=" * 50 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# DB MIGRATION — safely adds new columns to existing pcap_analysis table
# ══════════════════════════════════════════════════════════════════════════════
def _migrate_pcap_columns(engine):
    new_cols = [
        ("user_id",     "INTEGER"),
        ("risk_score",  "FLOAT"),
        ("risk_label",  "VARCHAR(32)"),
        ("model_used",  "VARCHAR(64)"),
        ("attack_type", "VARCHAR(64)"),
    ]
    with engine.connect() as conn:
        for col, col_type in new_cols:
            try:
                conn.execute(
                    text(f"ALTER TABLE pcap_analysis ADD COLUMN {col} {col_type}")
                )
                conn.commit()
                print(f"[DB] ✅ Migration: added column pcap_analysis.{col}")
            except Exception:
                pass  # Column already exists — safe to ignore


# ══════════════════════════════════════════════════════════════════════════════
# LIFESPAN
# ══════════════════════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        verify_connection()
        create_tables()

        from backend.database import engine
        PcapAnalysis.__table__.create(bind=engine, checkfirst=True)
        print("[DB] ✅ Table ensured: pcap_analysis")

        _migrate_pcap_columns(engine)

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


# ══════════════════════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════════════════════
app = FastAPI(title="IDS-ML v2.0 API", version="2.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════
class PublicRegister(BaseModel):
    username: str
    email:    str
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
    reason:     Optional[str] = ""

class AdminResolveReset(BaseModel):
    new_password: str

# ── PCAP Schemas ───────────────────────────────────────────────────────────────
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
    risk_score:       Optional[float] = None
    risk_label:       Optional[str]   = None
    model_used:       Optional[str]   = None
    attack_type:      Optional[str]   = None
    first_seen:       Optional[str]   = None
    last_seen:        Optional[str]   = None
    created_at:       Optional[str]   = None

    class Config:
        from_attributes    = True   # Pydantic v2
        protected_namespaces = ()
        # orm_mode = True           # uncomment for Pydantic v1

class PcapAnalysisResponse(BaseModel):
    duplicate: bool
    message:   str
    result:    PcapResultOut


# ── Helpers ────────────────────────────────────────────────────────────────────
def user_dict(u):
    return {
        "id":           u.id,
        "username":     u.username,
        "email":        u.email,
        "display_name": u.display_name,
        "role":         u.role,
        "is_active":    u.is_active,
        "created_at":   str(u.created_at) if u.created_at else None,
        "last_login":   str(u.last_login) if u.last_login else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ROOT / HEALTH
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0", "message": "IDS-ML v2.0 running!"}


# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/login", response_model=Token, tags=["Auth"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    identifier = form_data.username.strip()
    user = (
        db.query(User).filter(User.username == identifier).first() or
        db.query(User).filter(User.email    == identifier).first()
    )
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="ACCOUNT_DEACTIVATED")
    user.last_login = datetime.utcnow()
    db.commit()
    return {
        "access_token": create_access_token({"sub": user.username}),
        "token_type":   "bearer",
    }

@app.post("/register", tags=["Auth"], status_code=201)
async def register(data: PublicRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    if len(data.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    u = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(u); db.commit(); db.refresh(u)
    return {
        "message":  "Account created! You have been assigned the viewer role.",
        "username": u.username,
        "role":     u.role,
    }

@app.get("/me", response_model=UserOut, tags=["Auth"])
async def get_me(me: User = Depends(get_current_user)):
    return me


# ══════════════════════════════════════════════════════════════════════════════
# SELF — every logged-in user
# ══════════════════════════════════════════════════════════════════════════════
@app.patch("/me/profile", tags=["Self"])
async def update_profile(
    data: UpdateProfile,
    db:   Session = Depends(get_db),
    me:   User    = Depends(get_current_user),
):
    if data.email and data.email != me.email:
        if db.query(User).filter(User.email == data.email, User.id != me.id).first():
            raise HTTPException(400, "Email already in use by another account")
        me.email = data.email
    if data.display_name is not None:
        me.display_name = data.display_name.strip() or None
    db.commit(); db.refresh(me)
    return {"message": "Profile updated", "user": user_dict(me)}

@app.patch("/me/password", tags=["Self"])
async def change_password(
    data: ChangePassword,
    db:   Session = Depends(get_db),
    me:   User    = Depends(get_current_user),
):
    if not verify_password(data.current_password, me.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if len(data.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    if data.current_password == data.new_password:
        raise HTTPException(400, "New password must differ from current password")
    me.hashed_password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}

@app.post("/me/role-request", tags=["Self"], status_code=201)
async def request_role(
    data: RoleRequestCreate,
    db:   Session = Depends(get_db),
    me:   User    = Depends(get_current_user),
):
    valid = {"admin", "analyst", "viewer"}
    if data.requested_role not in valid:
        raise HTTPException(400, "Invalid role")
    if data.requested_role == me.role:
        raise HTTPException(400, f"You already have the '{me.role}' role")
    existing = db.query(RoleRequest).filter(
        RoleRequest.user_id == me.id,
        RoleRequest.status  == "pending",
    ).first()
    if existing:
        raise HTTPException(400, "You already have a pending access request. Wait for admin review.")
    req = RoleRequest(
        user_id        = me.id,
        username       = me.username,
        current_role   = me.role,
        requested_role = data.requested_role,
        reason         = data.reason or "",
    )
    db.add(req); db.commit(); db.refresh(req)
    return {
        "message":    f"Access request submitted for '{data.requested_role}' role. Pending admin review.",
        "request_id": req.id,
    }

@app.get("/me/role-request", tags=["Self"])
async def my_role_request(
    db: Session = Depends(get_db),
    me: User    = Depends(get_current_user),
):
    req = (
        db.query(RoleRequest)
        .filter(RoleRequest.user_id == me.id)
        .order_by(RoleRequest.created_at.desc())
        .first()
    )
    if not req:
        return {"request": None}
    return {"request": {
        "id":             req.id,
        "requested_role": req.requested_role,
        "current_role":   req.current_role,
        "reason":         req.reason,
        "status":         req.status,
        "created_at":     str(req.created_at),
        "reviewed_by":    req.reviewed_by,
        "reviewed_at":    str(req.reviewed_at) if req.reviewed_at else None,
    }}


# ══════════════════════════════════════════════════════════════════════════════
# FORGOT PASSWORD (public)
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
        PasswordResetRequest.status  == "pending",
    ).first()
    if existing:
        return {"message": "A reset request is already pending. Please wait for admin to process it."}
    req = PasswordResetRequest(
        user_id  = user.id,
        username = user.username,
        email    = user.email,
        reason   = data.reason or "",
    )
    db.add(req); db.commit(); db.refresh(req)
    return {"message": "Reset request submitted. An administrator will set a new temporary password for you."}


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — PASSWORD RESET MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/admin/password-resets", tags=["Admin"])
async def list_reset_requests(
    db: Session = Depends(get_db),
    _  = Depends(require_roles("admin")),
):
    reqs = db.query(PasswordResetRequest).order_by(
        PasswordResetRequest.created_at.desc()
    ).all()
    return [{
        "id":          r.id,
        "user_id":     r.user_id,
        "username":    r.username,
        "email":       r.email,
        "reason":      r.reason,
        "status":      r.status,
        "created_at":  str(r.created_at),
        "resolved_at": str(r.resolved_at) if r.resolved_at else None,
        "resolved_by": r.resolved_by,
    } for r in reqs]

@app.post("/admin/password-resets/{req_id}/resolve", tags=["Admin"])
async def resolve_reset(
    req_id: int,
    data:   AdminResolveReset,
    db:     Session = Depends(get_db),
    me:     User    = Depends(require_roles("admin")),
):
    req = db.query(PasswordResetRequest).filter(PasswordResetRequest.id == req_id).first()
    if not req:  raise HTTPException(404, "Reset request not found")
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
async def dismiss_reset(
    req_id: int,
    db:     Session = Depends(get_db),
    me:     User    = Depends(require_roles("admin")),
):
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
async def list_users(
    db: Session = Depends(get_db),
    _  = Depends(require_roles("admin")),
):
    return [user_dict(u) for u in db.query(User).order_by(User.id).all()]

@app.post("/admin/users", tags=["Admin"], status_code=201)
async def admin_create(
    data: AdminCreateUser,
    db:   Session = Depends(get_db),
    _     = Depends(require_roles("admin")),
):
    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "Invalid role")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    u = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(u); db.commit(); db.refresh(u)
    return {"message": f"User '{u.username}' created as {u.role}", "id": u.id}

@app.patch("/admin/users/{uid}/role", tags=["Admin"])
async def admin_change_role(
    uid:  int,
    data: RoleUpdate,
    db:   Session = Depends(get_db),
    me:   User    = Depends(require_roles("admin")),
):
    if data.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "Invalid role")
    u = db.query(User).filter(User.id == uid).first()
    if not u:         raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot change your own role")
    old = u.role; u.role = data.role; db.commit()
    return {"message": f"'{u.username}' role: {old} → {data.role}"}

@app.patch("/admin/users/{uid}/activate", tags=["Admin"])
async def admin_activate(
    uid: int,
    db:  Session = Depends(get_db),
    me:  User    = Depends(require_roles("admin")),
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:         raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot modify own account")
    u.is_active = True; db.commit()
    return {"message": f"'{u.username}' activated"}

@app.patch("/admin/users/{uid}/deactivate", tags=["Admin"])
async def admin_deactivate(
    uid: int,
    db:  Session = Depends(get_db),
    me:  User    = Depends(require_roles("admin")),
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:         raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot modify own account")
    u.is_active = False; db.commit()
    return {"message": f"'{u.username}' deactivated"}

@app.delete("/admin/users/{uid}", tags=["Admin"])
async def admin_delete(
    uid: int,
    db:  Session = Depends(get_db),
    me:  User    = Depends(require_roles("admin")),
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:         raise HTTPException(404, "User not found")
    if u.id == me.id: raise HTTPException(400, "Cannot delete own account")
    db.delete(u); db.commit()
    return {"message": f"'{u.username}' deleted"}

@app.patch("/admin/users/{uid}/reset-password", tags=["Admin"])
async def admin_reset_pwd(
    uid:  int,
    data: ResetPassword,
    db:   Session = Depends(get_db),
    _     = Depends(require_roles("admin")),
):
    if len(data.new_password) < 6: raise HTTPException(400, "Min 6 characters")
    u = db.query(User).filter(User.id == uid).first()
    if not u: raise HTTPException(404, "User not found")
    u.hashed_password = hash_password(data.new_password); db.commit()
    return {"message": f"Password reset for '{u.username}'"}


# ── Admin: Role Requests ───────────────────────────────────────────────────────
@app.get("/admin/role-requests", tags=["Admin"])
async def get_role_requests(
    status: Optional[str] = None,
    db:     Session        = Depends(get_db),
    _       = Depends(require_roles("admin")),
):
    q = db.query(RoleRequest)
    if status:
        q = q.filter(RoleRequest.status == status)
    reqs = q.order_by(RoleRequest.created_at.desc()).all()
    return [{
        "id":             r.id,
        "user_id":        r.user_id,
        "username":       r.username,
        "current_role":   r.current_role,
        "requested_role": r.requested_role,
        "reason":         r.reason,
        "status":         r.status,
        "created_at":     str(r.created_at),
        "reviewed_by":    r.reviewed_by,
        "reviewed_at":    str(r.reviewed_at) if r.reviewed_at else None,
    } for r in reqs]

@app.patch("/admin/role-requests/{req_id}/approve", tags=["Admin"])
async def approve_request(
    req_id: int,
    db:     Session = Depends(get_db),
    me:     User    = Depends(require_roles("admin")),
):
    req = db.query(RoleRequest).filter(RoleRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Request not found")
    if req.status != "pending": raise HTTPException(400, f"Request already {req.status}")
    user = db.query(User).filter(User.id == req.user_id).first()
    if user: user.role = req.requested_role
    req.status      = "approved"
    req.reviewed_by = me.username
    req.reviewed_at = datetime.utcnow()
    db.commit()
    return {"message": f"Approved: '{req.username}' is now {req.requested_role}"}

@app.patch("/admin/role-requests/{req_id}/reject", tags=["Admin"])
async def reject_request(
    req_id: int,
    db:     Session = Depends(get_db),
    me:     User    = Depends(require_roles("admin")),
):
    req = db.query(RoleRequest).filter(RoleRequest.id == req_id).first()
    if not req: raise HTTPException(404, "Request not found")
    if req.status != "pending": raise HTTPException(400, f"Request already {req.status}")
    req.status      = "rejected"
    req.reviewed_by = me.username
    req.reviewed_at = datetime.utcnow()
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
    file:  UploadFile = File(..., description="Network capture file (.pcap/.pcapng/.cap)"),
    db:    Session    = Depends(get_db),
    _user: User       = Depends(get_current_user),
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
    limit: int     = 20,
    db:    Session = Depends(get_db),
    _user: User    = Depends(get_current_user),
):
    rows = (
        db.query(PcapAnalysis)
        .order_by(PcapAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_orm_to_dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD STATS  (all authenticated roles)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/dashboard/stats", tags=["Dashboard"])
async def dashboard_stats(
    db:    Session = Depends(get_db),
    _user: User    = Depends(get_current_user),
):
    rows  = db.query(PcapAnalysis).all()
    total = len(rows)

    by_label = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        lbl = r.risk_label or "Low"
        if lbl in by_label:
            by_label[lbl] += 1

    attacks = by_label["Critical"] + by_label["High"]
    normal  = by_label["Medium"]   + by_label["Low"]

    # Last 7 days breakdown
    today  = datetime.utcnow().date()
    last_7 = []
    for i in range(6, -1, -1):
        d   = today - timedelta(days=i)
        dr  = [r for r in rows if r.created_at and r.created_at.date() == d]
        da  = sum(1 for r in dr if r.risk_label in ("Critical", "High"))
        last_7.append({"date": str(d), "total": len(dr), "attacks": da})

    # Top attack types
    atk = {}
    for r in rows:
        if r.attack_type:
            atk[r.attack_type] = atk.get(r.attack_type, 0) + 1
    top_attacks = sorted(atk.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total":          total,
        "attacks":        attacks,
        "normal":         normal,
        "by_label":       by_label,
        "top_attacks":    [{"type": t, "count": c} for t, c in top_attacks],
        "last_7_days":    last_7,
        "model":          model_manager.get_active_metadata().get("model_name", "Random Forest IDS"),
        "model_accuracy": f"{model_manager.get_active_metadata().get('accuracy', 0.859)*100:.1f}%",
    }


# ══════════════════════════════════════════════════════════════════════════════
# REPORTS SUMMARY  (all authenticated roles — viewer safe)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/reports/summary", tags=["Reports"])
async def reports_summary(
    db:    Session = Depends(get_db),
    _user: User    = Depends(get_current_user),
):
    rows  = db.query(PcapAnalysis).order_by(PcapAnalysis.created_at.desc()).all()
    total = len(rows)

    by_label = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        lbl = r.risk_label or "Low"
        if lbl in by_label:
            by_label[lbl] += 1

    threat_count = by_label["Critical"] + by_label["High"]
    normal_count = by_label["Medium"]   + by_label["Low"]
    avg_risk     = round(
        sum((r.risk_score or 0) for r in rows) / total, 3
    ) if total else 0.0

    # Top attack types
    atk = {}
    for r in rows:
        if r.attack_type:
            atk[r.attack_type] = atk.get(r.attack_type, 0) + 1
    top_attacks = sorted(atk.items(), key=lambda x: x[1], reverse=True)[:5]

    # Top protocols
    proto = {}
    for r in rows:
        for p in (r.top_protocols or "").split(","):
            p = p.strip()
            if p:
                proto[p] = proto.get(p, 0) + 1
    top_protocols = sorted(proto.items(), key=lambda x: x[1], reverse=True)[:5]

    # Last 7 days
    today  = datetime.utcnow().date()
    weekly = []
    for i in range(6, -1, -1):
        d   = today - timedelta(days=i)
        dr  = [r for r in rows if r.created_at and r.created_at.date() == d]
        dt_ = sum(1 for r in dr if r.risk_label in ("Critical", "High"))
        weekly.append({"date": str(d), "total": len(dr), "threats": dt_})

    return {
        "total_analyses":   total,
        "threat_count":     threat_count,
        "normal_count":     normal_count,
        "avg_risk_score":   avg_risk,
        "by_label":         by_label,
        "top_attack_types": [{"type": t, "count": c} for t, c in top_attacks],
        "top_protocols":    [{"protocol": p, "count": c} for p, c in top_protocols],
        "weekly":           weekly,
        "model_name":       model_manager.get_active_metadata().get("model_name", "Random Forest IDS"),
        "model_accuracy":   f"{model_manager.get_active_metadata().get('accuracy', 0.859)*100:.1f}%",
        "recent":           [_orm_to_dict(r) for r in rows[:10]],
    }


# ══════════════════════════════════════════════════════════════════════════════
# LIVE CAPTURE  (admin / analyst)
# ══════════════════════════════════════════════════════════════════════════════
class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None


@app.get("/live-capture/interfaces", tags=["Live Capture"])
async def live_capture_interfaces(
    _user: User = Depends(get_current_user),
):
    """Return available network interfaces for live capture."""
    ifaces = _get_interfaces()
    if not ifaces:
        return {
            "interfaces": [],
            "error": "No interfaces found. Ensure Scapy and Npcap are installed "
                     "and the application is running with admin privileges.",
        }
    return {"interfaces": ifaces}


@app.post("/live-capture/start", tags=["Live Capture"])
async def live_capture_start(
    req: CaptureStartRequest,
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Start live packet capture."""
    if capture_manager.is_running:
        raise HTTPException(400, "Capture already running")
    try:
        loop = asyncio.get_event_loop()
        capture_manager.start(
            interface=req.interface,
            bpf_filter=req.bpf_filter,
            loop=loop,
        )
        return {"status": "started", "interface": req.interface, "filter": req.bpf_filter}
    except Exception as e:
        raise HTTPException(500, f"Failed to start capture: {e}")


@app.post("/live-capture/stop", tags=["Live Capture"])
async def live_capture_stop(
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Stop live packet capture."""
    summary = capture_manager.stop()
    return {"status": "stopped", "summary": summary}


@app.get("/live-capture/status", tags=["Live Capture"])
async def live_capture_status(
    _user: User = Depends(get_current_user),
):
    """Return current capture state and statistics."""
    return capture_manager.get_status()


@app.get("/live-capture/export", tags=["Live Capture"])
async def live_capture_export(
    format: str = Query("json", regex="^(json|csv)$"),
    limit: int = Query(500, ge=1, le=5000),
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Export captured packets as JSON or CSV."""
    packets = capture_manager.get_packets(limit=limit)
    if not packets:
        raise HTTPException(404, "No captured packets to export")

    if format == "csv":
        output = io.StringIO()
        fields = ["timestamp", "src", "dst", "protocol", "length", "info", "risk"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(packets)
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=live_capture.csv"},
        )
    else:
        import json as _json
        content = _json.dumps(packets, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=live_capture.json"},
        )


@app.get("/live-capture/export/pcap", tags=["Live Capture"])
async def live_capture_export_pcap(
    limit: int = Query(10000, ge=1, le=50000),
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Export captured packets as a .pcap file."""
    pcap_bytes = capture_manager.get_pcap_bytes(limit=limit)
    if len(pcap_bytes) <= 24:  # Only global header, no packets
        raise HTTPException(404, "No captured packets to export")

    return StreamingResponse(
        iter([pcap_bytes]),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=live_capture.pcap"},
    )


@app.get("/live-capture/analytics", tags=["Live Capture"])
async def live_capture_analytics(
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Get aggregated analytics for the current/last capture session."""
    return capture_manager.get_analytics()


@app.post("/live-capture/analyze", tags=["Live Capture"])
async def live_capture_analyze(
    limit: int = Query(1000, ge=1, le=5000),
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Run ML analysis on captured packets and return predictions."""
    import numpy as np

    packets = capture_manager.get_packets(limit=limit)
    if not packets:
        raise HTTPException(404, "No captured packets to analyze")

    # Check if model is available
    active_model = model_manager.get_active()
    if not active_model:
        raise HTTPException(503, "No ML model available. Please activate a model first.")

    model_meta = model_manager.get_active_metadata()

    # NSL-KDD attack labels (23-class)
    ATTACK_LABELS = [
        "normal", "neptune", "warezclient", "ipsweep", "portsweep",
        "teardrop", "nmap", "satan", "smurf", "pod", "back",
        "guess_passwd", "ftp_write", "multihop", "rootkit",
        "buffer_overflow", "imap", "warezmaster", "phf", "land",
        "loadmodule", "spy", "perl",
    ]

    results = []
    threat_count = 0
    attack_breakdown = {}

    for pkt in packets:
        proto_enc = {"TCP": 0, "UDP": 1, "ICMP": 2}.get(pkt.get("protocol", ""), 0)
        length = float(pkt.get("length", 0))

        features = np.array([[
            0.0,        # duration
            proto_enc,  # protocol_type
            8,          # service (default: other)
            0,          # flag
            length,     # src_bytes
            0.0,        # dst_bytes
            0.0,        # logged_in
            1.0,        # count
            1.0,        # srv_count
            0.0,        # serror_rate
            0.0,        # srv_serror_rate
            min(80, 255),  # dst_host_srv_count
        ]])

        try:
            proba = model_manager.predict(features)
            pred_class = int(np.argmax(proba[0]))
            confidence = float(np.max(proba[0]))
            label = ATTACK_LABELS[pred_class] if pred_class < len(ATTACK_LABELS) else f"class_{pred_class}"
        except Exception:
            label = "error"
            confidence = 0.0
            pred_class = -1

        is_threat = label != "normal" and pred_class != 0
        if is_threat:
            threat_count += 1
            attack_breakdown[label] = attack_breakdown.get(label, 0) + 1

        results.append({
            "timestamp": pkt.get("timestamp"),
            "src": pkt.get("src"),
            "dst": pkt.get("dst"),
            "protocol": pkt.get("protocol"),
            "length": pkt.get("length"),
            "info": pkt.get("info"),
            "prediction": label,
            "confidence": round(confidence, 4),
            "is_threat": is_threat,
        })

    return {
        "total_packets": len(results),
        "threats_detected": threat_count,
        "threat_rate": round(threat_count / max(len(results), 1) * 100, 1),
        "model_used": model_meta.get("model_name", active_model),
        "attack_breakdown": attack_breakdown,
        "packets": results,
    }

@app.get("/analytics/combined", tags=["Analytics"])
async def combined_analytics(
    _user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Combined analytics from both live capture and PCAP analysis history."""
    # Live capture analytics
    live = capture_manager.get_analytics()

    # PCAP analysis stats from DB
    from sqlalchemy import func
    pcap_stats = {"total_analyses": 0, "total_packets": 0, "attack_types": {}}
    try:
        # Count PCAP analyses
        analyses = db.execute(
            text("SELECT COUNT(*) FROM pcap_analyses")
        ).scalar() or 0
        pcap_stats["total_analyses"] = analyses

        # Get prediction breakdown from predictions table
        rows = db.execute(
            text("SELECT predicted_label, COUNT(*) as cnt FROM predictions GROUP BY predicted_label ORDER BY cnt DESC LIMIT 20")
        ).fetchall()
        for row in rows:
            pcap_stats["attack_types"][row[0]] = row[1]
            pcap_stats["total_packets"] += row[1]
    except Exception:
        pass

    # Merge attack types
    merged_attacks = dict(pcap_stats["attack_types"])
    for attack, count in live.get("attack_types", {}).items():
        merged_attacks[attack] = merged_attacks.get(attack, 0) + count

    return {
        "live": {
            "running": live.get("running", False),
            "total_packets": live.get("total_packets", 0),
            "threats_detected": live.get("threats_detected", 0),
            "protocol_breakdown": live.get("protocol_breakdown", {}),
            "timeline": live.get("timeline", []),
            "top_sources": live.get("top_sources", []),
            "top_destinations": live.get("top_destinations", []),
        },
        "pcap": pcap_stats,
        "merged": {
            "total_packets": live.get("total_packets", 0) + pcap_stats["total_packets"],
            "attack_types": merged_attacks,
        },
    }

@app.websocket("/ws/live-capture")
async def ws_live_capture(ws: WebSocket, token: str = Query(...)):
    """WebSocket endpoint for real-time packet feed.
    Authenticates via query parameter: ?token=<jwt_token>
    """
    from backend.auth import decode_token
    try:
        payload = decode_token(token)
        if not payload:
            await ws.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await ws.close(code=4001, reason="Invalid token")
        return

    await ws.accept()
    queue = capture_manager.subscribe()
    try:
        while True:
            try:
                pkt = await asyncio.wait_for(queue.get(), timeout=30)
                await ws.send_json(pkt)
            except asyncio.TimeoutError:
                # Send keepalive ping
                await ws.send_json({"type": "ping"})
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        capture_manager.unsubscribe(queue)


# ══════════════════════════════════════════════════════════════════════════════
# MODEL MANAGEMENT  (admin / analyst)
# ══════════════════════════════════════════════════════════════════════════════
class ModelSwitchRequest(BaseModel):
    model_key: str


@app.get("/models", tags=["Models"])
async def list_models(
    _user: User = Depends(get_current_user),
):
    """List all available ML models with accuracy metadata."""
    return model_manager.list_models()


@app.get("/models/active", tags=["Models"])
async def get_active_model(
    _user: User = Depends(get_current_user),
):
    """Get the currently active model and its metadata."""
    return model_manager.get_active_metadata()


@app.post("/models/switch", tags=["Models"])
async def switch_model(
    req:   ModelSwitchRequest,
    _user: User = Depends(require_roles("admin")),
):
    """Switch the active ML model (admin only)."""
    try:
        meta = model_manager.set_active(req.model_key)
        return {"message": f"Switched to {meta.get('model_name', req.model_key)}", "model": meta}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Failed to switch model: {e}")


@app.post("/models/refresh", tags=["Models"])
async def refresh_models(
    _user: User = Depends(require_roles("admin")),
):
    """Re-scan models directory for newly trained models."""
    model_manager.refresh()
    return {"message": "Models refreshed", "models": model_manager.list_models()}


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-RETRAINING PIPELINE  (admin only)
# ══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
def start_retraining_scheduler():
    """Start the auto-retraining scheduler on app startup."""
    try:
        retraining_manager.start_scheduler()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Retraining scheduler failed to start: %s", e)


@app.on_event("shutdown")
def stop_retraining_scheduler():
    retraining_manager.stop_scheduler()


@app.get("/retraining/status", tags=["Retraining"])
async def retraining_status(
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Get current auto-retraining status."""
    return retraining_manager.get_status()


class RetrainRequest(BaseModel):
    model_type: str = "rf"


@app.post("/retraining/trigger", tags=["Retraining"])
async def trigger_retrain(
    req: RetrainRequest = RetrainRequest(),
    _user: User = Depends(require_roles("admin")),
):
    """Manually trigger model retraining (admin only)."""
    if req.model_type:
        retraining_manager.update_config(model_type=req.model_type)
    import threading
    t = threading.Thread(target=retraining_manager.retrain, kwargs={"force": True}, daemon=True)
    t.start()
    return {"message": "Retraining started", "model_type": req.model_type}


@app.get("/retraining/history", tags=["Retraining"])
async def retraining_history(
    limit: int = Query(20, ge=1, le=100),
    _user: User = Depends(require_roles("admin", "analyst")),
):
    """Get retraining history."""
    return retraining_manager.get_history(limit=limit)


class RetrainingConfigUpdate(BaseModel):
    interval_hours: int = None
    model_type: str = None
    dataset: str = None
    min_samples: int = None
    enabled: bool = None


@app.patch("/retraining/config", tags=["Retraining"])
async def update_retraining_config(
    config: RetrainingConfigUpdate,
    _user: User = Depends(require_roles("admin")),
):
    """Update retraining configuration (admin only)."""
    updates = {k: v for k, v in config.dict().items() if v is not None}
    new_config = retraining_manager.update_config(**updates)
    return {"message": "Config updated", "config": new_config}


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
