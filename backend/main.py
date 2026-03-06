# backend/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel

from backend.database import create_tables, get_db
from backend.models import User
from backend.auth import (
    authenticate_user, create_access_token,
    hash_password, get_current_user,
    Token, UserCreate, UserOut, require_roles
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
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

class RoleUpdate(BaseModel):
    role: str

class AdminCreateUser(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"

class ResetPassword(BaseModel):
    new_password: str

# ── Root / Health ─────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root(): return RedirectResponse(url="/docs")

@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0", "message": "IDS-ML v2.0 is running!"}

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/login", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    user.last_login = datetime.utcnow()
    db.commit()
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/register", tags=["Auth"], status_code=201)
async def public_register(data: PublicRegister, db: Session = Depends(get_db)):
    """Self-registration — always creates a viewer role."""
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = User(username=data.username, email=data.email,
                hashed_password=hash_password(data.password),
                role="viewer", is_active=True)
    db.add(user); db.commit(); db.refresh(user)
    return {"message": "Account created! You have been assigned the viewer role. Contact an admin for elevated access.",
            "username": user.username, "role": user.role}

@app.get("/me", response_model=UserOut, tags=["Auth"])
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/users", tags=["Admin"])
async def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles("admin"))):
    users = db.query(User).order_by(User.id).all()
    return [{"id":u.id,"username":u.username,"email":u.email,"role":u.role,
             "is_active":u.is_active,"created_at":str(u.created_at),
             "last_login":str(u.last_login) if u.last_login else None} for u in users]

@app.post("/admin/users", tags=["Admin"], status_code=201)
async def admin_create_user(data: AdminCreateUser, db: Session = Depends(get_db),
                             _: User = Depends(require_roles("admin"))):
    if data.role not in ("admin","analyst","viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, analyst or viewer")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(username=data.username, email=data.email,
                hashed_password=hash_password(data.password),
                role=data.role, is_active=True)
    db.add(user); db.commit(); db.refresh(user)
    return {"message": f"User '{user.username}' created with role '{user.role}'", "id": user.id}

@app.patch("/admin/users/{user_id}/role", tags=["Admin"])
async def change_role(user_id: int, data: RoleUpdate, db: Session = Depends(get_db),
                      me: User = Depends(require_roles("admin"))):
    if data.role not in ("admin","analyst","viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == me.id: raise HTTPException(status_code=400, detail="Cannot change your own role")
    old = user.role; user.role = data.role; db.commit()
    return {"message": f"'{user.username}' role changed: {old} → {data.role}"}

@app.patch("/admin/users/{user_id}/activate", tags=["Admin"])
async def activate_user(user_id: int, db: Session = Depends(get_db),
                        me: User = Depends(require_roles("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == me.id: raise HTTPException(status_code=400, detail="Cannot modify own account")
    user.is_active = True; db.commit()
    return {"message": f"User '{user.username}' activated"}

@app.patch("/admin/users/{user_id}/deactivate", tags=["Admin"])
async def deactivate_user(user_id: int, db: Session = Depends(get_db),
                          me: User = Depends(require_roles("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == me.id: raise HTTPException(status_code=400, detail="Cannot modify own account")
    user.is_active = False; db.commit()
    return {"message": f"User '{user.username}' deactivated"}

@app.delete("/admin/users/{user_id}", tags=["Admin"])
async def delete_user(user_id: int, db: Session = Depends(get_db),
                      me: User = Depends(require_roles("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == me.id: raise HTTPException(status_code=400, detail="Cannot delete own account")
    db.delete(user); db.commit()
    return {"message": f"User '{user.username}' permanently deleted"}

@app.patch("/admin/users/{user_id}/reset-password", tags=["Admin"])
async def reset_password(user_id: int, data: ResetPassword, db: Session = Depends(get_db),
                         _: User = Depends(require_roles("admin"))):
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = hash_password(data.new_password); db.commit()
    return {"message": f"Password reset for '{user.username}'"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
