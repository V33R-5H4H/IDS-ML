# backend/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime

from backend.database import create_tables, get_db
from backend.models import User
from backend.auth import (
    authenticate_user, create_access_token,
    hash_password, get_current_user,
    Token, UserCreate, UserOut, require_roles
)


# ── Lifespan (replaces deprecated on_event) ───────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_tables()
    print("🚀 IDS-ML v2.0 API started!")
    yield
    # Shutdown
    print("🛑 IDS-ML v2.0 API shutting down...")


# ── App init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IDS-ML v2.0 API",
    description="Network Intrusion Detection System — PCAP + Live + ML",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Root → redirect to docs ───────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {
        "status":  "ok",
        "version": "2.0.0",
        "message": "IDS-ML v2.0 is running!"
    }


# ── Auth Endpoints ────────────────────────────────────────────────────────────
@app.post("/login", response_model=Token, tags=["Auth"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login with username + password → returns JWT token."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register", response_model=UserOut, tags=["Auth"])
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin"))
):
    """Register a new user (Admin only)."""
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username        = user_data.username,
        email           = user_data.email,
        hashed_password = hash_password(user_data.password),
        role            = user_data.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/me", response_model=UserOut, tags=["Auth"])
async def get_me(current_user: User = Depends(get_current_user)):
    """Get currently logged-in user profile."""
    return current_user


@app.get("/users", tags=["Auth"])
async def list_users(
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin"))
):
    """List all users (Admin only)."""
    users = db.query(User).all()
    return [
        {
            "id":        u.id,
            "username":  u.username,
            "email":     u.email,
            "role":      u.role,
            "is_active": u.is_active,
            "last_login": str(u.last_login) if u.last_login else None
        }
        for u in users
    ]


@app.patch("/users/{user_id}/deactivate", tags=["Auth"])
async def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin"))
):
    """Deactivate a user account (Admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    db.commit()
    return {"message": f"User '{user.username}' deactivated"}


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
