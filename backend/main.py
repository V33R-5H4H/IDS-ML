# backend/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime

from backend.database import create_tables, get_db
from backend.models import User
from backend.auth import (
    authenticate_user, create_access_token,
    hash_password, get_current_user,
    Token, UserCreate, UserOut, require_roles
)

# ── App init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IDS-ML v2.0 API",
    description="Network Intrusion Detection System",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup
@app.on_event("startup")
async def startup():
    create_tables()
    print("🚀 IDS-ML v2.0 API started!")


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
    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register", response_model=UserOut, tags=["Auth"])
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    _admin = Depends(require_roles("admin"))   # only admin can register new users
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
    """Get currently logged-in user's profile."""
    return current_user


@app.get("/users", tags=["Auth"])
async def list_users(
    db: Session = Depends(get_db),
    _admin = Depends(require_roles("admin"))
):
    """List all users (Admin only)."""
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username,
             "role": u.role, "is_active": u.is_active} for u in users]


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
