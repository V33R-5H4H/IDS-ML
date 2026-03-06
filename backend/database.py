# backend/database.py
import os
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

# ── Load .env ─────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _here = os.path.dirname(os.path.abspath(__file__))
    _root = os.path.dirname(_here)
    for _p in [os.path.join(_root, ".env"), os.path.join(_here, ".env")]:
        if os.path.exists(_p):
            load_dotenv(_p, override=False)
            break
except ImportError:
    pass

# ── Resolve DATABASE_URL ──────────────────────────────────────────────────────
_raw_url = os.getenv("DATABASE_URL", "").strip()
if _raw_url.startswith("postgres://"):
    _raw_url = _raw_url.replace("postgres://", "postgresql://", 1)

_SQLITE_FALLBACK = (
    f"sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ids_ml.db')}"
)

def _make_engine(url: str):
    is_sqlite = url.startswith("sqlite")
    if is_sqlite:
        return create_engine(url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True)
    return create_engine(url,
        pool_size=5, max_overflow=10,
        pool_pre_ping=True, pool_recycle=300)

def _test_engine(eng) -> bool:
    try:
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"[DB] ❌ Connection test failed: {e}")
        return False

# ── Connect ───────────────────────────────────────────────────────────────────
_is_sqlite = True
DATABASE_URL = _SQLITE_FALLBACK

if _raw_url:
    _label = _raw_url.split("@")[-1] if "@" in _raw_url else _raw_url
    print(f"[DB] Trying: {_label}")
    _try = _make_engine(_raw_url)
    if _test_engine(_try):
        engine       = _try
        DATABASE_URL = _raw_url
        _is_sqlite   = _raw_url.startswith("sqlite")
        _db_type     = "SQLite" if _is_sqlite else "PostgreSQL"
        print(f"[DB] ✅ Connected ({_db_type}): {_label}")
    else:
        print("[DB] ⚠️  PostgreSQL unreachable — using SQLite fallback")
        engine = _make_engine(_SQLITE_FALLBACK)
        print(f"[DB] ✅ SQLite: {_SQLITE_FALLBACK}")
else:
    print("[DB] ⚠️  DATABASE_URL not set — using SQLite")
    engine = _make_engine(_SQLITE_FALLBACK)
    print(f"[DB] ✅ SQLite: {_SQLITE_FALLBACK}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()


def verify_connection() -> bool:
    return _test_engine(engine)


# ── Raw SQL table definitions (guaranteed fallback if ORM create_all misses them)
_IS_PG = not DATABASE_URL.startswith("sqlite")

_RAW_TABLES = {
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            username        VARCHAR UNIQUE NOT NULL,
            email           VARCHAR UNIQUE NOT NULL,
            display_name    VARCHAR,
            hashed_password VARCHAR NOT NULL,
            role            VARCHAR DEFAULT 'viewer',
            is_active       BOOLEAN DEFAULT TRUE,
            created_at      TIMESTAMP WITH TIME ZONE DEFAULT now(),
            last_login      TIMESTAMP WITH TIME ZONE
        )""" if _IS_PG else """
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        VARCHAR UNIQUE NOT NULL,
            email           VARCHAR UNIQUE NOT NULL,
            display_name    VARCHAR,
            hashed_password VARCHAR NOT NULL,
            role            VARCHAR DEFAULT 'viewer',
            is_active       BOOLEAN DEFAULT 1,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login      DATETIME
        )""",

    "role_requests": """
        CREATE TABLE IF NOT EXISTS role_requests (
            id             SERIAL PRIMARY KEY,
            user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username       VARCHAR NOT NULL,
            "current_role" VARCHAR NOT NULL,
            requested_role VARCHAR NOT NULL,
            reason         TEXT,
            status         VARCHAR DEFAULT 'pending',
            created_at     TIMESTAMP WITH TIME ZONE DEFAULT now(),
            reviewed_at    TIMESTAMP WITH TIME ZONE,
            reviewed_by    VARCHAR
        )""" if _IS_PG else """
        CREATE TABLE IF NOT EXISTS role_requests (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username       VARCHAR NOT NULL,
            current_role   VARCHAR NOT NULL,
            requested_role VARCHAR NOT NULL,
            reason         TEXT,
            status         VARCHAR DEFAULT 'pending',
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            reviewed_at    DATETIME,
            reviewed_by    VARCHAR
        )""",

    "password_reset_requests": """
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username    VARCHAR NOT NULL,
            email       VARCHAR NOT NULL,
            reason      TEXT,
            status      VARCHAR DEFAULT 'pending',
            created_at  TIMESTAMP WITH TIME ZONE DEFAULT now(),
            resolved_at TIMESTAMP WITH TIME ZONE,
            resolved_by VARCHAR
        )""" if _IS_PG else """
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username    VARCHAR NOT NULL,
            email       VARCHAR NOT NULL,
            reason      TEXT,
            status      VARCHAR DEFAULT 'pending',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME,
            resolved_by VARCHAR
        )""",
}


def _ensure_tables_raw():
    """Guarantee all tables exist using raw SQL — runs before ORM create_all."""
    with engine.connect() as conn:
        for tbl, sql in _RAW_TABLES.items():
            try:
                conn.execute(text(sql))
                conn.commit()
                print(f"[DB] ✅ Table ensured: {tbl}")
            except Exception as e:
                conn.rollback()
                print(f"[DB] ⚠️  Table {tbl}: {e}")


def run_migrations():
    """Add missing columns to existing tables."""
    is_sqlite = DATABASE_URL.startswith("sqlite")

    MIGRATIONS = {
        "users": [
            ("display_name",    "VARCHAR"),
            ("last_login",      "TIMESTAMP WITH TIME ZONE" if not is_sqlite else "DATETIME"),
            ("created_at",      "TIMESTAMP WITH TIME ZONE DEFAULT now()" if not is_sqlite
                                else "DATETIME DEFAULT CURRENT_TIMESTAMP"),
            ("is_active",       "BOOLEAN DEFAULT TRUE"),
            ("role",            "VARCHAR DEFAULT 'viewer'"),
        ],
        "role_requests": [
            ("reason",      "TEXT"),
            ("reviewed_at", "TIMESTAMP WITH TIME ZONE" if not is_sqlite else "DATETIME"),
            ("reviewed_by", "VARCHAR"),
        ],
        "password_reset_requests": [
            ("reason",      "TEXT"),
            ("resolved_at", "TIMESTAMP WITH TIME ZONE" if not is_sqlite else "DATETIME"),
            ("resolved_by", "VARCHAR"),
        ],
    }

    with engine.connect() as conn:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()

        for table, columns in MIGRATIONS.items():
            if table not in existing_tables:
                continue

            existing_cols = {c["name"] for c in inspector.get_columns(table)}

            for col_name, col_def in columns:
                if col_name in existing_cols:
                    continue
                try:
                    if is_sqlite:
                        conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"
                        ))
                    else:
                        conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                            f"{col_name} {col_def}"
                        ))
                    conn.commit()
                    print(f"[DB] ✅ Migration: {table}.{col_name} added")
                except Exception as e:
                    conn.rollback()
                    print(f"[DB] ⚠️  Migration skipped {table}.{col_name}: {e}")

    print("[DB] ✅ Migrations complete")


def create_tables():
    # Step 1: Guarantee tables via raw SQL (handles new tables reliably)
    _ensure_tables_raw()
    # Step 2: Register ORM models and sync any ORM-managed tables
    import backend.models as _models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    # Step 3: Add any missing columns to existing tables
    run_migrations()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
