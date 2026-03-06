# backend/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./ids_ml.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}   # SQLite only
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()   # ← defined HERE, never imported from models


def create_tables():
    # Import models locally so they register with Base before create_all()
    import backend.models as _models   # noqa: F401  (side-effect import)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
