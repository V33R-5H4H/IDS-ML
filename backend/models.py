# backend/models.py
from sqlalchemy import (
    Column, Integer, String, Float,
    Boolean, DateTime, Text, JSON, ForeignKey
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()


# ─────────────────────────────────────────
# TABLE 1: Users
# ─────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String(50),  unique=True, index=True, nullable=False)
    email           = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(String(20),  default="analyst")   # admin | analyst | viewer
    is_active       = Column(Boolean,     default=True)
    created_at      = Column(DateTime,    default=datetime.utcnow)
    last_login      = Column(DateTime,    nullable=True)

    # Relationships
    predictions = relationship("Prediction",   back_populates="user")
    analyses    = relationship("PCAPAnalysis", back_populates="user")


# ─────────────────────────────────────────
# TABLE 2: Predictions
# ─────────────────────────────────────────
class Prediction(Base):
    __tablename__ = "predictions"

    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip     = Column(String(45),  nullable=True)
    dest_ip       = Column(String(45),  nullable=True)
    protocol_type = Column(String(10),  nullable=True)
    service       = Column(String(20),  nullable=True)
    features      = Column(JSON,        nullable=True)   # all 12 features
    prediction    = Column(String(50),  index=True)
    confidence    = Column(Float,       default=0.0)
    is_attack     = Column(Boolean,     default=False,   index=True)
    severity      = Column(String(10),  default="low")   # low | medium | high
    source_type   = Column(String(10),  default="live")  # live | pcap | manual
    model_used    = Column(String(30),  default="RF")
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=True)

    user  = relationship("User",  back_populates="predictions")
    alert = relationship("Alert", back_populates="prediction", uselist=False)


# ─────────────────────────────────────────
# TABLE 3: Alerts
# ─────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, index=True)
    timestamp        = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type      = Column(String(50))
    severity         = Column(String(10), index=True)
    source_ip        = Column(String(45), nullable=True)
    confidence       = Column(Float,      default=0.0)
    acknowledged     = Column(Boolean,    default=False)
    acknowledged_by  = Column(Integer,    nullable=True)   # user id
    acknowledged_at  = Column(DateTime,   nullable=True)
    email_sent       = Column(Boolean,    default=False)
    sms_sent         = Column(Boolean,    default=False)
    slack_sent       = Column(Boolean,    default=False)
    prediction_id    = Column(Integer, ForeignKey("predictions.id"), nullable=True)

    prediction = relationship("Prediction", back_populates="alert")


# ─────────────────────────────────────────
# TABLE 4: PCAP Analyses
# ─────────────────────────────────────────
class PCAPAnalysis(Base):
    __tablename__ = "pcap_analyses"

    id                = Column(Integer, primary_key=True, index=True)
    filename          = Column(String(255), nullable=False)
    file_size_bytes   = Column(Integer,  default=0)
    file_hash         = Column(String(64), nullable=True)   # SHA-256
    total_packets     = Column(Integer,  default=0)
    analyzed_packets  = Column(Integer,  default=0)
    attacks_detected  = Column(Integer,  default=0)
    attack_rate       = Column(Float,    default=0.0)       # percentage
    processing_time   = Column(Float,    default=0.0)       # seconds
    model_used        = Column(String(50), default="RF")
    results_summary   = Column(JSON,     nullable=True)
    status            = Column(String(20), default="pending")  # pending|processing|done|failed
    created_at        = Column(DateTime, default=datetime.utcnow)
    user_id           = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="analyses")
