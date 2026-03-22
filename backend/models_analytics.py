from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from backend.database import Base

class PredictionLog(Base):
    """Stores individual prediction results for long-term analytics"""
    __tablename__ = "prediction_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source = Column(String(32), default="live", index=True)  # "live" or "pcap"
    model_name = Column(String(64), nullable=False)
    is_attack = Column(Boolean, default=False, index=True)
    attack_type = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False)
    
    # Optional network details context
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    protocol = Column(String(32), nullable=True)


class LiveCaptureSession(Base):
    """Stores metadata about a discrete live packet monitoring session"""
    __tablename__ = "live_capture_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    start_time = Column(DateTime(timezone=True), server_default=func.now())
    end_time = Column(DateTime(timezone=True), nullable=True)
    
    total_packets = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    
    # JSON string summarizing the top attacking IPs or general connection breakdown
    summary_data = Column(String, nullable=True)
