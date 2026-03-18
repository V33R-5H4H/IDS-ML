# backend/models_pcap.py
from sqlalchemy import Column, Integer, String, Float, BigInteger, DateTime
from sqlalchemy.sql import func
from .database import Base


class PcapAnalysis(Base):
    __tablename__ = "pcap_analysis"

    id               = Column(Integer,     primary_key=True, index=True)
    filename         = Column(String(255), nullable=False)
    sha256           = Column(String(64),  unique=True, index=True, nullable=False)
    file_size        = Column(BigInteger,  nullable=False)

    # 12 extracted features
    total_packets    = Column(Integer)
    total_bytes      = Column(BigInteger)
    duration_seconds = Column(Float)
    unique_src_ips   = Column(Integer)
    unique_dst_ips   = Column(Integer)
    top_protocols    = Column(String(128))
    avg_packet_size  = Column(Float)
    max_packet_size  = Column(Integer)
    tcp_packets      = Column(Integer)
    udp_packets      = Column(Integer)
    icmp_packets     = Column(Integer)
    bytes_per_second = Column(Float)

    # Metadata
    first_seen       = Column(String(32))
    last_seen        = Column(String(32))
    created_at       = Column(DateTime(timezone=True), server_default=func.now())
