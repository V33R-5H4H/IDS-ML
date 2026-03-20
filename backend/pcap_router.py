# app/pcap_router.py  —  PCAP Upload, Feature Extraction, ML Scoring
import hashlib
import tempfile
import os
import logging
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database  import get_db
from app.auth      import get_current_user
from app.models    import User, PcapAnalysis
from backend.ml_model import ids_model

log    = logging.getLogger(__name__)
router = APIRouter()

# ══════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION  —  wire in your existing extractor below
# ══════════════════════════════════════════════════════════════════════════════
def extract_features(file_path: str) -> dict:
    """
    Analyse a PCAP file and return a flat feature dict.

    Required keys (must ALL be present):
        total_packets, total_bytes, duration_seconds,
        unique_src_ips, unique_dst_ips, top_protocols,
        avg_packet_size, max_packet_size,
        tcp_packets, udp_packets, icmp_packets, bytes_per_second

    ── Replace the body below with your existing scapy/dpkt/pyshark logic ──
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        import time

        packets = rdpcap(file_path)
        if not packets:
            raise ValueError("Empty PCAP file")

        total_packets = len(packets)
        total_bytes   = sum(len(p) for p in packets)
        timestamps    = [float(p.time) for p in packets]
        duration      = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001

        src_ips  = set()
        dst_ips  = set()
        protos   = {}
        tcp = udp = icmp = 0

        for p in packets:
            if IP in p:
                src_ips.add(p[IP].src)
                dst_ips.add(p[IP].dst)
            if TCP in p:
                tcp  += 1
                protos["TCP"] = protos.get("TCP", 0) + 1
            elif UDP in p:
                udp  += 1
                protos["UDP"] = protos.get("UDP", 0) + 1
            elif ICMP in p:
                icmp += 1
                protos["ICMP"] = protos.get("ICMP", 0) + 1

        sizes        = [len(p) for p in packets]
        top_protocols = ",".join(
            k for k, _ in sorted(protos.items(), key=lambda x: -x[1])[:3]
        ) or "Unknown"

        return {
            "total_packets":    total_packets,
            "total_bytes":      total_bytes,
            "duration_seconds": round(duration, 4),
            "unique_src_ips":   len(src_ips),
            "unique_dst_ips":   len(dst_ips),
            "top_protocols":    top_protocols,
            "avg_packet_size":  round(sum(sizes) / total_packets, 2),
            "max_packet_size":  max(sizes),
            "tcp_packets":      tcp,
            "udp_packets":      udp,
            "icmp_packets":     icmp,
            "bytes_per_second": round(total_bytes / duration, 2),
        }

    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="scapy is not installed. Run: pip install scapy",
        )


# ══════════════════════════════════════════════════════════════════════════════
# POST /analyze-pcap
# ══════════════════════════════════════════════════════════════════════════════
@router.post("/analyze-pcap")
async def analyze_pcap(
    file: UploadFile = File(...),
    db:   Session    = Depends(get_db),
    me:   User       = Depends(get_current_user),
):
    # 1 — Validate extension
    allowed = {".pcap", ".pcapng", ".cap"}
    ext     = os.path.splitext(file.filename)[-1].lower()
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

    # 2 — Read bytes & compute SHA-256
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    sha256 = hashlib.sha256(content).hexdigest()

    # 3 — Return cached result if same file uploaded before
    cached = db.query(PcapAnalysis).filter_by(sha256=sha256).first()
    if cached:
        return {"result": _row_to_dict(cached), "duplicate": True}

    # 4 — Write to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    # 5 — Extract features
    try:
        features = extract_features(tmp_path)
    except HTTPException:
        raise
    except Exception as e:
        log.error("Feature extraction error: %s", e)
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # 6 — ML risk scoring
    risk = ids_model.predict(features)

    # 7 — Persist to database
    row = PcapAnalysis(
        user_id           = me.id,
        filename          = file.filename,
        sha256            = sha256,
        total_packets     = features["total_packets"],
        total_bytes       = features["total_bytes"],
        duration_seconds  = features["duration_seconds"],
        unique_src_ips    = features["unique_src_ips"],
        unique_dst_ips    = features["unique_dst_ips"],
        top_protocols     = features["top_protocols"],
        avg_packet_size   = features["avg_packet_size"],
        max_packet_size   = features["max_packet_size"],
        tcp_packets       = features["tcp_packets"],
        udp_packets       = features["udp_packets"],
        icmp_packets      = features["icmp_packets"],
        bytes_per_second  = features["bytes_per_second"],
        risk_score        = risk["risk_score"],
        risk_label        = risk["risk_label"],
        model_used        = risk["model_used"],
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {"result": _row_to_dict(row), "duplicate": False}


# ══════════════════════════════════════════════════════════════════════════════
# GET /analyze-pcap/history
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/analyze-pcap/history")
def pcap_history(
    limit: int    = 20,
    db:    Session = Depends(get_db),
    me:    User    = Depends(get_current_user),
):
    rows = (
        db.query(PcapAnalysis)
        .filter_by(user_id=me.id)
        .order_by(PcapAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_row_to_dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════════
# HELPER
# ══════════════════════════════════════════════════════════════════════════════
def _row_to_dict(r: PcapAnalysis) -> dict:
    return {
        "id":               r.id,
        "filename":         r.filename,
        "sha256":           r.sha256,
        "total_packets":    r.total_packets,
        "total_bytes":      r.total_bytes,
        "duration_seconds": r.duration_seconds,
        "unique_src_ips":   r.unique_src_ips,
        "unique_dst_ips":   r.unique_dst_ips,
        "top_protocols":    r.top_protocols,
        "avg_packet_size":  r.avg_packet_size,
        "max_packet_size":  r.max_packet_size,
        "tcp_packets":      r.tcp_packets,
        "udp_packets":      r.udp_packets,
        "icmp_packets":     r.icmp_packets,
        "bytes_per_second": r.bytes_per_second,
        "risk_score":       r.risk_score,
        "risk_label":       r.risk_label,
        "model_used":       r.model_used,
        "created_at":       str(r.created_at),
    }
