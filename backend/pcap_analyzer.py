# backend/pcap_analyzer.py
import hashlib, os, tempfile, logging
from fastapi import UploadFile
from .packet_extractor import extract_features

logger = logging.getLogger("ids_ml.pcap")

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE      = 100 * 1024 * 1024  # 100 MB


# ── Validation ──────────────────────────────────────────────────────────────
def _validate_file(filename: str, size: int):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    if size == 0:
        raise ValueError("File is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large ({size / 1024 / 1024:.1f} MB). Max is 100 MB."
        )


# ── Helpers ──────────────────────────────────────────────────────────────────
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _save_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".pcap")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


# ── Attack type inference ────────────────────────────────────────────────────
def _infer_attack_type(features: dict, risk_label: str) -> str:
    if risk_label == "Low":
        return "Normal Traffic"

    total  = max(features.get("total_packets", 1), 1)
    bps    = features.get("bytes_per_second", 0)
    icmp_r = features.get("icmp_packets", 0) / total
    src    = features.get("unique_src_ips", 1)
    dur    = max(features.get("duration_seconds", 1), 0.001)

    if risk_label == "Medium":
        if icmp_r > 0.30:
            return "ICMP Probe"
        return "Suspicious Activity"

    # High / Critical
    if icmp_r > 0.40:
        return "ICMP Flood"
    if bps > 500_000:
        return "DDoS / Volumetric"
    if src > 50:
        return "Port Scan"
    if dur < 1 and total > 500:
        return "Burst Attack"
    return "Network Anomaly"


# ── ORM → dict (all fields including risk) ───────────────────────────────────
def _orm_to_dict(r) -> dict:
    return {
        "id":              r.id,
        "filename":        r.filename,
        "sha256":          r.sha256,
        "file_size":       r.file_size,
        "total_packets":   r.total_packets,
        "total_bytes":     r.total_bytes,
        "duration_seconds":r.duration_seconds,
        "unique_src_ips":  r.unique_src_ips,
        "unique_dst_ips":  r.unique_dst_ips,
        "top_protocols":   r.top_protocols,
        "avg_packet_size": r.avg_packet_size,
        "max_packet_size": r.max_packet_size,
        "tcp_packets":     r.tcp_packets,
        "udp_packets":     r.udp_packets,
        "icmp_packets":    r.icmp_packets,
        "bytes_per_second":r.bytes_per_second,
        # ── risk fields ──────────────────────────────────────────────────────
        "risk_score":      r.risk_score,
        "risk_label":      r.risk_label,
        "model_used":      r.model_used,
        "attack_type":     r.attack_type,
        # ── metadata ─────────────────────────────────────────────────────────
        "first_seen":      r.first_seen,
        "last_seen":       r.last_seen,
        "created_at":      str(r.created_at) if hasattr(r, "created_at") and r.created_at else None,
    }


# ── Main analysis entry point ─────────────────────────────────────────────────
async def run_analysis(file: UploadFile, db, PcapAnalysis) -> dict:
    # Import here to avoid circular import at module load
    from .ml_model import ids_model

    data = await file.read()
    _validate_file(file.filename, len(data))

    digest = _sha256(data)
    logger.info("PCAP upload: %s  sha256=%s…", file.filename, digest[:12])

    # ── Return cached result for duplicate uploads ────────────────────────────
    existing = db.query(PcapAnalysis).filter(PcapAnalysis.sha256 == digest).first()
    if existing:
        return {
            "duplicate": True,
            "message":   "This file was already analysed. Returning cached result.",
            "result":    _orm_to_dict(existing),
        }

    # ── Extract packet features ───────────────────────────────────────────────
    tmp_path = _save_temp(data)
    try:
        features = extract_features(tmp_path)
    except ValueError:
        raise
    except Exception as exc:
        logger.exception("Feature extraction error")
        raise RuntimeError(f"Feature extraction failed: {exc}") from exc
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    # ── ML risk scoring ───────────────────────────────────────────────────────
    risk        = ids_model.predict(features)
    attack_type = _infer_attack_type(features, risk["risk_label"])

    logger.warning("==== PCAP PREDICTION DEBUG ====")
    logger.warning("Features extracted: %s", features)
    logger.warning("Model used: %s", risk.get("model_used"))
    logger.warning("Risk Score: %s | Risk Label: %s", risk.get("risk_score"), risk.get("risk_label"))
    logger.warning("Attack Type: %s", attack_type)
    logger.warning("===============================")


    # ── Persist ───────────────────────────────────────────────────────────────
    record = PcapAnalysis(
        filename        = file.filename,
        sha256          = digest,
        file_size       = len(data),
        total_packets   = features["total_packets"],
        total_bytes     = features["total_bytes"],
        duration_seconds= features["duration_seconds"],
        unique_src_ips  = features["unique_src_ips"],
        unique_dst_ips  = features["unique_dst_ips"],
        top_protocols   = features["top_protocols"],
        avg_packet_size = features["avg_packet_size"],
        max_packet_size = features["max_packet_size"],
        tcp_packets     = features["tcp_packets"],
        udp_packets     = features["udp_packets"],
        icmp_packets    = features["icmp_packets"],
        bytes_per_second= features["bytes_per_second"],
        first_seen      = features.get("first_seen"),
        last_seen       = features.get("last_seen"),
        risk_score      = risk["risk_score"],
        risk_label      = risk["risk_label"],
        model_used      = risk["model_used"],
        attack_type     = attack_type,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "duplicate": False,
        "message":   "Analysis complete",
        "result":    _orm_to_dict(record),
    }
