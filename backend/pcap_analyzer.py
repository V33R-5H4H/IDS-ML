# backend/pcap_analyzer.py
import hashlib, os, tempfile, logging
from fastapi import UploadFile
from .packet_extractor import extract_features
from .ml_model import ids_model

logger = logging.getLogger("ids_ml.pcap")

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE      = 100 * 1024 * 1024   # 100 MB

ATTACK_TYPES = [
    "back", "buffer_overflow", "ftp_write", "guess_passwd", "imap",
    "ipsweep", "land", "loadmodule", "multihop", "neptune", "nmap",
    "normal", "perl", "phf", "pod", "portsweep", "rootkit", "satan",
    "smurf", "spy", "teardrop", "warezclient", "warezmaster",
]


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
            f"File too large ({size/1024/1024:.1f} MB). "
            f"Max is {MAX_FILE_SIZE//1024//1024} MB"
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _save_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".pcap")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _orm_to_dict(r) -> dict:
    return {
        "id":               r.id,
        "filename":         r.filename,
        "sha256":           r.sha256,
        "file_size":        r.file_size,
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
        "risk_score":       getattr(r, "risk_score",   0.0),
        "risk_label":       getattr(r, "risk_label",   "Unknown"),
        "model_used":       getattr(r, "model_used",   "heuristic"),
        "attack_type":      getattr(r, "attack_type",  "unknown"),
        "first_seen":       r.first_seen,
        "last_seen":        r.last_seen,
        "created_at":       str(r.created_at) if hasattr(r, "created_at") else None,
    }


async def run_analysis(file: UploadFile, db, PcapAnalysis) -> dict:
    data = await file.read()
    _validate_file(file.filename, len(data))

    digest = _sha256(data)
    logger.info(f"PCAP upload: {file.filename}  sha256={digest[:12]}...")

    # Return cached result if same file was analysed before
    existing = db.query(PcapAnalysis).filter(PcapAnalysis.sha256 == digest).first()
    if existing:
        return {
            "duplicate": True,
            "message":   "This file was already analysed. Returning cached result.",
            "result":    _orm_to_dict(existing),
        }

    # Extract features
    tmp_path = _save_temp(data)
    try:
        features = extract_features(tmp_path)
    except ValueError:
        raise
    except Exception as e:
        logger.exception("Unexpected error during feature extraction")
        raise RuntimeError(f"Feature extraction failed: {e}") from e
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    # ML risk scoring + attack type detection
    risk = ids_model.predict(features)
    logger.info(
        f"{file.filename} → {risk['risk_label']} "
        f"({risk['risk_score']:.4f}) [{risk['attack_type']}] "
        f"via {risk['model_used']}"
    )

    record = PcapAnalysis(
        filename          = file.filename,
        sha256            = digest,
        file_size         = len(data),
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
        first_seen        = features["first_seen"],
        last_seen         = features["last_seen"],
        risk_score        = risk["risk_score"],
        risk_label        = risk["risk_label"],
        model_used        = risk["model_used"],
        attack_type       = risk["attack_type"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "duplicate": False,
        "message":   "Analysis complete",
        "result":    _orm_to_dict(record),
    }
