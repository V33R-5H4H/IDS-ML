# backend/ml_model.py
import logging
import pickle
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, List

log = logging.getLogger(__name__)

PROJECT_ROOT    = Path(__file__).resolve().parent.parent
MODEL_PATH      = PROJECT_ROOT / "models"  / "random_forest_ids.pkl"
PREPROCESS_PATH = PROJECT_ROOT / "data"    / "processed" / "preprocessed_data.pkl"

# ── Exact 12 features the model was trained on ────────────────────────────────
FEATURE_NAMES = [
    "duration",          # 1  → duration_seconds
    "protocol_type",     # 2  → tcp/udp/icmp  (label-encoded)
    "service",           # 3  → http/ftp/etc  (label-encoded, use "other"→most common)
    "flag",              # 4  → SF/S0/REJ etc (label-encoded, assume "SF" = normal)
    "src_bytes",         # 5  → total_bytes * 0.6
    "dst_bytes",         # 6  → total_bytes * 0.4
    "logged_in",         # 7  → 1 (connected session)
    "count",             # 8  → total_packets capped at 511
    "srv_count",         # 9  → packet rate approximation
    "serror_rate",       # 10 → icmp_ratio (SYN error proxy)
    "srv_serror_rate",   # 11 → icmp_ratio
    "dst_host_srv_count",# 12 → unique_dst_ips capped at 255
]

# attack_types sorted alphabetically — index = encoded class label
# ['back'=0,'buffer_overflow'=1,...,'normal'=11,...]
NORMAL_CLASS_LABEL = 11   # position of 'normal' in sorted attack_types list

RISK_BANDS = [
    (0.75, "Critical"),
    (0.50, "High"),
    (0.25, "Medium"),
    (0.00, "Low"),
]


def score_to_label(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "Low"


class IDSModel:
    def __init__(self):
        self.model          = None
        self.scaler         = None
        self.label_encoders = {}
        self.model_name     = "heuristic"
        self._load()

    def _load(self):
        # ── Load scaler + label encoders ──────────────────────────────────────
        try:
            with open(PREPROCESS_PATH, "rb") as f:
                data = pickle.load(f)
            self.scaler         = data["scaler"]
            self.label_encoders = data.get("label_encoders", {})
            log.info("✅ Scaler and label_encoders loaded from preprocessed_data.pkl")

            # Pre-encode the categorical defaults we'll use
            self._proto_map  = self._build_map("protocol_type", ["tcp","udp","icmp"])
            self._flag_map   = self._build_map("flag", ["SF","S0","REJ","RSTO","SH","OTH"])
            self._svc_default = self._encode_cat("service", "http")

        except Exception as e:
            log.warning("⚠️  Could not load preprocessed_data.pkl: %s", e)

        # ── Load trained model ────────────────────────────────────────────────
        try:
            self.model      = joblib.load(MODEL_PATH)
            self.model_name = "random_forest_ids"
            log.info("✅ RF model loaded — n_features=%d  n_classes=%d",
                     getattr(self.model, "n_features_in_", "?"),
                     len(self.model.classes_))

            # Confirm which index is 'normal' from model's class list
            classes = list(self.model.classes_)
            if NORMAL_CLASS_LABEL in classes:
                self._normal_idx = classes.index(NORMAL_CLASS_LABEL)
            else:
                self._normal_idx = 0
                log.warning("⚠️  Class 11 (normal) not found in model.classes_ — using index 0")

        except Exception as e:
            log.warning("⚠️  Could not load model: %s  —  heuristic mode active", e)
            self._normal_idx = 0

    def _build_map(self, col: str, values: List[str]) -> Dict[str, int]:
        """Pre-compute encoded integers for a list of category values."""
        result = {}
        for v in values:
            result[v] = self._encode_cat(col, v)
        return result

    def _encode_cat(self, col: str, value: str) -> int:
        """Encode a single categorical value using the saved LabelEncoder."""
        le = self.label_encoders.get(col)
        if le is None:
            return 0
        try:
            return int(le.transform([value])[0])
        except ValueError:
            # Unseen label — use first known class (safe fallback)
            return int(le.transform([le.classes_[0]])[0])

    # ── Build exact 12-feature vector from PCAP stats ─────────────────────────
    def _build_vector(self, f: Dict[str, float]) -> np.ndarray:
        total    = max(f.get("total_packets",    1),     1)
        duration = max(f.get("duration_seconds", 0.001), 0.001)
        tcp      = f.get("tcp_packets",      0)
        udp      = f.get("udp_packets",      0)
        icmp     = f.get("icmp_packets",     0)
        total_b  = f.get("total_bytes",      0)
        dst_ips  = f.get("unique_dst_ips",   1)
        pkt_rate = total / duration

        # ── Categorical encoding ───────────────────────────────────────────────
        # Dominant protocol
        if tcp >= udp and tcp >= icmp:
            proto_enc = self._proto_map.get("tcp", 1)
        elif udp >= icmp:
            proto_enc = self._proto_map.get("udp", 2)
        else:
            proto_enc = self._proto_map.get("icmp", 0)

        # Service: default to http (most common in normal traffic)
        svc_enc  = self._svc_default

        # Flag: SF = normal established connection (safe default)
        flag_enc = self._flag_map.get("SF", 0)

        # ICMP ratio as SYN error proxy
        icmp_ratio = icmp / total

        # ── Assemble vector in exact FEATURE_NAMES order ───────────────────────
        vec = [
            duration,                        # duration
            proto_enc,                       # protocol_type (encoded)
            svc_enc,                         # service       (encoded)
            flag_enc,                        # flag          (encoded)
            total_b * 0.6,                   # src_bytes
            total_b * 0.4,                   # dst_bytes
            1.0,                             # logged_in
            min(total, 511),                 # count
            min(int(pkt_rate), 511),         # srv_count
            icmp_ratio,                      # serror_rate
            icmp_ratio,                      # srv_serror_rate
            min(dst_ips, 255),               # dst_host_srv_count
        ]

        return np.array(vec, dtype=np.float64).reshape(1, -1)

    # ── Run inference ─────────────────────────────────────────────────────────
    def _infer(self, vec: np.ndarray) -> float:
        if self.scaler:
            vec = self.scaler.transform(vec)

        proba  = self.model.predict_proba(vec)[0]
        # Attack probability = 1 - P(normal class)
        score  = float(1.0 - proba[self._normal_idx])
        return round(min(max(score, 0.0), 1.0), 4)

    # ── Heuristic fallback ────────────────────────────────────────────────────
    def _heuristic_score(self, f: Dict[str, float]) -> float:
        score = 0.0
        total = max(f.get("total_packets", 1), 1)
        bps   = f.get("bytes_per_second", 0)
        dur   = max(f.get("duration_seconds", 1), 0.001)

        if   bps > 500_000: score += 0.35
        elif bps > 100_000: score += 0.15

        src = f.get("unique_src_ips", 0)
        if   src > 50: score += 0.25
        elif src > 20: score += 0.10

        icmp_ratio = f.get("icmp_packets", 0) / total
        if   icmp_ratio > 0.4: score += 0.25
        elif icmp_ratio > 0.2: score += 0.10

        if dur < 1 and total > 1000: score += 0.20
        if f.get("max_packet_size", 0) > 9000: score += 0.10

        return min(round(score, 4), 1.0)

    # ── Public predict ────────────────────────────────────────────────────────
    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        if self.model:
            try:
                score = self._infer(self._build_vector(features))
                return {
                    "risk_score": score,
                    "risk_label": score_to_label(score),
                    "model_used": self.model_name,
                }
            except Exception as e:
                log.error("Model inference error: %s — falling back to heuristic", e)

        score = self._heuristic_score(features)
        return {
            "risk_score": score,
            "risk_label": score_to_label(score),
            "model_used": "heuristic",
        }


# ── Singleton ─────────────────────────────────────────────────────────────────
ids_model = IDSModel()
