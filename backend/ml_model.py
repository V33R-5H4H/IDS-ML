# backend/ml_model.py
import logging
import pickle
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

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

ATTACK_TYPES = [
    "back", "buffer_overflow", "ftp_write", "guess_passwd", "imap",
    "ipsweep", "land", "loadmodule", "multihop", "neptune", "nmap",
    "normal", "perl", "phf", "pod", "portsweep", "rootkit", "satan",
    "smurf", "spy", "teardrop", "warezclient", "warezmaster",
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
            self._svc_udp = self._encode_cat("service", "domain_u")
            self._svc_icmp = self._encode_cat("service", "eco_i")

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
        
        # Prevent single packets from being extrapolated into DoS rates
        if total <= 5 and duration < 0.05:
            pkt_rate = total
        else:
            pkt_rate = total / duration

        # ── Categorical encoding ───────────────────────────────────────────────
        # Dominant protocol & appropriate default service
        if tcp >= udp and tcp >= icmp:
            proto_enc = self._proto_map.get("tcp", 1)
            svc_enc = self._svc_default
            logged_in_val = 1.0
        elif udp >= icmp:
            proto_enc = self._proto_map.get("udp", 2)
            svc_enc = getattr(self, "_svc_udp", self._svc_default)
            logged_in_val = 0.0
        else:
            proto_enc = self._proto_map.get("icmp", 0)
            svc_enc = getattr(self, "_svc_icmp", self._svc_default)
            logged_in_val = 0.0

        # Flag: SF = normal established connection (safe default)
        flag_enc = self._flag_map.get("SF", 0)

        # ICMP ratio as SYN error proxy
        icmp_ratio = icmp / total

        # Average bytes per packet
        bpp = total_b / total if total > 0 else 0
        
        # Proxy for connection duration (most individual normal connections are short)
        # PCAPs provide total capture duration, which breaks ML assumptions.
        conn_duration = min(duration, 2.0)

        # ── Assemble vector in exact FEATURE_NAMES order ───────────────────────
        vec = [
            conn_duration,                   # duration proxy
            proto_enc,                       # protocol_type (encoded)
            svc_enc,                         # service       (encoded)
            flag_enc,                        # flag          (encoded)
            bpp * 0.6,                       # src_bytes (normalized)
            bpp * 0.4,                       # dst_bytes (normalized)
            logged_in_val,                   # logged_in (0 for UDP/ICMP)
            min(int(pkt_rate * 2), 511),     # count proxy
            min(int(pkt_rate * 2), 511),     # srv_count proxy


            icmp_ratio,                      # serror_rate
            icmp_ratio,                      # srv_serror_rate
            min(int(pkt_rate * 2), 255),     # dst_host_srv_count (MUST correlate with srv_count!)
        ]

        return np.array(vec, dtype=np.float64).reshape(1, -1)

    # ── Run inference ─────────────────────────────────────────────────────────
    def _infer(self, vec: np.ndarray):
        """Returns (score: float, attack_type: str)"""
        if self.scaler:
            # Pass named DataFrame so scaler doesn't warn about missing feature names
            df = pd.DataFrame(vec, columns=FEATURE_NAMES)
            vec = self.scaler.transform(df)
        
        # Try model_manager first (supports RF/LSTM/CNN switching)
        try:
            from backend.model_manager import model_manager
            active_key = model_manager.get_active()
            if active_key:
                proba = model_manager.predict(vec)
                n_classes = proba.shape[1]
                
                # Find normal class probability
                active_meta = model_manager.get_active_metadata()
                attack_types = active_meta.get("attack_types") or ATTACK_TYPES
                normal_idx = None
                for i, at in enumerate(attack_types):
                    if at == "normal":
                        normal_idx = i
                        break
                
                if normal_idx is not None and normal_idx < n_classes:
                    score = float(1.0 - proba[0][normal_idx])
                else:
                    score = float(1.0 - proba[0][0])
                
                pred_class = int(np.argmax(proba[0]))
                attack_type = (
                    attack_types[pred_class]
                    if pred_class < len(attack_types)
                    else "unknown"
                )
                
                return round(min(max(score, 0.0), 1.0), 4), attack_type, active_key
        except Exception as e:
            log.error("model_manager inference failed, falling back to direct RF. Error: %s", e)
            import traceback
            log.error(traceback.format_exc())
        
        # Fallback: direct RF model inference
        if self.model:
            proba = self.model.predict_proba(vec)[0]
            classes = list(self.model.classes_)
            
            try:
                normal_idx = classes.index(self._normal_idx)
                score = float(1.0 - proba[normal_idx])
            except (ValueError, AttributeError):
                score = float(1.0 - proba[0])
            
            pred_class = int(self.model.predict(vec)[0])
            attack_type = (
                ATTACK_TYPES[pred_class]
                if pred_class < len(ATTACK_TYPES)
                else "unknown"
            )
            
            return round(min(max(score, 0.0), 1.0), 4), attack_type, self.model_name
        
        raise RuntimeError("No model available for inference")
    
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
                score, attack_type, model_used = self._infer(self._build_vector(features))
                return {
                    "risk_score": score,
                    "risk_label": score_to_label(score),
                    "model_used": model_used,
                    "attack_type": attack_type,
                }
            except Exception as e:
                log.error("Model inference error: %s — falling back to heuristic", e)
        
        score = self._heuristic_score(features)
        return {
            "risk_score": score,
            "risk_label": score_to_label(score),
            "model_used": "heuristic",
            "attack_type": "unknown",
        }


# ── Singleton ─────────────────────────────────────────────────────────────────
ids_model = IDSModel()
