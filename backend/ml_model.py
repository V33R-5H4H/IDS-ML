# app/ml_model.py  —  ML Risk Scoring for PCAP Features
import os, logging, numpy as np
import joblib
from typing import Dict, Any

log = logging.getLogger(__name__)

# ── Feature order MUST match what was used during model training ──────────────
FEATURE_ORDER = [
    "total_packets",
    "total_bytes",
    "duration_seconds",
    "unique_src_ips",
    "unique_dst_ips",
    "avg_packet_size",
    "max_packet_size",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "bytes_per_second",
    "tcp_ratio",          # derived: tcp_packets / total_packets
]

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
    def __init__(
        self,
        model_path:  str = "models/ids_rf_v1.joblib",
        scaler_path: str = "models/scaler.joblib",
    ):
        self.model  = None
        self.scaler = None
        try:
            self.model  = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            log.info("✅ IDS ML model loaded from %s", model_path)
        except Exception as e:
            log.warning("⚠️  Model files not found (%s) — using heuristic scoring", e)

    def _build_vector(self, f: Dict[str, float]) -> np.ndarray:
        total = max(f.get("total_packets", 1), 1)
        tcp   = f.get("tcp_packets", 0)
        derived = {**f, "tcp_ratio": tcp / total}
        return np.array([derived.get(k, 0.0) for k in FEATURE_ORDER], dtype=np.float64)

    def _heuristic_score(self, f: Dict[str, float]) -> float:
        """
        Rule-based fallback when no trained model is present.
        Each rule contributes a weight; final score is capped at 1.0.
        """
        score = 0.0
        total = max(f.get("total_packets", 1), 1)

        # Very high bytes-per-second  → likely DDoS / flood
        if f.get("bytes_per_second", 0) > 500_000:   score += 0.35
        elif f.get("bytes_per_second", 0) > 100_000: score += 0.15

        # Many unique source IPs      → scanning / spoofing
        if f.get("unique_src_ips", 0) > 50:  score += 0.25
        elif f.get("unique_src_ips", 0) > 20: score += 0.10

        # ICMP ratio > 40 %           → ping flood
        icmp_ratio = f.get("icmp_packets", 0) / total
        if icmp_ratio > 0.4:  score += 0.25
        elif icmp_ratio > 0.2: score += 0.10

        # Very short duration with lots of packets  → burst attack
        dur = f.get("duration_seconds", 1)
        if dur < 1 and total > 1000: score += 0.20

        # Abnormally large max packet  → possible fragmentation attack
        if f.get("max_packet_size", 0) > 9000: score += 0.10

        return min(round(score, 4), 1.0)

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Returns {"risk_score": float, "risk_label": str, "model_used": str}
        """
        vec = self._build_vector(features).reshape(1, -1)

        if self.model and self.scaler:
            try:
                scaled = self.scaler.transform(vec)
                # Works for both classifiers (predict_proba) and anomaly detectors
                if hasattr(self.model, "predict_proba"):
                    proba = self.model.predict_proba(scaled)[0]
                    # Assumes class index 1 = "attack"
                    score = float(proba[1]) if len(proba) > 1 else float(proba[0])
                elif hasattr(self.model, "decision_function"):
                    raw   = self.model.decision_function(scaled)[0]
                    # Isolation Forest: negative = anomaly, positive = normal
                    score = float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
                else:
                    pred  = int(self.model.predict(scaled)[0])
                    score = 1.0 if pred == 1 else 0.1
                return {
                    "risk_score": round(score, 4),
                    "risk_label": score_to_label(score),
                    "model_used": "ids_rf_v1",
                }
            except Exception as e:
                log.error("Model inference failed: %s — falling back to heuristic", e)

        score = self._heuristic_score(features)
        return {
            "risk_score": score,
            "risk_label": score_to_label(score),
            "model_used": "heuristic",
        }


# ── Singleton — import this everywhere ───────────────────────────────────────
ids_model = IDSModel()
