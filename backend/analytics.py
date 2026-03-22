# backend/analytics.py
"""
Advanced Analytics Engine for IDS-ML v2.0
Collects and computes analytics from PCAP analyses, live captures, and ML predictions.
"""

import logging
import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from collections import Counter, defaultdict

try:
    from prometheus_client import Counter as PromCounter, Gauge as PromGauge, Histogram
except ImportError:
    PromCounter = PromGauge = Histogram = None

log = logging.getLogger(__name__)

# Prometheus Metrics
if PromCounter:
    PREDICTIONS_TOTAL = PromCounter('ids_predictions_total', 'Total number of predictions', ['source', 'label'])
    ATTACK_GAUGE = PromGauge('ids_active_attacks', 'Current number of active attack predictions in the window')
    CONFIDENCE_HISTOGRAM = Histogram('ids_prediction_confidence', 'Confidence scores of predictions')
else:
    PREDICTIONS_TOTAL = ATTACK_GAUGE = CONFIDENCE_HISTOGRAM = None


class AnalyticsEngine:
    """Computes analytics from stored analysis results and live capture data."""

    def __init__(self):
        self._prediction_log: list = []  # Rolling log of predictions

    def log_prediction(self, label: str, confidence: float, source: str = "pcap",
                       src_ip: str = "", dst_ip: str = "", protocol: str = ""):
        """Log a prediction for analytics tracking."""
        self._prediction_log.append({
            "label": label,
            "confidence": confidence,
            "source": source,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        if PREDICTIONS_TOTAL:
            PREDICTIONS_TOTAL.labels(source=source, label=label).inc()
            CONFIDENCE_HISTOGRAM.observe(confidence)
            if label != "normal":
                ATTACK_GAUGE.inc()
            else:
                ATTACK_GAUGE.dec()
        # Keep last 10k entries
        if len(self._prediction_log) > 10000:
            self._prediction_log = self._prediction_log[-10000:]

    def get_attack_distribution(self, hours: int = 24) -> Dict[str, Any]:
        """Get attack type distribution over the specified period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent = [p for p in self._prediction_log
                  if p["timestamp"] >= cutoff.isoformat()]

        attack_counts = Counter()
        for p in recent:
            if p["label"] != "normal":
                attack_counts[p["label"]] += 1

        total = len(recent)
        attacks = sum(attack_counts.values())
        normal = total - attacks

        return {
            "total_predictions": total,
            "total_attacks": attacks,
            "total_normal": normal,
            "attack_rate": round(attacks / max(total, 1) * 100, 1),
            "distribution": dict(attack_counts.most_common(20)),
            "period_hours": hours,
        }

    def get_detection_trends(self, hours: int = 24, interval: int = 1) -> Dict[str, Any]:
        """Get detection rate trends over time, bucketed by interval (hours)."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        buckets = defaultdict(lambda: {"total": 0, "attacks": 0, "normal": 0})

        for p in self._prediction_log:
            if p["timestamp"] < cutoff.isoformat():
                continue
            ts = datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00"))
            bucket_key = ts.strftime(f"%Y-%m-%d %H:00")
            buckets[bucket_key]["total"] += 1
            if p["label"] == "normal":
                buckets[bucket_key]["normal"] += 1
            else:
                buckets[bucket_key]["attacks"] += 1

        # Sort by time
        sorted_buckets = sorted(buckets.items())
        return {
            "labels": [b[0] for b in sorted_buckets],
            "total": [b[1]["total"] for b in sorted_buckets],
            "attacks": [b[1]["attacks"] for b in sorted_buckets],
            "normal": [b[1]["normal"] for b in sorted_buckets],
            "period_hours": hours,
        }

    def get_top_talkers(self, limit: int = 10) -> Dict[str, Any]:
        """Get top source and destination IPs."""
        src_counter = Counter()
        dst_counter = Counter()
        attack_sources = Counter()

        for p in self._prediction_log:
            if p.get("src_ip"):
                src_counter[p["src_ip"]] += 1
                if p["label"] != "normal":
                    attack_sources[p["src_ip"]] += 1
            if p.get("dst_ip"):
                dst_counter[p["dst_ip"]] += 1

        return {
            "top_sources": dict(src_counter.most_common(limit)),
            "top_destinations": dict(dst_counter.most_common(limit)),
            "top_attack_sources": dict(attack_sources.most_common(limit)),
        }

    def get_protocol_breakdown(self) -> Dict[str, int]:
        """Get protocol distribution."""
        proto_counter = Counter()
        for p in self._prediction_log:
            proto = p.get("protocol", "Unknown")
            if proto:
                proto_counter[proto] += 1
        return dict(proto_counter.most_common(10))

    def get_model_performance(self) -> Dict[str, Any]:
        """Get model performance metrics based on prediction confidence."""
        if not self._prediction_log:
            return {"avg_confidence": 0, "high_confidence": 0, "low_confidence": 0, "total": 0}

        confidences = [p["confidence"] for p in self._prediction_log]
        avg = sum(confidences) / len(confidences)
        high = sum(1 for c in confidences if c >= 0.9)
        low = sum(1 for c in confidences if c < 0.5)

        return {
            "avg_confidence": round(avg, 4),
            "high_confidence_pct": round(high / len(confidences) * 100, 1),
            "low_confidence_pct": round(low / len(confidences) * 100, 1),
            "total_predictions": len(confidences),
        }

    def get_source_comparison(self) -> Dict[str, Any]:
        """Compare PCAP vs Live capture stats."""
        pcap_preds = [p for p in self._prediction_log if p.get("source") == "pcap"]
        live_preds = [p for p in self._prediction_log if p.get("source") == "live"]

        def _stats(preds):
            if not preds:
                return {"total": 0, "attacks": 0, "normal": 0, "attack_rate": 0}
            attacks = sum(1 for p in preds if p["label"] != "normal")
            return {
                "total": len(preds),
                "attacks": attacks,
                "normal": len(preds) - attacks,
                "attack_rate": round(attacks / len(preds) * 100, 1),
            }

        return {
            "pcap": _stats(pcap_preds),
            "live": _stats(live_preds),
        }

    def get_full_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """Get all analytics in one call."""
        return {
            "attack_distribution": self.get_attack_distribution(hours),
            "detection_trends": self.get_detection_trends(hours),
            "top_talkers": self.get_top_talkers(),
            "protocol_breakdown": self.get_protocol_breakdown(),
            "model_performance": self.get_model_performance(),
            "source_comparison": self.get_source_comparison(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def export_csv(self) -> str:
        """Export the analytics prediction log to CSV string format."""
        if not self._prediction_log:
            return "timestamp,label,confidence,source,src_ip,dst_ip,protocol\n"
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["timestamp", "label", "confidence", "source", "src_ip", "dst_ip", "protocol"])
        writer.writeheader()
        for p in self._prediction_log:
            writer.writerow(p)
        return output.getvalue()


# ── Singleton ────────────────────────────────────────────────────────────────
analytics_engine = AnalyticsEngine()
