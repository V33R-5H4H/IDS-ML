# backend/live_capture.py — Live packet capture with Scapy + WebSocket streaming
import asyncio
import io
import json
import logging
import traceback
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, List

log = logging.getLogger(__name__)


class CaptureManager:
    """Manages a single live-capture session using Scapy AsyncSniffer."""

    def __init__(self):
        self._sniffer = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packets: List[Dict] = []
        self._raw_packets: List[bytes] = []  # raw bytes for PCAP export
        self._raw_timestamps: List[float] = []  # timestamps for PCAP
        self._stats = self._empty_stats()
        self._analytics = {
            "attack_types": defaultdict(int),
            "protocol_breakdown": defaultdict(int),
            "timeline": [],  # [{timestamp, packets, threats}]
            "top_sources": defaultdict(int),
            "top_destinations": defaultdict(int),
        }
        self._start_time: Optional[float] = None
        self._interface: Optional[str] = None
        self._bpf_filter: Optional[str] = None
        self._subscribers: List[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = threading.Lock()
        self._ml_model = None
        self._timeline_bucket = 0  # current 10-second bucket counters
        self._timeline_bucket_threats = 0

    @staticmethod
    def _empty_stats():
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "threats_detected": 0,
            "ml_predictions": 0,
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
        }

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, interface: str = None, bpf_filter: str = None,
              loop: asyncio.AbstractEventLoop = None):
        """Start packet capture on the given interface."""
        if self._running:
            raise RuntimeError("Capture already running")

        self._interface = interface
        self._bpf_filter = bpf_filter
        self._loop = loop or asyncio.get_event_loop()
        self._running = True
        self._start_time = time.time()
        self._packets = []
        self._raw_packets = []
        self._raw_timestamps = []
        self._stats = self._empty_stats()
        self._analytics = {
            "attack_types": defaultdict(int),
            "protocol_breakdown": defaultdict(int),
            "timeline": [],
            "top_sources": defaultdict(int),
            "top_destinations": defaultdict(int),
        }
        self._timeline_bucket = 0
        self._timeline_bucket_threats = 0

        # Try to load ML model for inference
        self._load_ml_model()

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        log.info("Live capture started on interface=%s filter=%s",
                 interface, bpf_filter)

    def _load_ml_model(self):
        """Load the ML model for real-time inference on packets."""
        try:
            from backend.model_manager import model_manager
            if model_manager.get_active():
                self._ml_model = model_manager
                log.info("ML model loaded for live inference: %s",
                         model_manager.get_active_metadata().get("model_name", "?"))
            else:
                log.warning("No active ML model — live inference disabled")
        except Exception as e:
            log.warning("Could not load ML model for live capture: %s", e)
            self._ml_model = None

    def _capture_loop(self):
        """Run Scapy sniffer in a background thread."""
        try:
            from scapy.all import AsyncSniffer
            kwargs = {"prn": self._process_packet, "store": False}
            if self._interface:
                kwargs["iface"] = self._interface
            if self._bpf_filter:
                kwargs["filter"] = self._bpf_filter

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()

            # Wait until stopped
            while self._running:
                time.sleep(0.1)

            self._sniffer.stop()
        except ImportError:
            log.error("Scapy not installed — live capture unavailable")
            self._running = False
        except Exception as e:
            log.error("Capture thread error: %s", e)
            self._running = False

    def _run_ml_inference(self, pkt_data: dict) -> Optional[str]:
        """Run ML model on packet features. Returns predicted label or None."""
        if not self._ml_model:
            return None
        try:
            from backend.ml_model import ids_model
            f = {
                "total_packets": 1,
                "duration_seconds": 0.001,
                "tcp_packets": 1 if pkt_data.get("protocol") == "TCP" else 0,
                "udp_packets": 1 if pkt_data.get("protocol") == "UDP" else 0,
                "icmp_packets": 1 if pkt_data.get("protocol") == "ICMP" else 0,
                "total_bytes": pkt_data.get("length", 0),
                "unique_dst_ips": 1
            }
            res = ids_model.predict(f)
            self._stats["ml_predictions"] += 1
            return res.get("attack_type", "normal")
        except Exception as e:
            log.debug("ML inference error: %s", e)
        return None

    def _process_packet(self, pkt):
        """Extract features from each packet and queue for WebSocket broadcast."""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether

            pkt_len = len(pkt)
            ts = time.time()
            pkt_data = {
                "timestamp": datetime.now().isoformat(),
                "length": pkt_len,
                "src": "unknown",
                "dst": "unknown",
                "protocol": "OTHER",
                "info": "",
                "risk": "low",
                "prediction": None,
                "_dst_port": 0,
                "_dst_port_enc": 8,
                "_flag_enc": 0,
                "_syn_ratio": 0.0,
                "_has_response": False,
            }

            # ── Extract source/destination IPs ────────────────────────────
            if IP in pkt:
                pkt_data["src"] = pkt[IP].src
                pkt_data["dst"] = pkt[IP].dst
                self._stats["unique_src_ips"].add(pkt[IP].src)
                self._stats["unique_dst_ips"].add(pkt[IP].dst)
            elif IPv6 in pkt:
                pkt_data["src"] = pkt[IPv6].src
                pkt_data["dst"] = pkt[IPv6].dst
                self._stats["unique_src_ips"].add(pkt[IPv6].src)
                self._stats["unique_dst_ips"].add(pkt[IPv6].dst)
            elif ARP in pkt:
                pkt_data["src"] = pkt[ARP].psrc or pkt[ARP].hwsrc
                pkt_data["dst"] = pkt[ARP].pdst or pkt[ARP].hwdst
                pkt_data["protocol"] = "ARP"
                pkt_data["info"] = f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}" if pkt[ARP].op == 1 else f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
                self._stats["other_packets"] += 1
            elif Ether in pkt:
                # Fallback: use MAC addresses
                pkt_data["src"] = pkt[Ether].src
                pkt_data["dst"] = pkt[Ether].dst

            # ── Protocol detection ────────────────────────────────────────
            if TCP in pkt:
                pkt_data["protocol"] = "TCP"
                pkt_data["info"] = f":{pkt[TCP].sport} → :{pkt[TCP].dport}"
                flags = str(pkt[TCP].flags)
                pkt_data["flags"] = flags
                pkt_data["_dst_port"] = pkt[TCP].dport
                pkt_data["_flag_enc"] = (
                    3 * int("S" in flags and "A" not in flags) +
                    1 * int("R" in flags) +
                    2 * int("F" in flags)
                )
                pkt_data["_syn_ratio"] = 1.0 if "S" in flags and "A" not in flags else 0.0
                pkt_data["_has_response"] = "A" in flags
                p = pkt[TCP].dport
                pkt_data["_dst_port_enc"] = (
                    0 if p == 80 else (1 if p == 443 else (2 if p == 22 else
                    (3 if p == 21 else (4 if p == 25 else (5 if p == 53 else
                    (6 if p == 110 else (7 if p < 1024 else 8)))))))
                )
                self._stats["tcp_packets"] += 1
                if pkt[TCP].dport in (4444, 5555, 6666, 31337):
                    pkt_data["risk"] = "high"
                    self._stats["threats_detected"] += 1
                elif pkt[TCP].flags == "S" and pkt_len < 60:
                    pkt_data["risk"] = "medium"
            elif UDP in pkt:
                pkt_data["protocol"] = "UDP"
                pkt_data["info"] = f":{pkt[UDP].sport} → :{pkt[UDP].dport}"
                pkt_data["_dst_port"] = pkt[UDP].dport
                pkt_data["_dst_port_enc"] = 5 if pkt[UDP].dport == 53 else 8
                self._stats["udp_packets"] += 1
                if pkt[UDP].dport == 53:
                    pkt_data["info"] += " (DNS)"
            elif ICMP in pkt:
                pkt_data["protocol"] = "ICMP"
                icmp_type = pkt[ICMP].type
                pkt_data["info"] = f"Type {icmp_type}"
                self._stats["icmp_packets"] += 1
                if pkt_len > 1000:
                    pkt_data["risk"] = "medium"
            elif pkt_data["protocol"] != "ARP":
                self._stats["other_packets"] += 1

            # Run ML inference
            prediction = self._run_ml_inference(pkt_data)
            if prediction:
                pkt_data["prediction"] = prediction
                if prediction != "normal" and prediction != "0":
                    pkt_data["risk"] = "high"
                    self._stats["threats_detected"] += 1
                    self._analytics["attack_types"][prediction] += 1

            # Update analytics
            self._analytics["protocol_breakdown"][pkt_data["protocol"]] += 1
            if IP in pkt:
                self._analytics["top_sources"][pkt[IP].src] += 1
                self._analytics["top_destinations"][pkt[IP].dst] += 1

            # Timeline buckets (every 10 seconds)
            bucket = int(ts) // 10 * 10
            if bucket != self._timeline_bucket and self._timeline_bucket > 0:
                self._analytics["timeline"].append({
                    "time": datetime.fromtimestamp(self._timeline_bucket).isoformat(),
                    "packets": self._stats["total_packets"],
                    "threats": self._timeline_bucket_threats,
                })
                # Keep last 60 buckets (10 minutes)
                if len(self._analytics["timeline"]) > 60:
                    self._analytics["timeline"] = self._analytics["timeline"][-60:]
                self._timeline_bucket_threats = 0
            self._timeline_bucket = bucket
            if pkt_data["risk"] in ("high", "medium"):
                self._timeline_bucket_threats += 1

            # Clean private keys before storing
            clean_data = {k: v for k, v in pkt_data.items() if not k.startswith("_")}

            with self._lock:
                self._stats["total_packets"] += 1
                self._stats["total_bytes"] += pkt_len
                self._packets.append(clean_data)
                # Store raw bytes for PCAP export
                raw = bytes(pkt)
                self._raw_packets.append(raw)
                self._raw_timestamps.append(ts)
                # Keep max 10000 packets in memory
                if len(self._packets) > 10000:
                    self._packets = self._packets[-10000:]
                    self._raw_packets = self._raw_packets[-10000:]
                    self._raw_timestamps = self._raw_timestamps[-10000:]

            # Broadcast to WebSocket subscribers
            self._broadcast(clean_data)

        except Exception as e:
            log.debug("Packet processing error: %s", e)

    def _broadcast(self, pkt_data: dict):
        """Send packet data to all WebSocket subscriber queues."""
        for q in list(self._subscribers):
            try:
                if self._loop and self._loop.is_running():
                    self._loop.call_soon_threadsafe(q.put_nowait, pkt_data)
            except asyncio.QueueFull:
                pass
            except Exception:
                pass

    def subscribe(self) -> asyncio.Queue:
        """Add a new WebSocket subscriber and return its queue."""
        q = asyncio.Queue(maxsize=200)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Remove a WebSocket subscriber."""
        if q in self._subscribers:
            self._subscribers.remove(q)

    def stop(self) -> dict:
        """Stop the capture and return summary stats."""
        if not self._running:
            return self.get_status()
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Live capture stopped — %d packets captured",
                 self._stats["total_packets"])
        return self.get_status()

    def get_status(self) -> dict:
        """Return current capture state and stats."""
        duration = 0
        if self._start_time:
            end = time.time() if self._running else (
                self._start_time + 1)
            duration = round(end - self._start_time, 1)
        with self._lock:
            return {
                "running": self._running,
                "interface": self._interface,
                "filter": self._bpf_filter,
                "duration_seconds": duration,
                "total_packets": self._stats["total_packets"],
                "total_bytes": self._stats["total_bytes"],
                "tcp_packets": self._stats["tcp_packets"],
                "udp_packets": self._stats["udp_packets"],
                "icmp_packets": self._stats["icmp_packets"],
                "other_packets": self._stats["other_packets"],
                "threats_detected": self._stats["threats_detected"],
                "ml_predictions": self._stats["ml_predictions"],
                "unique_src_ips": len(self._stats["unique_src_ips"]),
                "unique_dst_ips": len(self._stats["unique_dst_ips"]),
                "packets_per_sec": round(
                    self._stats["total_packets"] / max(duration, 0.1), 1),
                "stored_packets": len(self._packets),
            }

    def get_packets(self, limit: int = 500) -> List[Dict]:
        """Return captured packets for export."""
        with self._lock:
            return list(self._packets[-limit:])

    def get_pcap_bytes(self, limit: int = 10000) -> bytes:
        """Build a PCAP file in memory from stored raw packets."""
        with self._lock:
            raw = self._raw_packets[-limit:]
            timestamps = self._raw_timestamps[-limit:]

        # Write PCAP global header (libpcap format)
        buf = io.BytesIO()
        # Magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        buf.write(struct.pack("<IHHiIII",
                              0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for raw_pkt, ts in zip(raw, timestamps):
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_len = len(raw_pkt)
            # Packet header: ts_sec, ts_usec, incl_len, orig_len
            buf.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            buf.write(raw_pkt)

        return buf.getvalue()

    def get_analytics(self) -> dict:
        """Return aggregated analytics for the current/last capture session."""
        with self._lock:
            status = self.get_status()

        attack_types = dict(self._analytics["attack_types"])
        protocol_breakdown = dict(self._analytics["protocol_breakdown"])

        # Top sources/destinations (top 10)
        top_src = sorted(self._analytics["top_sources"].items(),
                         key=lambda x: -x[1])[:10]
        top_dst = sorted(self._analytics["top_destinations"].items(),
                         key=lambda x: -x[1])[:10]

        return {
            **status,
            "attack_types": attack_types,
            "protocol_breakdown": protocol_breakdown,
            "timeline": list(self._analytics["timeline"][-30:]),
            "top_sources": [{"ip": ip, "count": c} for ip, c in top_src],
            "top_destinations": [{"ip": ip, "count": c} for ip, c in top_dst],
        }


def get_interfaces() -> list:
    """Return available network interfaces using Scapy."""
    try:
        from scapy.all import get_if_list, conf
        ifaces = []
        try:
            for iface in conf.ifaces.values():
                ifaces.append({
                    "name": str(getattr(iface, 'name', iface)),
                    "description": str(getattr(iface, 'description', '')),
                    "ip": str(getattr(iface, 'ip', '')),
                })
        except Exception:
            for name in get_if_list():
                ifaces.append({"name": name, "description": "", "ip": ""})
        return ifaces
    except ImportError:
        return []
    except Exception as e:
        log.error("Failed to get interfaces: %s", e)
        return []


# Module-level singleton
capture_manager = CaptureManager()
