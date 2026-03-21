# backend/live_capture.py — Live packet capture with Scapy + WebSocket streaming
import asyncio
import json
import logging
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
        self._stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "threats_detected": 0,
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
        }
        self._start_time: Optional[float] = None
        self._interface: Optional[str] = None
        self._bpf_filter: Optional[str] = None
        self._subscribers: List[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = threading.Lock()

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
        self._stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "threats_detected": 0,
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
        }

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        log.info("Live capture started on interface=%s filter=%s",
                 interface, bpf_filter)

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

    def _process_packet(self, pkt):
        """Extract features from each packet and queue for WebSocket broadcast."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP

            pkt_len = len(pkt)
            pkt_data = {
                "timestamp": datetime.now().isoformat(),
                "length": pkt_len,
                "src": "unknown",
                "dst": "unknown",
                "protocol": "OTHER",
                "info": "",
                "risk": "low",
            }

            if IP in pkt:
                pkt_data["src"] = pkt[IP].src
                pkt_data["dst"] = pkt[IP].dst
                self._stats["unique_src_ips"].add(pkt[IP].src)
                self._stats["unique_dst_ips"].add(pkt[IP].dst)

            if TCP in pkt:
                pkt_data["protocol"] = "TCP"
                pkt_data["info"] = f":{pkt[TCP].sport} → :{pkt[TCP].dport}"
                flags = str(pkt[TCP].flags)
                pkt_data["flags"] = flags
                self._stats["tcp_packets"] += 1
                # Basic heuristic threat detection
                if pkt[TCP].dport in (4444, 5555, 6666, 31337):
                    pkt_data["risk"] = "high"
                    self._stats["threats_detected"] += 1
                elif pkt[TCP].flags == "S" and pkt_len < 60:
                    pkt_data["risk"] = "medium"
            elif UDP in pkt:
                pkt_data["protocol"] = "UDP"
                pkt_data["info"] = f":{pkt[UDP].sport} → :{pkt[UDP].dport}"
                self._stats["udp_packets"] += 1
                if pkt[UDP].dport == 53:
                    pkt_data["info"] += " (DNS)"
            elif ICMP in pkt:
                pkt_data["protocol"] = "ICMP"
                icmp_type = pkt[ICMP].type
                pkt_data["info"] = f"Type {icmp_type}"
                self._stats["icmp_packets"] += 1
                # ICMP flood detection
                if pkt_len > 1000:
                    pkt_data["risk"] = "medium"
            else:
                self._stats["other_packets"] += 1

            with self._lock:
                self._stats["total_packets"] += 1
                self._stats["total_bytes"] += pkt_len
                self._packets.append(pkt_data)
                # Keep max 5000 packets in memory
                if len(self._packets) > 5000:
                    self._packets = self._packets[-5000:]

            # Broadcast to WebSocket subscribers
            self._broadcast(pkt_data)

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
                self._start_time + 1)  # fallback
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
                "unique_src_ips": len(self._stats["unique_src_ips"]),
                "unique_dst_ips": len(self._stats["unique_dst_ips"]),
                "packets_per_sec": round(
                    self._stats["total_packets"] / max(duration, 0.1), 1),
            }

    def get_packets(self, limit: int = 500) -> List[Dict]:
        """Return captured packets for export."""
        with self._lock:
            return list(self._packets[-limit:])


def get_interfaces() -> list:
    """Return available network interfaces using Scapy."""
    try:
        from scapy.all import get_if_list, conf
        ifaces = []
        try:
            # Try to get detailed interface info
            for iface in conf.ifaces.values():
                ifaces.append({
                    "name": str(getattr(iface, 'name', iface)),
                    "description": str(getattr(iface, 'description', '')),
                    "ip": str(getattr(iface, 'ip', '')),
                })
        except Exception:
            # Fallback to simple list
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
