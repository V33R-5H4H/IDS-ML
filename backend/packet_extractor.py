from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime

def extract_features(pcap_path: str) -> dict:
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        raise ValueError(f"Cannot read PCAP file: {e}")

    if not pkts:
        raise ValueError("PCAP file contains no packets")

    sizes      = []
    src_ips    = set()
    dst_ips    = set()
    proto_ctr  = Counter()
    tcp = udp = icmp = 0
    timestamps = []

    for pkt in pkts:
        sizes.append(len(pkt))
        timestamps.append(float(pkt.time))

        if pkt.haslayer(IP):
            src_ips.add(pkt[IP].src)
            dst_ips.add(pkt[IP].dst)

        if pkt.haslayer(TCP):
            proto_ctr["TCP"] += 1
            tcp += 1
        elif pkt.haslayer(UDP):
            proto_ctr["UDP"] += 1
            udp += 1
        elif pkt.haslayer(ICMP):
            proto_ctr["ICMP"] += 1
            icmp += 1
        else:
            proto_ctr["OTHER"] += 1

    total_packets = len(pkts)
    total_bytes   = sum(sizes)
    first_ts      = min(timestamps)
    last_ts       = max(timestamps)
    duration      = round(last_ts - first_ts, 6)

    return {
        "total_packets":    total_packets,
        "total_bytes":      total_bytes,
        "duration_seconds": duration,
        "unique_src_ips":   len(src_ips),
        "unique_dst_ips":   len(dst_ips),
        "top_protocols":    ",".join(k for k, _ in proto_ctr.most_common(5)),
        "avg_packet_size":  round(total_bytes / total_packets, 2) if total_packets else 0.0,
        "max_packet_size":  max(sizes),
        "tcp_packets":      tcp,
        "udp_packets":      udp,
        "icmp_packets":     icmp,
        "bytes_per_second": round(total_bytes / duration, 2) if duration > 0 else 0.0,
        "first_seen":       datetime.utcfromtimestamp(first_ts).isoformat(),
        "last_seen":        datetime.utcfromtimestamp(last_ts).isoformat(),
    }
