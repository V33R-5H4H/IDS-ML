# test_pcap.py  —  run from project root
# Usage: python test_pcap.py path/to/file.pcap
import sys, os, json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from packet_extractor import extract_features

if len(sys.argv) < 2:
    print("Usage: python test_pcap.py <path/to/file.pcap>")
    sys.exit(1)

path = sys.argv[1]
print(f"\nAnalysing: {path}")
print("-" * 52)

try:
    features = extract_features(path)
    print(json.dumps(features, indent=2, default=str))
    print(f"\n✅  {len(features)} features extracted successfully")
except Exception as e:
    print(f"\n❌  Error: {e}")
    sys.exit(1)
