# diag_frontend.py — step-by-step Windows frontend diagnostic
import os, sys, socket, subprocess, http.server, socketserver, functools, threading, time

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
INDEX_FILE   = os.path.join(FRONTEND_DIR, "index.html")

print("=" * 60)
print("  FRONTEND SERVER DIAGNOSTIC")
print("=" * 60)

# ── CHECK 1: Does the directory & file exist? ─────────────────────────────────
print(f"\n[1] frontend/ directory : {os.path.isdir(FRONTEND_DIR)}")
print(f"    frontend/index.html  : {os.path.isfile(INDEX_FILE)}")
if not os.path.isfile(INDEX_FILE):
    print("    ❌ index.html NOT FOUND — check your file placement!")
    sys.exit(1)

# ── CHECK 2: Is port 3000 already in use? ─────────────────────────────────────
def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0

for port in [3000, 8080, 5500]:
    in_use = port_in_use(port)
    print(f"\n[2] Port {port} in use: {in_use}", "← ❌ already occupied!" if in_use else "← ✅ free")
    if not in_use:
        CHOSEN_PORT = port
        break
else:
    print("    ❌ All ports 3000/8080/5500 are in use!")
    sys.exit(1)

print(f"\n    Using port: {CHOSEN_PORT}")

# ── CHECK 3: Can we open a socket? ───────────────────────────────────────────
print(f"\n[3] Testing socket bind on 127.0.0.1:{CHOSEN_PORT}...")
try:
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_sock.bind(("127.0.0.1", CHOSEN_PORT))
    test_sock.close()
    print(f"    ✅ Socket bind successful")
except Exception as e:
    print(f"    ❌ Socket bind FAILED: {e}")
    print("    → Windows Firewall or antivirus may be blocking Python")
    print("    → Try: Allow Python through Windows Defender Firewall")
    sys.exit(1)

# ── START SERVER on 127.0.0.1 (not 0.0.0.0) ─────────────────────────────────
print(f"\n[4] Starting HTTP server...")
print(f"    Serving : {FRONTEND_DIR}")
print(f"    URL     : http://127.0.0.1:{CHOSEN_PORT}/index.html")
print(f"\n    *** Open browser to: http://127.0.0.1:{CHOSEN_PORT}/index.html ***")
print(f"    (use 127.0.0.1, NOT localhost)\n")
print("    Ctrl+C to stop\n")

class VerboseHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)
    def log_message(self, fmt, *args):
        print(f"    → {self.address_string()} [{args[0]}] {args[1]}")

socketserver.TCPServer.allow_reuse_address = True
try:
    with socketserver.TCPServer(("127.0.0.1", CHOSEN_PORT), VerboseHandler) as httpd:
        print(f"    ✅ Server listening on 127.0.0.1:{CHOSEN_PORT}")
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\n    🛑 Stopped.")
except Exception as e:
    print(f"\n    ❌ Server error: {e}")
