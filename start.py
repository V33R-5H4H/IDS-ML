# start.py  — IDS-ML v2.0 system launcher  (auto port + zombie killer)
import sys, os, time, subprocess, threading, webbrowser
import http.server, socketserver, socket, functools

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
PYTHON       = sys.executable

PREFERRED_FRONTEND = 3000
PREFERRED_BACKEND  = 8000

# ══════════════════════════════════════════════════════════════════════════════
# PORT UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def is_port_free(port):
    """Return True if nothing is listening on 127.0.0.1:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0

def kill_port(port):
    """
    On Windows: find the PID using the port via netstat and kill it.
    Returns True if the port is now free.
    """
    try:
        # netstat -ano lists all TCP connections with PIDs
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=5
        )
        pids = set()
        for line in result.stdout.splitlines():
            # Look for lines with :PORT in local address column
            parts = line.split()
            if len(parts) >= 5 and f":{port}" in parts[1]:
                pid = parts[4]
                if pid.isdigit() and pid != "0":
                    pids.add(pid)

        for pid in pids:
            subprocess.run(
                ["taskkill", "/PID", pid, "/F"],
                capture_output=True, timeout=5
            )
            print(f"   🔪 Killed zombie process PID {pid} on port {port}")

        time.sleep(0.5)
        return is_port_free(port)
    except Exception as e:
        print(f"   ⚠️  Could not kill port {port}: {e}")
        return is_port_free(port)

def acquire_port(preferred, fallbacks):
    """
    Try preferred port first (kill zombie if needed).
    Fall back through alternatives if still blocked.
    Returns the port number acquired.
    """
    # 1. Try preferred — kill zombie if occupied
    if not is_port_free(preferred):
        print(f"   ⚠️  Port {preferred} occupied — attempting to free it...")
        if kill_port(preferred):
            print(f"   ✅ Port {preferred} is now free")
            return preferred
        else:
            print(f"   ⚠️  Port {preferred} still busy — trying alternatives...")
    else:
        return preferred

    # 2. Try fallbacks
    for port in fallbacks:
        if is_port_free(port):
            print(f"   ✅ Using fallback port {port}")
            return port

    print(f"   ❌ No available ports! Tried: {[preferred]+fallbacks}")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# FRONTEND HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def log_message(self, fmt, *args):
        # Only show 4xx/5xx — suppress normal request noise
        code = str(args[1]) if len(args) > 1 else ""
        if code and code[0] in ("4", "5") and code != "404":
            print(f"   ⚠️  {self.path} → {args[1]}")

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 60)
print("  IDS-ML v2.0 — SYSTEM STARTUP")
print("=" * 60)

# ── Acquire ports ─────────────────────────────────────────────────────────────
print("\n🔌 Checking ports...")
BACKEND_PORT  = acquire_port(PREFERRED_BACKEND,  [8001, 8002, 8003])
FRONTEND_PORT = acquire_port(PREFERRED_FRONTEND, [8080, 5500, 4000])

FRONTEND_URL = f"http://127.0.0.1:{FRONTEND_PORT}/index.html"

# ── Patch auth.js API_BASE if backend port changed ────────────────────────────
AUTH_JS = os.path.join(FRONTEND_DIR, "js", "auth.js")
if os.path.exists(AUTH_JS):
    with open(AUTH_JS, "r") as f:
        content = f.read()
    import re
    new_content = re.sub(
        r'const API_BASE\s*=\s*["\']http://localhost:\d+["\']',
        f'const API_BASE = "http://localhost:{BACKEND_PORT}"',
        content
    )
    if new_content != content:
        with open(AUTH_JS, "w") as f:
            f.write(new_content)
        print(f"   🔧 Updated auth.js API_BASE → port {BACKEND_PORT}")

# ── Start backend ─────────────────────────────────────────────────────────────
print(f"\n🚀 Starting backend on port {BACKEND_PORT}...")
try:
    backend_proc = subprocess.Popen(
        [PYTHON, "-m", "uvicorn", "backend.main:app",
         "--host", "0.0.0.0",
         "--port", str(BACKEND_PORT),
         "--reload"],
        cwd=BASE_DIR,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
    )
except Exception as e:
    print(f"❌ Backend failed to start: {e}")
    sys.exit(1)

print("⏳ Waiting for backend...")
time.sleep(3)

# ── Start frontend ─────────────────────────────────────────────────────────────
socketserver.TCPServer.allow_reuse_address = True
try:
    httpd = socketserver.TCPServer(("127.0.0.1", FRONTEND_PORT), FrontendHandler)
except OSError as e:
    print(f"❌ Frontend bind failed on port {FRONTEND_PORT}: {e}")
    backend_proc.terminate()
    sys.exit(1)

# ── Summary ────────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  ✅  IDS-ML SYSTEM STARTED SUCCESSFULLY!")
print("=" * 60)
print(f"""
📊 Access Points:
   🔐 Login      →  {FRONTEND_URL}
   📝 Register   →  http://127.0.0.1:{FRONTEND_PORT}/register.html
   📊 Dashboard  →  http://127.0.0.1:{FRONTEND_PORT}/dashboard.html
   🔧 API Docs   →  http://localhost:{BACKEND_PORT}/docs
""")

# ── Open browser ───────────────────────────────────────────────────────────────
threading.Thread(
    target=lambda: (time.sleep(1.5), webbrowser.open(FRONTEND_URL)),
    daemon=True
).start()

print("⚠️  Press CTRL+C to stop all servers\n")

# ── Serve frontend in main thread (permanent, never dies) ─────────────────────
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\n🛑 Shutting down all servers...")
    httpd.server_close()
    backend_proc.terminate()
    backend_proc.wait(timeout=5)
    print("✅ All servers stopped cleanly.")
