# start.py  — IDS-ML v2.0 system launcher  (auto port + zombie killer)
import sys, os, time, subprocess, threading, webbrowser
import http.server, socketserver, socket, functools

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
PYTHON       = sys.executable

PREFERRED_FRONTEND = 3000
PREFERRED_BACKEND  = 8000   # will be skipped if held by a non-IDS-ML process

# ══════════════════════════════════════════════════════════════════════════════
# PORT UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def is_port_free(port):
    """Return True if nothing is listening on 127.0.0.1:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0

def kill_all_on_port(port):
    """Kill EVERY process (reloader + worker) listening on a port."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=5
        )
        pids = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and f":{port}" in parts[1] and parts[3] in ("LISTENING","TIME_WAIT","ESTABLISHED"):
                pid = parts[4]
                if pid.isdigit() and pid != "0":
                    pids.add(pid)

        if not pids:
            # Also try without state filter
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1]:
                    pid = parts[4]
                    if pid.isdigit() and pid != "0":
                        pids.add(pid)

        killed = 0
        for pid in pids:
            r = subprocess.run(["taskkill", "/PID", pid, "/F"],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                print(f"   🔪 Killed PID {pid} on port {port}")
                killed += 1

        if killed:
            time.sleep(1.5)  # give OS time to release the port
            # Second attempt if still busy
            if not is_port_free(port):
                time.sleep(1.5)
        return is_port_free(port)
    except Exception as e:
        print(f"   ⚠️  kill_all_on_port({port}): {e}")
        return is_port_free(port)

# Keep old name as alias
kill_port = kill_all_on_port

def acquire_port(preferred, fallbacks):
    """Kill all zombies on preferred port, fall back if still stuck."""
    if not is_port_free(preferred):
        print(f"   ⚠️  Port {preferred} occupied — attempting to free it...")
        if kill_all_on_port(preferred):
            print(f"   ✅ Port {preferred} is now free")
            return preferred
        # Try killing again after brief wait
        time.sleep(1)
        if is_port_free(preferred):
            print(f"   ✅ Port {preferred} is now free")
            return preferred
        print(f"   ⚠️  Port {preferred} still busy — trying alternatives...")
    else:
        return preferred

    for port in fallbacks:
        if not is_port_free(port):
            kill_all_on_port(port)  # clean up fallback ports too
        if is_port_free(port):
            print(f"   ✅ Using fallback port {port}")
            return port

    print(f"   ❌ No available ports! Tried: {[preferred]+fallbacks}")
    print("   💡 Run: python stop.py  — then try again")
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

# Skip port 8000 if it belongs to a foreign (non-IDS-ML) process, use stable 8089 instead
def _is_ids_port(port):
    try:
        import urllib.request as _ur
        with _ur.urlopen(f"http://localhost:{port}/health", timeout=1) as r:
            return b"IDS-ML" in r.read()
    except:
        return False

_p8000_free  = is_port_free(8000)
_p8000_idsml = (not _p8000_free) and _is_ids_port(8000)
if not _p8000_free and not _p8000_idsml:
    print("   ⚠️  Port 8000 held by foreign process — using stable fallback port 8089")
    PREFERRED_BACKEND = 8089

BACKEND_PORT  = acquire_port(PREFERRED_BACKEND,  [8089, 8090, 8091, 8001, 8002, 9001])
FRONTEND_PORT = acquire_port(PREFERRED_FRONTEND, [8080, 5500, 4000])

FRONTEND_URL = f"http://127.0.0.1:{FRONTEND_PORT}/index.html"

# ── Write config.js with current backend port + bust browser cache ──────────
import time as _time
CONFIG_JS  = os.path.join(FRONTEND_DIR, "js", "config.js")
CACHE_VER  = str(int(_time.time()))
config_content = f'''// Auto-generated by start.py — do NOT edit manually or commit to git
// Regenerated on every launch with the correct backend port
window.API_BASE = "http://localhost:{BACKEND_PORT}"; // global — accessible to all scripts
'''
with open(CONFIG_JS, "w", encoding="utf-8") as f:
    f.write(config_content)
print(f"   🔧 config.js → API_BASE = http://localhost:{BACKEND_PORT}")

# Replace ALL version placeholders in HTML files (JSVER + CONFIGVER) with fresh timestamp
import re as _re
for _html in ["index.html", "dashboard.html", "register.html"]:
    _hp = os.path.join(FRONTEND_DIR, _html)
    if not os.path.exists(_hp): continue
    _hc = open(_hp, encoding="utf-8", errors="replace").read()
    # Replace all ?v=JSVER placeholders on local .js script tags
    _hc_new = _re.sub(r'(\.js)\?v=(?:JSVER|CONFIGVER|\d+)', f'\\1?v={CACHE_VER}', _hc)
    if _hc_new != _hc:
        with open(_hp, "w", encoding="utf-8") as _hf:
            _hf.write(_hc_new)
print(f"   🔧 All JS cache-busters → ?v={CACHE_VER} (forces fresh browser fetch)")

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
