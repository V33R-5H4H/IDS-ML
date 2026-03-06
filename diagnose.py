#!/usr/bin/env python3
"""
IDS-ML v2.0 — Full Diagnostic Script
Run: python diagnose.py
Checks backend, database, frontend files, auth flow, JS syntax, and more.
"""

import os, sys, re, json, socket, subprocess, time, urllib.request, urllib.error, shutil

BASE = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(BASE, "frontend")
BACKEND  = os.path.join(BASE, "backend")

PASS  = "  ✅"
FAIL  = "  ❌"
WARN  = "  ⚠️ "
INFO  = "  ℹ️ "
SEP   = "─" * 62

issues  = []
fixes   = []

def hdr(title):
    print(f"\n{'═'*62}")
    print(f"  {title}")
    print(f"{'═'*62}")

def ok(msg):   print(f"{PASS} {msg}")
def err(msg, fix=None):
    print(f"{FAIL} {msg}")
    issues.append(msg)
    if fix: fixes.append(fix)
def warn(msg): print(f"{WARN} {msg}")
def info(msg): print(f"{INFO} {msg}")

# ─────────────────────────────────────────────────────────────
# 1. FILE STRUCTURE
# ─────────────────────────────────────────────────────────────
hdr("1. FILE STRUCTURE")

required_files = {
    "frontend/index.html":        "Login page",
    "frontend/dashboard.html":    "Dashboard HTML",
    "frontend/register.html":     "Register page",
    "frontend/js/config.js":      "Auto-generated API port config",
    "frontend/js/auth.js":        "Auth/token management",
    "frontend/js/api.js":         "API wrapper",
    "frontend/js/dashboard.js":   "Dashboard logic",
    "frontend/js/account.js":     "Account management",
    "backend/main.py":            "FastAPI entry point",
    "start.py":                   "Startup script",
    "stop.py":                    "Stop script",
}

for rel, desc in required_files.items():
    path = os.path.join(BASE, rel)
    if os.path.exists(path):
        size = os.path.getsize(path)
        ok(f"{rel} ({size:,} bytes) — {desc}")
    else:
        err(f"MISSING: {rel} — {desc}", f"Recreate {rel}")

# ─────────────────────────────────────────────────────────────
# 2. config.js / API_BASE
# ─────────────────────────────────────────────────────────────
hdr("2. API_BASE CONFIGURATION")

config_path = os.path.join(FRONTEND, "js", "config.js")
auth_path   = os.path.join(FRONTEND, "js", "auth.js")

detected_port = None

if os.path.exists(config_path):
    content = open(config_path, encoding='utf-8', errors='replace').read()
    m = re.search(r'localhost:(\d+)', content)
    if m:
        detected_port = int(m.group(1))
        ok(f"config.js declares API_BASE → port {detected_port}")
    else:
        err("config.js exists but has no localhost:PORT", "Re-run start.py to regenerate config.js")
else:
    err("config.js MISSING — frontend has no API_BASE!", "Run start.py to generate config.js")

if os.path.exists(auth_path):
    auth_content = open(auth_path, encoding='utf-8', errors='replace').read()
    if re.search(r"const API_BASE\s*=", auth_content):
        m2 = re.search(r'localhost:(\d+)', auth_content)
        auth_port = int(m2.group(1)) if m2 else None
        if auth_port and auth_port != detected_port:
            err(f"auth.js ALSO hardcodes API_BASE port {auth_port} — conflicts with config.js port {detected_port}!",
                f"Remove 'const API_BASE' line from auth.js (it should only be in config.js)")
        else:
            warn(f"auth.js still has 'const API_BASE' (port {auth_port}) — should be removed, only config.js should define it")
    else:
        ok("auth.js has no hardcoded API_BASE ✓ (correctly uses config.js)")

# Check all HTML files load config.js BEFORE auth.js
for html_name in ["index.html", "dashboard.html", "register.html"]:
    hp = os.path.join(FRONTEND, html_name)
    if not os.path.exists(hp): continue
    hc = open(hp, encoding='utf-8', errors='replace').read()
    has_config = 'config.js' in hc
    has_auth   = 'auth.js'   in hc
    if not has_config:
        err(f"{html_name} does NOT load config.js — API_BASE will be undefined!",
            f"Add <script src=\"js/config.js\"></script> BEFORE auth.js in {html_name}")
    else:
        ci = hc.find('config.js')
        ai = hc.find('auth.js')
        if ci < ai:
            ok(f"{html_name} loads config.js before auth.js ✓")
        else:
            err(f"{html_name} loads auth.js BEFORE config.js — API_BASE undefined at auth.js load time!",
                f"Move config.js script tag above auth.js in {html_name}")

# ─────────────────────────────────────────────────────────────
# 3. PORT / PROCESS CHECK
# ─────────────────────────────────────────────────────────────
hdr("3. PORT & PROCESS STATUS")

def is_port_open(port, host="127.0.0.1", timeout=1.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close(); return True
    except: return False

# Check common ports
common_ports = [8000, 8001, 8002, 8080, 8090, 9000, 9001, 9002, 3000, 3001]
backend_live_port = None
frontend_live_port = None

print()
for p in common_ports:
    if is_port_open(p):
        label = ""
        if p in [3000, 3001]: label = "  ← Frontend?"
        else: label = "  ← Backend?"
        print(f"  🟢 Port {p} is OPEN{label}")
        if p not in [3000, 3001] and backend_live_port is None:
            backend_live_port = p
        elif p in [3000, 3001]:
            frontend_live_port = p
    else:
        print(f"  ⚫ Port {p} closed")

if backend_live_port:
    ok(f"Backend appears live on port {backend_live_port}")
else:
    err("No backend port found open!", "Run: python start.py")

if frontend_live_port:
    ok(f"Frontend server live on port {frontend_live_port}")
else:
    warn("No frontend server detected on port 3000/3001")

# Cross-check config.js port vs actual live port
if detected_port and backend_live_port:
    if detected_port == backend_live_port:
        ok(f"config.js port {detected_port} matches live backend port {backend_live_port} ✓")
    else:
        err(f"PORT MISMATCH: config.js says port {detected_port} but backend is LIVE on port {backend_live_port}!",
            f"Update frontend/js/config.js: const API_BASE = \"http://localhost:{backend_live_port}\";")

# ─────────────────────────────────────────────────────────────
# 4. BACKEND HEALTH CHECK (HTTP)
# ─────────────────────────────────────────────────────────────
hdr("4. BACKEND HTTP ENDPOINTS")

def http_get(url, token=None, timeout=4):
    try:
        req = urllib.request.Request(url)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as ex:
        return None, str(ex)

test_port = backend_live_port or detected_port or 9001

endpoints = [
    (f"http://localhost:{test_port}/",       "Root"),
    (f"http://localhost:{test_port}/health", "Health check"),
    (f"http://localhost:{test_port}/docs",   "API docs"),
    (f"http://localhost:{test_port}/me",     "/me (no token — expect 401/403)"),
]

for url, label in endpoints:
    status, body = http_get(url)
    if status is None:
        err(f"{label} ({url}) — UNREACHABLE: {body}")
    elif status in [200, 401, 403, 422]:
        ok(f"{label} → HTTP {status}")
        if label == "Health check" and status == 200:
            try:
                d = json.loads(body)
                info(f"  Health: {json.dumps(d, indent=2)[:200]}")
            except: pass
    else:
        warn(f"{label} → HTTP {status}: {body[:100]}")

# ─────────────────────────────────────────────────────────────
# 5. LOGIN FLOW TEST
# ─────────────────────────────────────────────────────────────
hdr("5. LOGIN + /me FLOW TEST")

import urllib.parse

# Check if any user exists in DB by trying default admin credentials
test_creds = [
    ("admin", "admin123"),
    ("admin", "admin"),
    ("admin", "password"),
    ("test",  "test123"),
]

token = None
for username, password in test_creds:
    try:
        data = urllib.parse.urlencode({"username": username, "password": password}).encode()
        req  = urllib.request.Request(
            f"http://localhost:{test_port}/login",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=4) as r:
            resp = json.loads(r.read().decode())
            token = resp.get("access_token")
            if token:
                ok(f"Login SUCCESS as '{username}' — token received")
                break
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code == 401:
            warn(f"Login as '{username}' → 401 Unauthorized (wrong credentials)")
        else:
            warn(f"Login as '{username}' → HTTP {e.code}: {body[:80]}")
    except Exception as ex:
        err(f"Login request failed: {ex}")
        break

if token:
    status, body = http_get(f"http://localhost:{test_port}/me", token=token)
    if status == 200:
        ok(f"/me with token → HTTP 200")
        try:
            user = json.loads(body)
            info(f"  User: {user.get('username')} | Role: {user.get('role')}")
        except: pass
    else:
        err(f"/me with valid token → HTTP {status}: {body[:100]}",
            "Check JWT secret or token expiry in backend/main.py")
else:
    warn("Could not obtain token with test credentials — manual login check skipped")

# ─────────────────────────────────────────────────────────────
# 6. CORS CHECK
# ─────────────────────────────────────────────────────────────
hdr("6. CORS CONFIGURATION")

try:
    req = urllib.request.Request(
        f"http://localhost:{test_port}/health",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "GET"
        }
    )
    with urllib.request.urlopen(req, timeout=4) as r:
        cors = r.headers.get("Access-Control-Allow-Origin", "")
        if cors:
            ok(f"CORS header present: Access-Control-Allow-Origin: {cors}")
        else:
            err("No CORS header returned — browser will block all API calls from frontend!",
                "Add CORSMiddleware to backend/main.py allowing origin http://127.0.0.1:3000")
except Exception as ex:
    warn(f"CORS preflight check failed: {ex}")

# Check main.py for CORS configuration
main_py = os.path.join(BACKEND, "main.py")
if os.path.exists(main_py):
    mc = open(main_py, encoding='utf-8', errors='replace').read()
    if "CORSMiddleware" in mc:
        ok("backend/main.py has CORSMiddleware ✓")
        if '"*"' in mc or "'*'" in mc:
            ok("CORS allow_origins includes wildcard '*' ✓")
        elif "127.0.0.1:3000" in mc or "localhost:3000" in mc:
            ok("CORS allow_origins includes localhost:3000 ✓")
        else:
            warn("CORS origins may not include frontend URL — check allow_origins list")
    else:
        err("backend/main.py has NO CORSMiddleware!",
            "Add: app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])")

# ─────────────────────────────────────────────────────────────
# 7. DATABASE CHECK
# ─────────────────────────────────────────────────────────────
hdr("7. DATABASE CONNECTION")

db_cfg_paths = [
    os.path.join(BACKEND, "database.py"),
    os.path.join(BACKEND, "db.py"),
    os.path.join(BACKEND, "core", "database.py"),
    os.path.join(BACKEND, "app", "database.py"),
]
db_file = next((p for p in db_cfg_paths if os.path.exists(p)), None)

if db_file:
    ok(f"Database file found: {os.path.basename(db_file)}")
    dc = open(db_file, encoding='utf-8', errors='replace').read()
    m = re.search(r'postgresql[+\w]*://([^@\s"\']+@)?([^/\s"\']+)/([^\s"\'?]+)', dc)
    if m:
        info(f"Connection string: postgresql://...@{m.group(2)}/{m.group(3)}")
else:
    warn("No database.py found — checking main.py for DB config")
    if os.path.exists(main_py):
        mc = open(main_py, encoding='utf-8', errors='replace').read()
        m = re.search(r'postgresql[+\w]*://([^@\s"\']+@)?([^/\s"\']+)/([^\s"\'?]+)', mc)
        if m:
            info(f"Connection string in main.py: postgresql://...@{m.group(2)}/{m.group(3)}")

# Try psycopg2 connection
try:
    import psycopg2
    # Extract credentials from config
    db_content = open(db_file, encoding='utf-8', errors='replace').read() if db_file else (open(main_py, encoding='utf-8', errors='replace').read() if os.path.exists(main_py) else "")
    m = re.search(r'postgresql[+\w]*://([^:@\s"\']+):([^@\s"\']+)@([^:/\s"\']+):?(\d+)?/([^\s"\'?]+)', db_content)
    if m:
        user, pwd, host, port_str, dbname = m.group(1), m.group(2), m.group(3), m.group(4) or "5432", m.group(5)
        try:
            conn = psycopg2.connect(host=host, port=int(port_str), dbname=dbname, user=user, password=pwd, connect_timeout=3)
            cur = conn.cursor()
            cur.execute("SELECT version();")
            ver = cur.fetchone()[0]
            ok(f"PostgreSQL connection successful!")
            info(f"  {ver[:60]}")
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public';")
            tables = [r[0] for r in cur.fetchall()]
            ok(f"Tables: {', '.join(tables) if tables else '(none)'}")
            conn.close()
        except Exception as ex:
            err(f"PostgreSQL connection FAILED: {ex}", "Check DB credentials in database.py / ensure PostgreSQL is running")
    else:
        warn("Could not parse DB connection string for direct test")
except ImportError:
    warn("psycopg2 not available for direct DB test — relying on backend health check")

# ─────────────────────────────────────────────────────────────
# 8. JAVASCRIPT SYNTAX CHECK
# ─────────────────────────────────────────────────────────────
hdr("8. JAVASCRIPT SYNTAX CHECK")

js_files = {
    "frontend/js/config.js":    "Config",
    "frontend/js/auth.js":      "Auth",
    "frontend/js/api.js":       "API",
    "frontend/js/dashboard.js": "Dashboard",
    "frontend/js/account.js":   "Account",
}

# Try Node.js if available
node_available = shutil.which("node") is not None
print(f"  Node.js available: {node_available}")

for rel, label in js_files.items():
    path = os.path.join(BASE, rel)
    if not os.path.exists(path): 
        warn(f"{rel} not found — skipping")
        continue
    content = open(path, encoding='utf-8', errors='replace').read()

    # Basic checks
    bt = content.count('`')
    sq = content.count("'")
    dq = content.count('"')

    syntax_ok = True

    # Unbalanced backticks (template literals)
    if bt % 2 != 0:
        err(f"{label} ({rel}): ODD number of backticks ({bt}) — template literal not closed!",
            f"Check {rel} for unclosed template literal (`)")
        syntax_ok = False

    # Check brace balance (roughly)
    opens  = content.count('{')
    closes = content.count('}')
    if abs(opens - closes) > 5:  # allow some in strings
        warn(f"{label}: brace imbalance {{ {opens} open vs {closes} close }}")

    if node_available:
        result = subprocess.run(
            ["node", "--check", path],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ok(f"{label} ({rel}) — Node.js syntax check PASSED ✓")
        else:
            err(f"{label} ({rel}) — Node.js SYNTAX ERROR:\n    {result.stderr.strip()[:200]}",
                f"Fix syntax error in {rel}")
    elif syntax_ok:
        ok(f"{label} ({rel}) — basic checks passed (install Node.js for full syntax check)")

# Check for duplicate const API_BASE definitions
all_js = ""
for rel in js_files:
    path = os.path.join(BASE, rel)
    if os.path.exists(path):
        all_js += f"\n// FILE: {rel}\n" + open(path, encoding='utf-8', errors='replace').read()

api_base_defs = re.findall(r'const API_BASE\s*=\s*["\']http://localhost:\d+["\']', all_js)
if len(api_base_defs) > 1:
    err(f"API_BASE defined {len(api_base_defs)} times across JS files — conflict!: {api_base_defs}",
        "Keep API_BASE ONLY in config.js, remove from all other files")
elif len(api_base_defs) == 1:
    ok(f"API_BASE defined exactly once: {api_base_defs[0]}")
else:
    warn("API_BASE not found in any JS file — will be undefined!")

# ─────────────────────────────────────────────────────────────
# 9. HTML SCRIPT TAG ORDER CHECK
# ─────────────────────────────────────────────────────────────
hdr("9. HTML SCRIPT TAG ORDER")

for html_name in ["index.html", "dashboard.html", "register.html"]:
    hp = os.path.join(FRONTEND, html_name)
    if not os.path.exists(hp): continue
    hc = open(hp, encoding='utf-8', errors='replace').read()

    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', hc)
    js_scripts = [s for s in scripts if not s.startswith('http')]
    print(f"\n  {html_name} script load order:")
    for i, s in enumerate(js_scripts):
        print(f"    {i+1}. {s}")

    names = [os.path.basename(s).split('?')[0] for s in js_scripts]  # strip ?v= before basename
    if 'config.js' in names and 'auth.js' in names:
        ci, ai = names.index('config.js'), names.index('auth.js')
        if ci < ai:
            ok(f"  {html_name}: config.js ({ci+1}) before auth.js ({ai+1}) ✓")
        else:
            err(f"  {html_name}: auth.js ({ai+1}) loaded BEFORE config.js ({ci+1})!",
                f"Swap script order in {html_name}")
    elif 'config.js' not in names:
        err(f"  {html_name}: config.js NOT included!", f"Add <script src=\"js/config.js\"></script> in {html_name}")
    elif 'auth.js' not in names:
        warn(f"  {html_name}: auth.js not found in script list")

# ─────────────────────────────────────────────────────────────
# 10. SUMMARY
# ─────────────────────────────────────────────────────────────
hdr("10. DIAGNOSTIC SUMMARY")

if not issues:
    print(f"\n  🎉 ALL CHECKS PASSED — system appears healthy!")
    print(f"\n  If dashboard is still blank, try:")
    print(f"    1. Open browser DevTools → Console tab")
    print(f"    2. Hard refresh: Ctrl+Shift+R")
    print(f"    3. Look for red errors in Console")
    print(f"    4. Paste the error here")
else:
    print(f"\n  Found {len(issues)} issue(s):\n")
    for i, iss in enumerate(issues, 1):
        print(f"  {i}. ❌ {iss}")
    if fixes:
        print(f"\n  Suggested fixes:\n")
        for i, fix in enumerate(fixes, 1):
            print(f"  {i}. 🔧 {fix}")

print(f"\n{'═'*62}\n")
