# stop.py — kill ALL IDS-ML related processes
import subprocess, sys, time

PORTS = [8000, 8001, 8002, 8003, 8080, 8090, 9000, 3000, 5500, 4000]

print("🛑 Stopping all IDS-ML servers...")
killed_ports = 0
killed_procs = 0

# ── Step 1: Kill by port ──────────────────────────────────────────────────────
for port in PORTS:
    try:
        result = subprocess.run(["netstat", "-ano"],
                                capture_output=True, text=True, timeout=5)
        pids = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and f":{port}" in parts[1]:
                pid = parts[4]
                if pid.isdigit() and pid != "0":
                    pids.add(pid)
        for pid in pids:
            r = subprocess.run(["taskkill", "/PID", pid, "/F"],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                print(f"   ✅ Killed PID {pid} (port {port})")
                killed_ports += 1
    except Exception as e:
        pass

# ── Step 2: Kill lingering uvicorn processes by image name ────────────────────
time.sleep(0.5)
try:
    # Find python processes running uvicorn
    result = subprocess.run(
        ["wmic", "process", "where",
         "name='python.exe' or name='python3.exe'",
         "get", "processid,commandline"],
        capture_output=True, text=True, timeout=10
    )
    for line in result.stdout.splitlines():
        if "uvicorn" in line.lower() or "ids-ml" in line.lower().replace("-",""):
            parts = line.strip().split()
            pid = parts[-1] if parts else None
            if pid and pid.isdigit():
                r = subprocess.run(["taskkill", "/PID", pid, "/F"],
                                   capture_output=True, timeout=5)
                if r.returncode == 0:
                    print(f"   ✅ Killed uvicorn/IDS-ML process PID {pid}")
                    killed_procs += 1
except Exception:
    pass

total = killed_ports + killed_procs
if total == 0:
    print("   ℹ️  No IDS-ML processes were running.")
else:
    print(f"\n✅ Stopped {total} process(es). Ports are clear.")
    print("   You can now run: python start.py")
