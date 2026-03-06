# stop.py — cleanly kill all IDS-ML servers
import subprocess, sys

PORTS = [8000, 8001, 3000, 8080, 5500, 4000]

print("🛑 Stopping all IDS-ML servers...")
killed = 0

for port in PORTS:
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and f":{port}" in parts[1]:
                pid = parts[4]
                if pid.isdigit() and pid != "0":
                    r = subprocess.run(
                        ["taskkill", "/PID", pid, "/F"],
                        capture_output=True, timeout=5
                    )
                    if r.returncode == 0:
                        print(f"   ✅ Killed PID {pid} (port {port})")
                        killed += 1
    except Exception as e:
        print(f"   ⚠️  Error checking port {port}: {e}")

if killed == 0:
    print("   ℹ️  No IDS-ML processes were running.")
else:
    print(f"\n✅ Stopped {killed} process(es).")
