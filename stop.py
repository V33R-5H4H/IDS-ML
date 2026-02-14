"""
Stop all IDS-ML servers
"""

import subprocess
import sys
import platform

def kill_port(port):
    """Kill process running on specified port"""
    system = platform.system()

    if system == "Windows":
        # Find PID using port
        result = subprocess.run(
            f'netstat -ano | findstr :{port}',
            shell=True,
            capture_output=True,
            text=True
        )

        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    print(f"Killing process {pid} on port {port}...")
                    subprocess.run(f'taskkill /PID {pid} /F', shell=True)
    else:
        # Linux/Mac
        subprocess.run(f'lsof -ti:{port} | xargs kill -9', shell=True)

def main():
    print("=" * 60)
    print("STOPPING IDS-ML SYSTEM")
    print("=" * 60)

    print("\nStopping backend (port 8000)...")
    kill_port(8000)

    print("Stopping frontend (port 3000)...")
    kill_port(3000)

    print("\n✅ All servers stopped!")

if __name__ == "__main__":
    main()
