"""
Startup script for IDS-ML System
Starts both backend API and frontend server automatically
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path
import os

def start_backend():
    """Start FastAPI backend server"""
    backend_path = Path(__file__).parent / "backend"
    python_exe = backend_path / "ids2.0_backend" / "Scripts" / "python.exe"
    main_py = backend_path / "main.py"

    if not python_exe.exists():
        print("❌ Virtual environment not found!")
        print(f"   Expected: {python_exe}")
        return None

    print("🚀 Starting backend API...")
    backend_process = subprocess.Popen(
        [str(python_exe), str(main_py)],
        cwd=str(backend_path)
    )
    return backend_process

def start_frontend():
    """Start frontend HTTP server"""
    frontend_path = Path(__file__).parent / "frontend"

    print("🌐 Starting frontend server...")
    frontend_process = subprocess.Popen(
        [sys.executable, "-m", "http.server", "3000"],
        cwd=str(frontend_path)
    )
    return frontend_process

def main():
    print("=" * 60)
    print("IDS-ML SYSTEM STARTUP")
    print("=" * 60)

    # Start backend
    backend = start_backend()
    if not backend:
        print("Failed to start backend!")
        return

    # Wait for backend to initialize
    print("⏳ Waiting for backend to initialize...")
    time.sleep(3)

    # Start frontend
    frontend = start_frontend()

    # Wait for frontend to start
    time.sleep(2)

    print("\n" + "=" * 60)
    print("✅ IDS-ML SYSTEM STARTED SUCCESSFULLY!")
    print("=" * 60)
    print("\n📊 Access Points:")
    print("   Backend API:  http://localhost:8000")
    print("   API Docs:     http://localhost:8000/docs")
    print("   Frontend:     http://localhost:3000")
    print("\n🌐 Opening dashboard in browser...")

    # Open browser
    time.sleep(1)
    webbrowser.open('http://localhost:3000')

    print("\n⚠️  Press CTRL+C to stop all servers\n")

    try:
        # Keep running
        backend.wait()
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down servers...")
        backend.terminate()
        frontend.terminate()
        print("✅ Servers stopped. Goodbye!")

if __name__ == "__main__":
    main()
