# Quick Start Guide

## 🚀 Start the System

### Windows:
```
Double-click: start.bat
```

### Linux/Mac:
```bash
chmod +x start.sh
./start.sh
```

### Or use Python directly:
```bash
python start.py
```

## 🛑 Stop the System

### Windows:
```
Double-click: stop.bat
```

### Or press CTRL+C in the terminal

## 📊 Access Points

- **Frontend Dashboard:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs

## 🔧 Manual Start

If auto-start doesn't work:

### Terminal 1 (Backend):
```bash
cd backend
python main.py
```

### Terminal 2 (Frontend):
```bash
cd frontend
python -m http.server 3000
```

Then open: http://localhost:3000
