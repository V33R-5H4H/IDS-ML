# Setup Guide - IDS-ML v1.0

## Prerequisites

- **Python:** 3.11 or higher
- **pip:** Latest version
- **RAM:** 4GB minimum (8GB recommended)
- **Storage:** 2GB free space
- **OS:** Windows 10/11, Linux, or macOS

---

## Installation Steps

### 1. Clone/Navigate to Repository
```powershell
cd C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0
```

### 2. Create Virtual Environment

**Windows:**
```powershell
python -m venv backend/.ids1.0_backend
backend\.ids1.0_backend\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv backend/.ids1.0_backend
source backend/.ids1.0_backend/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
```

**Expected output:**
```
Successfully installed fastapi-0.104.1 uvicorn-0.24.0 ...
```

### 4. Download Dataset

**Option A: Manual Download**
1. Visit: https://www.kaggle.com/datasets/hassan06/nslkdd
2. Download and extract
3. Copy these files to `data/raw/`:
   - `KDDTrain+.txt`
   - `KDDTest+.txt`

**Option B: Command Line (with Kaggle CLI)**
```bash
pip install kaggle
kaggle datasets download -d hassan06/nslkdd -p data/raw
unzip data/raw/nslkdd.zip -d data/raw
```

### 5. Configure Environment
```bash
# Copy template
cp .env.example backend/.env

# Edit backend/.env if needed (optional for v1.0)
```

### 6. Preprocess Data
```bash
python scripts/preprocess_data.py
```

**Expected output:**
```
============================================================
IDS-ML DATA PREPROCESSING
============================================================

[1/7] Loading data...
✅ Training data: (125973, 43)
✅ Test data: (18794, 43)

...

[7/7] Saving preprocessed data...
✅ Saved to: data/processed/preprocessed_data.pkl

PREPROCESSING COMPLETE!
```

**Files created:**
- `data/processed/preprocessed_data.pkl`
- `data/processed/train_test_data.npz`

### 7. Train Model
```bash
python scripts/train_model.py
```

**Expected output:**
```
============================================================
IDS-ML MODEL TRAINING - Random Forest
============================================================

[1/5] Loading preprocessed data...
✅ Training samples: 125,973
✅ Test samples: 18,794

[2/5] Training Random Forest model...
Training in progress...
✅ Training complete!

...

✅ Accuracy: 0.8591 (85.91%)
```

**Files created:**
- `models/random_forest_ids.pkl`
- `models/model_metadata.json`

### 8. Start Backend API
```bash
cd backend
python main.py
```

**Expected output:**
```
✅ Model loaded: Random Forest IDS v1.0
   Accuracy: 0.8591
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

**Backend is now running!** 🚀

### 9. Open Frontend

**Option A: Double-click**
- Navigate to `frontend/` folder
- Double-click `index.html`

**Option B: Command line**
```bash
# Windows
start frontend/index.html

# Linux
xdg-open frontend/index.html

# macOS
open frontend/index.html
```

---

## Verification Steps

### 1. Check API Health
```bash
curl http://localhost:8000/health
```

**Expected:**
```json
{"status":"healthy","model_loaded":true}
```

### 2. View API Documentation
Open in browser: http://localhost:8000/docs

### 3. Test Prediction
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 181,
    "dst_bytes": 5450,
    "logged_in": 1,
    "count": 8,
    "srv_count": 8,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "dst_host_srv_count": 9
  }'
```

### 4. Test Frontend
- Open `frontend/index.html`
- Fill in the form
- Click "Analyze Traffic"
- Should see prediction result

---

## Project Structure

```
IDS-ML_1.0/
├── README.md                   # Project overview
├── .gitignore                  # Git ignore rules
├── .env.example                # Environment template
│
├── backend/                    # API server
│   ├── .ids1.0_backend/       # Virtual environment
│   ├── .env                   # Configuration
│   ├── __init__.py
│   ├── config.py              # Settings
│   ├── main.py                # FastAPI app
│   └── requirements.txt       # Dependencies
│
├── data/                       # Dataset
│   ├── raw/                   # Original NSL-KDD
│   │   ├── KDDTrain+.txt
│   │   └── KDDTest+.txt
│   └── processed/             # Preprocessed data
│       ├── preprocessed_data.pkl
│       └── train_test_data.npz
│
├── docs/                       # Documentation
│   ├── API.md                 # API documentation
│   ├── Model.md               # Model details
│   └── Setup.md               # This file
│
├── frontend/                   # Web interface
│   └── index.html
│
├── logs/                       # Application logs
│   └── .gitkeep
│
├── models/                     # Trained models
│   ├── random_forest_ids.pkl  # Model file
│   └── model_metadata.json    # Model info
│
├── notebooks/                  # Jupyter notebooks
│   └── 01-eda.ipynb           # Exploratory analysis
│
└── scripts/                    # Python scripts
    ├── __init__.py
    ├── predict.py             # Inference
    ├── preprocess_data.py     # Data preprocessing
    └── train_model.py         # Model training
```

---

## Troubleshooting

### Issue: Module not found error
```bash
# Reinstall dependencies
pip install -r backend/requirements.txt --upgrade
```

### Issue: Model file not found
```bash
# Retrain the model
python scripts/train_model.py
```

### Issue: Port 8000 already in use
```bash
# Option 1: Change port in backend/.env
API_PORT=8001

# Option 2: Kill process using port 8000
# Windows:
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/macOS:
lsof -ti:8000 | xargs kill -9
```

### Issue: Dataset download fails
```bash
# Download manually from:
# https://www.unb.ca/cic/datasets/nsl.html
# Place files in data/raw/
```

### Issue: Permission denied (Linux/macOS)
```bash
# Add execute permissions
chmod +x scripts/*.py
```

### Issue: Virtual environment activation fails
```powershell
# Windows: Enable scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then retry activation
backend\.ids1.0_backend\Scripts\activate
```

### Issue: Out of memory during training
```python
# Edit scripts/train_model.py
# Reduce n_estimators:
model = RandomForestClassifier(
    n_estimators=100,  # Reduced from 300
    ...
)
```

### Issue: Frontend not connecting to API
```javascript
// Check frontend/index.html
// Update API_URL if port changed:
const API_URL = 'http://localhost:8000';  // Update port
```

---

## Development Workflow

### 1. Activate Environment
```bash
backend\.ids1.0_backend\Scripts\activate  # Windows
source backend/.ids1.0_backend/bin/activate  # Linux/macOS
```

### 2. Make Changes
- Edit code in `backend/`, `scripts/`, or `frontend/`

### 3. Test Changes
```bash
# Run tests (if available)
pytest

# Start API in development mode
uvicorn backend.main:app --reload
```

### 4. Restart API
```bash
# CTRL+C to stop
# Re-run: python backend/main.py
```

---

## Environment Variables

Edit `backend/.env` to customize:

```env
# API Configuration
API_HOST=0.0.0.0          # Listen on all interfaces
API_PORT=8000             # API port
API_TITLE="IDS-ML API"    # API title

# Model Configuration
CONFIDENCE_THRESHOLD=0.7   # Minimum confidence for alerts

# Logging
LOG_LEVEL=INFO            # DEBUG, INFO, WARNING, ERROR
LOG_FILE=../logs/app.log  # Log file path

# CORS (for frontend)
CORS_ORIGINS=http://localhost,http://localhost:3000
```

---

## Performance Optimization

### For Faster Training:
```python
# Use fewer estimators
n_estimators=100  # Instead of 300

# Use all CPU cores
n_jobs=-1

# Limit tree depth
max_depth=10
```

### For Faster Inference:
```python
# Reduce model size
# Use fewer features (trade accuracy for speed)
```

### For Production:
```bash
# Use gunicorn instead of uvicorn
pip install gunicorn
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

---

## Updating Dependencies

```bash
# Check for updates
pip list --outdated

# Update specific package
pip install --upgrade fastapi

# Update all packages (careful!)
pip install --upgrade -r backend/requirements.txt
```

---

## Uninstallation

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf backend/.ids1.0_backend  # Linux/macOS
Remove-Item -Recurse backend/.ids1.0_backend  # Windows

# Remove processed data (optional)
rm -rf data/processed/*
rm -rf models/*.pkl
```

---

## Next Steps

After successful setup:

1. ✅ Explore API at http://localhost:8000/docs
2. ✅ Test frontend interface
3. ✅ Review `docs/API.md` for API usage
4. ✅ Check `docs/Model.md` for model details
5. ✅ Experiment with notebooks in `notebooks/`

---

## Support

For issues:
1. Check logs in `logs/app.log`
2. Review error messages carefully
3. Test with `/health` endpoint
4. Try preprocessing/training again
5. Check GitHub issues (if applicable)

---

## Credits

- **Dataset:** NSL-KDD (UNB, 2009)
- **Framework:** FastAPI, scikit-learn
- **Author:** Your Name
- **Version:** 1.0.0
