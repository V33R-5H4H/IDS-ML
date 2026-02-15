# 📋 IDS-ML v1.0 — Complete Project Specification

> **Intrusion Detection System using Machine Learning**
> A full-stack, real-time network intrusion detection system powered by a Random Forest classifier, trained on the NSL-KDD benchmark dataset.

---

## 📌 Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Problem Statement & Objectives](#2-problem-statement--objectives)
- [3. System Architecture](#3-system-architecture)
- [4. Tech Stack](#4-tech-stack)
- [5. Machine Learning Pipeline](#5-machine-learning-pipeline)
- [6. API Specification](#6-api-specification)
- [7. Frontend Dashboard](#7-frontend-dashboard)
- [8. Attack Simulators](#8-attack-simulators)
- [9. Project File Structure](#9-project-file-structure)
- [10. File-by-File Inventory](#10-file-by-file-inventory)
- [11. Data Assets](#11-data-assets)
- [12. Model Artifacts](#12-model-artifacts)
- [13. Configuration & Environment](#13-configuration--environment)
- [14. Startup & Shutdown](#14-startup--shutdown)
- [15. Testing & Verification](#15-testing--verification)
- [16. Documentation Suite](#16-documentation-suite)
- [17. Performance Metrics](#17-performance-metrics)
- [18. Known Limitations](#18-known-limitations)
- [19. Future Roadmap](#19-future-roadmap)
- [20. Author & Contact](#20-author--contact)

---

## 1. Project Overview

**IDS-ML** is an intelligent, machine-learning-powered **Network Intrusion Detection System (NIDS)** that analyses network traffic features and classifies them as either *normal* or one of **22 specific attack types** in real time.

### What It Does

| Capability | Description |
|---|---|
| **Real-Time Detection** | Accepts network traffic features via a REST API and returns an instant classification with a confidence score |
| **Multi-Attack Classification** | Distinguishes between 22 attack types across 4 categories — DoS, Probe, R2L, U2R — plus normal traffic |
| **Severity Grading** | Tags each detected attack as *High*, *Medium*, or *Low* severity based on the model's confidence |
| **Interactive Dashboard** | A browser-based UI showing live stats, prediction history, and a form for manual traffic analysis |
| **Automated Testing** | Three separate traffic simulator scripts that send synthetic attack/normal packets to validate the system end-to-end |
| **One-Click Startup** | Batch scripts and a Python orchestrator that launch both backend and frontend in a single step |

### High-Level Data Flow

```
Network Traffic Features
        │
        ▼
  ┌─────────────┐     HTTP/JSON     ┌──────────────────┐
  │  Dashboard   │ ◄──────────────► │  FastAPI Backend  │
  │  (Browser)   │                  │  (Port 8000)      │
  └─────────────┘                  └────────┬───────────┘
                                            │
                                   ┌────────▼───────────┐
                                   │  IDSPredictor       │
                                   │  (predict.py)       │
                                   └────────┬───────────┘
                                            │
                                   ┌────────▼───────────┐
                                   │  Random Forest      │
                                   │  (300 Trees, ~148MB)│
                                   └────────────────────┘
```

---

## 2. Problem Statement & Objectives

### Problem

Traditional signature-based IDS can only detect known attack patterns and fail to generalise to variations or novel threats. Manual inspection of network traffic at scale is infeasible.

### Objectives

1. Design and implement an ML-based IDS achieving **≥85% accuracy** on the NSL-KDD benchmark.
2. Provide a **REST API** for real-time, low-latency predictions (~45 ms per request).
3. Build an **interactive web dashboard** for security analysts.
4. Include **automated traffic simulators** for end-to-end system testing.
5. Document the entire pipeline — data, model, API, and deployment.

### Scope

| Dimension | Detail |
|---|---|
| Dataset | NSL-KDD (125,973 train / 18,794 test samples after filtering) |
| Algorithm | Random Forest Classifier (300 estimators) |
| Features | 12 selected network traffic features (out of 41 original) |
| Attack Categories | DoS, Probe, R2L, U2R |
| Deployment | Local (localhost), manual start |

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                 │
│                                                                      │
│  ┌───────────────────┐   ┌───────────────────┐   ┌──────────────┐  │
│  │   Web Dashboard   │   │  Attack Simulator  │   │  Enhanced    │  │
│  │  HTML/CSS/JS +    │   │  (attack_           │   │  Simulator   │  │
│  │  Bootstrap 5      │   │   simulator.py)    │   │  + Dashboard │  │
│  │  Port 3000        │   │                    │   │  Simulator   │  │
│  └────────┬──────────┘   └────────┬───────────┘   └──────┬───────┘  │
│           │                       │                       │          │
└───────────┼───────────────────────┼───────────────────────┼──────────┘
            │         HTTP / JSON   │                       │
            └───────────────────────┼───────────────────────┘
                                    │
┌───────────────────────────────────┼──────────────────────────────────┐
│                          API LAYER                                    │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  FastAPI Application (backend/main.py) — Port 8000            │  │
│  │                                                                │  │
│  │  Endpoints:                                                    │  │
│  │    GET  /            — Root info                               │  │
│  │    GET  /health      — Health check                            │  │
│  │    GET  /model/info  — Model metadata & features               │  │
│  │    POST /predict     — Classify traffic                        │  │
│  │    GET  /stats       — System statistics                       │  │
│  │    GET  /history     — Recent prediction history (last 20)     │  │
│  │    POST /reset-stats — Reset counters (testing)                │  │
│  │                                                                │  │
│  │  Middleware: CORS (all origins)                                 │  │
│  │  Validation: Pydantic v2 models                                │  │
│  │  Server: Uvicorn (ASGI)                                        │  │
│  └─────────────────────────┬──────────────────────────────────────┘  │
│                             │                                        │
└─────────────────────────────┼────────────────────────────────────────┘
                              │
┌─────────────────────────────┼────────────────────────────────────────┐
│                          ML LAYER                                     │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  IDSPredictor (scripts/predict.py)                              │ │
│  │                                                                 │ │
│  │  1. Loads trained model (.pkl) + preprocessor (.pkl)            │ │
│  │  2. Applies LabelEncoder to categorical features               │ │
│  │  3. Applies StandardScaler to all features                     │ │
│  │  4. Runs model.predict() + model.predict_proba()               │ │
│  │  5. Decodes label → attack name                                │ │
│  │  6. Returns prediction, confidence, is_attack flag             │ │
│  └─────────────────────────┬───────────────────────────────────────┘ │
│                             │                                        │
│  ┌─────────────────────────▼───────────────────────────────────────┐ │
│  │  Random Forest Model (models/random_forest_ids.pkl)             │ │
│  │  • 300 decision trees, unlimited depth                         │ │
│  │  • Balanced subsample class weighting                          │ │
│  │  • Trained on 125,973 samples, 12 features                    │ │
│  │  • Test accuracy: 85.91%                                       │ │
│  │  • Model file size: ~148 MB (joblib serialised)                │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Tech Stack

### Backend

| Technology | Version | Purpose |
|---|---|---|
| **Python** | 3.11+ | Primary language |
| **FastAPI** | 0.104.1 | REST API framework |
| **Uvicorn** | 0.24.0 | ASGI web server |
| **Pydantic** | 2.4.2 | Request/response validation |
| **python-dotenv** | 1.0.0 | Environment variable management |
| **python-multipart** | 0.0.6 | Form data parsing |

### Machine Learning & Data Science

| Technology | Version | Purpose |
|---|---|---|
| **scikit-learn** | 1.5.2 | Random Forest, preprocessing (StandardScaler, LabelEncoder), metrics |
| **pandas** | 2.2.0 | Data loading, manipulation, feature engineering |
| **numpy** | 1.26.4 | Numerical operations, array handling |
| **joblib** | 1.4.2 | Model serialisation (pickle alternative) |
| **matplotlib** | 3.9.0 | Visualisation (for notebooks / EDA) |
| **seaborn** | 0.13.2 | Statistical visualisation (for notebooks / EDA) |

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| **HTML5** | — | Dashboard structure |
| **CSS3** | — | Custom styling (gradients, animations, responsive) |
| **JavaScript (ES6+)** | — | Dashboard logic, API communication, polling |
| **Bootstrap** | 5.1.3 | UI component framework (CDN) |
| **Fetch API** | — | HTTP requests to backend |
| **Python `http.server`** | — | Static file server for frontend (port 3000) |

### Development & Tooling

| Technology | Purpose |
|---|---|
| **Git** | Version control |
| **VS Code / IntelliJ IDEA** | IDE (`.vscode/` and `.idea/` config present) |
| **pytest** | 7.4.3 — Test framework |
| **pytest-cov** | 4.1.0 — Coverage reporting |
| **httpx** | 0.25.2 — Async HTTP test client |
| **Jupyter Notebook** | Exploratory data analysis (`01-eda.ipynb`) |

---

## 5. Machine Learning Pipeline

### 5.1 Dataset — NSL-KDD

| Property | Value |
|---|---|
| Source | University of New Brunswick |
| Original features | 41 + attack label + difficulty level |
| Training samples | 125,973 |
| Test samples (after filtering) | 18,794 |
| Attack types in training set | 22 (plus `normal`) |
| Files | `KDDTrain+.txt`, `KDDTest+.txt` |

The test set is filtered to remove attack types that don't appear in the training set (unseen attacks are excluded during preprocessing).

### 5.2 Feature Selection

12 features were selected from the original 41 based on domain knowledge and correlation analysis:

| # | Feature | Type | Description |
|---|---|---|---|
| 1 | `duration` | int | Connection duration (seconds) |
| 2 | `protocol_type` | categorical | tcp / udp / icmp |
| 3 | `service` | categorical | Network service (http, ftp, ssh, smtp, private, etc.) |
| 4 | `flag` | categorical | Connection status flag (SF, S0, REJ, RSTO, etc.) |
| 5 | `src_bytes` | int | Bytes from source to destination |
| 6 | `dst_bytes` | int | Bytes from destination to source |
| 7 | `logged_in` | binary | Whether user is logged in (0/1) |
| 8 | `count` | int | Connections to same host in past 2 sec |
| 9 | `srv_count` | int | Connections to same service in past 2 sec |
| 10 | `serror_rate` | float | % of connections with SYN errors |
| 11 | `srv_serror_rate` | float | % of service connections with SYN errors |
| 12 | `dst_host_srv_count` | int | Count of connections to destination host |

### 5.3 Preprocessing Steps (`scripts/preprocess_data.py`)

| Step | Operation | Tool |
|---|---|---|
| 1 | Load train & test CSVs | pandas |
| 2 | Filter test set — remove unseen attack types | pandas |
| 3 | Select 12 features | pandas |
| 4 | Encode categoricals (`protocol_type`, `service`, `flag`) | `LabelEncoder` (fit on combined train+test) |
| 5 | Scale all features | `StandardScaler` (fit on train, transform both) |
| 6 | Encode target labels | `LabelEncoder` |
| 7 | Save to `.pkl` and `.npz` | pickle, numpy |

**Output artifacts:**

- `data/processed/preprocessed_data.pkl` — Contains: `X_train`, `X_test`, `y_train_encoded`, `y_test_encoded`, `scaler`, `label_encoders`, `label_encoder_target`, `feature_names`, `attack_types`
- `data/processed/train_test_data.npz` — Numpy arrays only

### 5.4 Model Training (`scripts/train_model.py`)

| Hyperparameter | Value |
|---|---|
| Algorithm | `RandomForestClassifier` |
| `n_estimators` | 300 |
| `max_depth` | None (unlimited) |
| `min_samples_split` | 4 |
| `min_samples_leaf` | 2 |
| `class_weight` | `balanced_subsample` |
| `n_jobs` | -1 (all CPU cores) |
| `random_state` | 42 |

**Output artifacts:**

- `models/random_forest_ids.pkl` (~148 MB) — Serialised model (joblib)
- `models/model_metadata.json` — Name, accuracy, features, attack types

### 5.5 Inference (`scripts/predict.py`)

The `IDSPredictor` class:

1. Loads model + preprocessor at startup.
2. Accepts a dictionary of 12 features.
3. Creates a DataFrame, encodes categoricals (with fallback for unseen values).
4. Scales features using the saved `StandardScaler`.
5. Calls `model.predict()` and `model.predict_proba()`.
6. Returns: `prediction` (string), `confidence` (float), `is_attack` (bool).
7. Full `predict()` also returns top-5 class probabilities.

### 5.6 Detectable Attack Types (22 + Normal)

| Category | Attacks |
|---|---|
| **DoS** | neptune, smurf, back, teardrop, pod, land |
| **Probe** | satan, ipsweep, portsweep, nmap |
| **R2L** | guess_passwd, ftp_write, imap, phf, multihop, warezmaster, warezclient, spy |
| **U2R** | buffer_overflow, loadmodule, rootkit, perl |
| **Benign** | normal |

### 5.7 Feature Importance (Top 5)

| Rank | Feature | Importance |
|---|---|---|
| 1 | `src_bytes` | 20.4% |
| 2 | `dst_bytes` | 14.0% |
| 3 | `dst_host_srv_count` | 12.2% |
| 4 | `service` | 11.3% |
| 5 | `count` | 8.0% |

---

## 6. API Specification

**Base URL:** `http://localhost:8000`

### Endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| `GET` | `/` | Root — returns API name, version, status | None |
| `GET` | `/health` | Health check — confirms model is loaded | None |
| `GET` | `/model/info` | Returns model name, accuracy, version, feature list | None |
| `POST` | `/predict` | Classify a single traffic record | None |
| `GET` | `/stats` | Total predictions, attacks detected, normal count, model accuracy | None |
| `GET` | `/history` | Last 20 predictions (from in-memory buffer of 50) | None |
| `POST` | `/reset-stats` | Resets all counters to zero | None |

### `/predict` — Request Schema

```json
{
  "duration": 0,            // int, connection duration
  "protocol_type": "tcp",   // str, tcp | udp | icmp
  "service": "http",        // str, network service
  "flag": "SF",             // str, connection flag
  "src_bytes": 181,         // int, source bytes
  "dst_bytes": 5450,        // int, destination bytes
  "logged_in": 1,           // int, 0 or 1
  "count": 8,               // int, connections count
  "srv_count": 8,           // int, service connections
  "serror_rate": 0.0,       // float, SYN error rate
  "srv_serror_rate": 0.0,   // float, service SYN error rate
  "dst_host_srv_count": 9   // int, destination host count
}
```

### `/predict` — Response Schema

```json
{
  "prediction": "normal",      // str, attack name or "normal"
  "confidence": 0.9234,        // float, max class probability
  "is_attack": false,          // bool
  "severity": "None",          // str, None | Low | Medium | High
  "version": "1.0.0",         // str
  "timestamp": "2026-02-15T13:00:00.000000"  // str, ISO 8601
}
```

**Severity logic:**

- Not an attack → `"None"`
- Attack with confidence ≥ 0.9 → `"High"`
- Attack with confidence ≥ 0.7 → `"Medium"`
- Attack with confidence < 0.7 → `"Low"`

### Auto-Generated Docs

| Format | URL |
|---|---|
| Swagger UI | `http://localhost:8000/docs` |
| ReDoc | `http://localhost:8000/redoc` |

### Response Codes

| Code | Meaning |
|---|---|
| 200 | Success |
| 422 | Validation error (bad input) |
| 500 | Internal server error |
| 503 | Model not loaded / service unavailable |

---

## 7. Frontend Dashboard

### Technology

- **Served by:** `python -m http.server 3000` (static files)
- **UI Framework:** Bootstrap 5.1.3 (CDN)
- **Custom CSS:** `style.css` — gradient headers, card hover effects, slide-in animations, responsive layout
- **JS Logic:** `app.js` — Polls `/stats` and `/history` every 2 seconds, handles form submission, displays colour-coded results

### Dashboard Sections

| Section | Description |
|---|---|
| **Header** | Purple gradient banner with project name |
| **Stats Row** | 4 metric cards — Model Accuracy, Total Predictions, Attacks Detected, Model Version |
| **Prediction Form** | 12-field form (dropdowns + number inputs) with "Analyze Traffic" button |
| **Prediction Result** | Slide-in card — green for normal, red for attack — shows prediction, confidence, severity |
| **System Information** | Model name, accuracy, list of 12 features |
| **Recent Predictions** | Colour-coded list of last 10 predictions with timestamps |

### Alternate Frontend JS

- `app_js_autorefresh.js` — An alternative version with localStorage-based state persistence and fetch request interception for counting predictions across tabs.

### Polling Behaviour

- Stats and history are polled every **2 seconds**.
- Polling pauses when the browser tab is hidden (via `visibilitychange` event).
- Polling resumes when the tab becomes visible again.

---

## 8. Attack Simulators

The project includes **three** traffic simulation scripts:

### 8.1 `attack_simulator.py` — Basic Simulator

| Mode | Packets | Attack Rate | Delay |
|---|---|---|---|
| 1 — Quick Demo | 20 | 30% | 0.5s |
| 2 — Continuous | 60 sec | 30% | 1.0s |
| 3 — Heavy Attack | 30 | 70% | 0.5s |
| 4 — All Attack Types | All 8 + 4 normal | — | 1.0s |
| 5 — Custom | User-defined | User-defined | User-defined |

- Simulates 8 attack types (Neptune, Smurf, PortSweep, Satan, IPSweep, Back, Teardrop, PoD) and 4 normal traffic patterns (HTTP, FTP, SMTP, SSH).
- Prints a summary table at the end.

### 8.2 `enhanced_attack_sim.py` — Detailed Simulator

- Same attack/normal patterns as above but with **detailed terminal output** for each packet.
- Shows full feature table, explains *why* each pattern is detected as attack/normal.
- Opens the dashboard in the browser automatically.
- **Best for presentations** — lets the audience see both terminal details and dashboard updates.

### 8.3 `dashboard_attack_sim.py` — Dashboard-Focused Simulator

- Minimal terminal output — only prints one-line status per packet.
- Designed to be run while watching the **dashboard for live updates**.
- Opens browser automatically.

---

## 9. Project File Structure

```
IDS-ML_1.0/
│
├── .env.example                     # Environment variable template
├── .gitignore                       # Git ignore rules
├── README.md                        # Primary project documentation
├── QUICKSTART.md                    # Quick start guide
├── PROJECT_REPORT.md                # Academic project report template
├── PRESENTATION_OUTLINE.md          # Slide-by-slide presentation guide
├── FINAL_CHECKLIST.md               # Submission checklist
├── PROJECT_SPECS.md                 # ◀ THIS FILE
│
├── start.py                         # Python startup orchestrator
├── start.bat                        # Windows batch startup
├── stop.py                          # Python shutdown script
├── stop.bat                         # Windows batch shutdown
├── attack_simulator.py              # Basic traffic simulator
├── enhanced_attack_sim.py           # Detailed traffic simulator
├── dashboard_attack_sim.py          # Dashboard-focused simulator
│
├── backend/                         # ─── API Backend ───
│   ├── .ids1.0_backend/             # Python virtual environment
│   ├── .env                         # Environment variables (not tracked)
│   ├── __init__.py                  # Package init (version, author)
│   ├── config.py                    # Configuration class (paths, ports, CORS)
│   ├── main.py                      # FastAPI app (7 endpoints, Pydantic models)
│   └── requirements.txt             # Pinned Python dependencies (15 packages)
│
├── frontend/                        # ─── Web Dashboard ───
│   ├── index.html                   # Dashboard HTML (Bootstrap 5)
│   ├── style.css                    # Custom CSS (gradients, animations)
│   ├── app.js                       # Main JS (polling, form handling)
│   └── app_js_autorefresh.js        # Alternative JS (localStorage persistence)
│
├── scripts/                         # ─── ML Pipeline Scripts ───
│   ├── __init__.py                  # Package init
│   ├── preprocess_data.py           # 7-step data preprocessing
│   ├── train_model.py               # Random Forest training (5 steps)
│   └── predict.py                   # IDSPredictor class (inference)
│
├── data/                            # ─── Dataset ───
│   ├── raw/                         # Original NSL-KDD files
│   │   ├── KDDTrain+.txt            # Training data (~18 MB)
│   │   ├── KDDTest+.txt             # Test data (~3.3 MB)
│   │   └── nsl-kdd/                 # Full NSL-KDD download (ARFF + TXT + images)
│   └── processed/                   # Preprocessed artifacts
│       ├── preprocessed_data.pkl    # Complete preprocessor bundle (~14.4 MB)
│       └── train_test_data.npz      # Numpy arrays (~13.8 MB)
│
├── models/                          # ─── Trained Models ───
│   ├── random_forest_ids.pkl        # Trained model (~148 MB)
│   └── model_metadata.json          # Model metadata (JSON)
│
├── docs/                            # ─── Documentation ───
│   ├── API.md                       # REST API documentation
│   ├── Setup.md                     # Installation & setup guide
│   └── Model.md                     # Model performance details
│
├── notebooks/                       # ─── Jupyter Notebooks ───
│   └── 01-eda.ipynb                 # Exploratory Data Analysis
│
└── logs/                            # ─── Application Logs ───
    └── (app.log — created at runtime)
```

---

## 10. File-by-File Inventory

### Root-Level Files

| File | Size | Purpose |
|---|---|---|
| `README.md` | 15.5 KB | Primary project documentation (523 lines) |
| `PROJECT_REPORT.md` | 10.3 KB | Academic report template with sections for abstract, methodology, results |
| `PRESENTATION_OUTLINE.md` | 11.5 KB | 19-slide presentation outline with speaker notes and Q&A answers |
| `FINAL_CHECKLIST.md` | 8.1 KB | Comprehensive submission checklist (documentation, testing, deployment) |
| `QUICKSTART.md` | 707 B | Minimal quickstart — 3 commands to run the system |
| `PROJECT_SPECS.md` | — | This specification document |
| `.env.example` | 1.1 KB | Environment variable template |
| `.gitignore` | 881 B | Ignores venv, data files, model binaries, logs, IDE configs |
| `start.py` | 2.3 KB | Orchestrates backend + frontend startup, opens browser |
| `start.bat` | 245 B | Windows wrapper for `start.py` |
| `stop.py` | 1.2 KB | Kills processes on ports 8000 & 3000 (cross-platform) |
| `stop.bat` | 63 B | Windows wrapper for `stop.py` |
| `attack_simulator.py` | 15.9 KB | Basic attack simulator (5 modes, 8 attack + 4 normal patterns) |
| `enhanced_attack_sim.py` | 20.6 KB | Detailed simulator with feature tables & explanations |
| `dashboard_attack_sim.py` | 16.7 KB | Dashboard-focused simulator (minimal terminal output) |

### Backend Files

| File | Size | Purpose |
|---|---|---|
| `backend/__init__.py` | 187 B | Package metadata — version `1.0.0`, author `V33R5H4H` |
| `backend/config.py` | 1.3 KB | `Config` class — model paths, API settings, CORS, logging, DB URL placeholder |
| `backend/main.py` | 7.4 KB | FastAPI app — 7 endpoints, 4 Pydantic models, in-memory stats tracking |
| `backend/requirements.txt` | 600 B | 15 pinned dependencies |
| `backend/.env` | 757 B | Active environment config (git-ignored) |

### Frontend Files

| File | Size | Purpose |
|---|---|---|
| `frontend/index.html` | 9.1 KB | Dashboard layout — 4 stat cards, prediction form, system info, history |
| `frontend/style.css` | 3.4 KB | Custom styles — gradients, animations, responsive breakpoints |
| `frontend/app.js` | 6.8 KB | Main logic — polling every 2s, form submission, result display |
| `frontend/app_js_autorefresh.js` | 8.6 KB | Alternative — adds localStorage, fetch interception |

### Script Files

| File | Size | Purpose |
|---|---|---|
| `scripts/__init__.py` | 106 B | Package metadata |
| `scripts/preprocess_data.py` | 6.5 KB | 7-step preprocessing pipeline |
| `scripts/train_model.py` | 4.6 KB | 5-step model training pipeline |
| `scripts/predict.py` | 5.0 KB | `IDSPredictor` class + standalone test |

### Documentation Files

| File | Size | Purpose |
|---|---|---|
| `docs/API.md` | 5.7 KB | Complete API reference with examples in Python, cURL, JS |
| `docs/Setup.md` | 9.6 KB | Step-by-step installation, troubleshooting, env vars, performance tips |
| `docs/Model.md` | 1.4 KB | Model performance breakdown by attack category + feature importance |

---

## 11. Data Assets

### Raw Data (`data/raw/`)

| File | Size | Description |
|---|---|---|
| `KDDTrain+.txt` | 18.2 MB | NSL-KDD training set (125,973 records, 43 columns) |
| `KDDTest+.txt` | 3.3 MB | NSL-KDD test set (22,544 records, 43 columns) |
| `nsl-kdd/` | — | Full dataset download containing ARFF and TXT variants, 20% subsets, and info page |

### Processed Data (`data/processed/`)

| File | Size | Description |
|---|---|---|
| `preprocessed_data.pkl` | 14.4 MB | Complete preprocessing bundle (arrays + scaler + encoders + metadata) |
| `train_test_data.npz` | 13.8 MB | Numpy arrays only (X_train, X_test, y_train, y_test) |

---

## 12. Model Artifacts

### Trained Model

| Property | Value |
|---|---|
| File | `models/random_forest_ids.pkl` |
| Size | ~148 MB |
| Format | joblib (pickle-based) |
| Algorithm | RandomForestClassifier |
| Trees | 300 |
| Accuracy | 85.91% |

### Model Metadata (`models/model_metadata.json`)

```json
{
  "model_name": "Random Forest IDS v1.0",
  "model_type": "RandomForestClassifier",
  "accuracy": 0.8591039693519208,
  "n_estimators": 300,
  "max_depth": null,
  "training_samples": 125973,
  "test_samples": 18794,
  "features": [ "duration", "protocol_type", "service", "flag",
                 "src_bytes", "dst_bytes", "logged_in", "count",
                 "srv_count", "serror_rate", "srv_serror_rate",
                 "dst_host_srv_count" ],
  "attack_types": [ "back", "buffer_overflow", "ftp_write",
                     "guess_passwd", "imap", "ipsweep", "land",
                     "loadmodule", "multihop", "neptune", "nmap",
                     "normal", "perl", "phf", "pod", "portsweep",
                     "rootkit", "satan", "smurf", "spy", "teardrop",
                     "warezclient", "warezmaster" ]
}
```

---

## 13. Configuration & Environment

### Environment Variables (`.env.example` → `backend/.env`)

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `0.0.0.0` | API listen address |
| `API_PORT` | `8000` | API port |
| `API_TITLE` | `"IDS-ML System API"` | API title |
| `API_VERSION` | `"1.0.0"` | API version |
| `CONFIDENCE_THRESHOLD` | `0.7` | Minimum confidence for severity alerts |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FILE` | `../logs/app.log` | Log file path |
| `CORS_ORIGINS` | `*` (in Config class) | Allowed origins |
| `DATABASE_URL` | `sqlite:///./ids_ml.db` | Future database URL |

### Config Class (`backend/config.py`)

- Uses `pathlib.Path` for cross-platform path resolution.
- Loads `.env` via `python-dotenv`.
- Provides class-level attributes for all paths and settings.

---

## 14. Startup & Shutdown

### One-Click Start

| Method | Command |
|---|---|
| Windows batch | Double-click `start.bat` |
| Python (cross-platform) | `python start.py` |
| Manual (2 terminals) | Terminal 1: `cd backend && python main.py` / Terminal 2: `cd frontend && python -m http.server 3000` |

**`start.py` flow:**

1. Locates the virtual environment's `python.exe` in `backend/.ids1.0_backend/Scripts/`.
2. Launches `backend/main.py` as a subprocess.
3. Waits 3 seconds for backend initialisation.
4. Launches `python -m http.server 3000` in `frontend/`.
5. Waits 2 seconds, then opens `http://localhost:3000` in the default browser.
6. Keeps running until `Ctrl+C`, then terminates both processes.

### Shutdown

| Method | Command |
|---|---|
| Windows batch | Double-click `stop.bat` |
| Python | `python stop.py` |
| Manual | `Ctrl+C` in the terminal running `start.py` |

`stop.py` uses `netstat` (Windows) or `lsof` (Linux/Mac) to find and kill processes on ports 8000 and 3000.

---

## 15. Testing & Verification

### API Health Check

```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","model_loaded":true}
```

### Prediction Test (Normal Traffic)

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"duration":0,"protocol_type":"tcp","service":"http","flag":"SF","src_bytes":181,"dst_bytes":5450,"logged_in":1,"count":8,"srv_count":8,"serror_rate":0.0,"srv_serror_rate":0.0,"dst_host_srv_count":9}'
```

### Automated Testing

```bash
# Run attack simulator (Mode 4 — all attack types)
python attack_simulator.py

# Run enhanced simulator (best for demonstrations)
python enhanced_attack_sim.py

# Run dashboard simulator (visual testing)
python dashboard_attack_sim.py
```

### Unit Tests

The project includes `pytest` and `httpx` in dependencies for testing, though the test files themselves are not present in the current release.

---

## 16. Documentation Suite

| Document | Path | Description |
|---|---|---|
| **README** | `README.md` | Full project overview, installation, usage, screenshots, contributing |
| **Project Report** | `PROJECT_REPORT.md` | Academic report (abstract, methodology, results, conclusion, references) |
| **Presentation Outline** | `PRESENTATION_OUTLINE.md` | 19-slide breakdown with speaker notes, demo steps, and expected Q&A |
| **Submission Checklist** | `FINAL_CHECKLIST.md` | Checkboxes for code, docs, screenshots, testing, deployment |
| **Quick Start** | `QUICKSTART.md` | 3-step startup guide |
| **API Docs** | `docs/API.md` | Full REST API reference with code examples |
| **Setup Guide** | `docs/Setup.md` | Installation, env config, troubleshooting, development workflow |
| **Model Report** | `docs/Model.md` | Detection rates by attack category, feature importance, limitations |
| **Project Specs** | `PROJECT_SPECS.md` | This document |
| **Auto Docs** | `http://localhost:8000/docs` | Live Swagger UI (auto-generated by FastAPI) |
| **Auto Docs** | `http://localhost:8000/redoc` | Live ReDoc (auto-generated by FastAPI) |
| **EDA Notebook** | `notebooks/01-eda.ipynb` | Exploratory data analysis of NSL-KDD dataset |

---

## 17. Performance Metrics

### Model Performance

| Metric | Score |
|---|---|
| **Accuracy** | 85.91% |
| **Precision** (weighted) | 86.24% |
| **Recall** (weighted) | 85.91% |
| **F1-Score** (weighted) | 85.88% |

### Detection Rates by Attack Category

| Category | Example Attacks | Detection Rate |
|---|---|---|
| **DoS** | Neptune, Smurf, Back | 96–100% |
| **Probe** | Satan, Nmap, IPSweep, PortSweep | 78–100% |
| **R2L** | guess_passwd, warezmaster | 0–2% |
| **U2R** | rootkit, buffer_overflow | ~0% |
| **Normal** | — | 97% (true negative) |

### System Performance

| Metric | Value |
|---|---|
| Average prediction latency | ~45 ms |
| Throughput | ~500 requests/second |
| Model load time | ~3 seconds |
| Model file size | ~148 MB |
| RAM usage (loaded model) | ~1 GB |

### System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| Python | 3.11+ | 3.11+ |
| RAM | 4 GB | 8 GB |
| Disk Space | 2 GB | 4 GB |
| CPU | 2 cores | 4+ cores |
| OS | Windows 10, Linux, macOS | Windows 10/11 |

---

## 18. Known Limitations

| Limitation | Impact | Root Cause |
|---|---|---|
| Poor R2L/U2R detection (0–2%) | Rare attacks may go undetected | Severe class imbalance (<100 samples for many R2L/U2R types vs. 14,000+ DoS) |
| No real-time packet capture | Must manually supply features | No Scapy/pyshark integration yet |
| In-memory stats only | Stats lost on restart | No database persistence |
| No authentication | API is open | v1.0 scope — no JWT/API keys |
| No rate limiting | Vulnerable to abuse | v1.0 scope |
| Single-node only | No horizontal scaling | No load balancing or message queue |
| Static frontend | No hot-reloading in dev | Served by `http.server` |
| Unseen categories | Unknown `service`/`flag` defaults to 0 | LabelEncoder fallback in `predict.py` |

---

## 19. Future Roadmap

### v2.0 (Planned)

- [ ] **Deep Learning** — LSTM/CNN models for improved accuracy on rare attacks
- [ ] **Real-Time Packet Capture** — Scapy/pyshark integration for live monitoring
- [ ] **Database Integration** — PostgreSQL for persistent logging and analytics
- [ ] **User Authentication** — JWT-based API security
- [ ] **Email/SMS Alerts** — Notification system for high-severity attacks
- [ ] **Dashboard Analytics** — Charts, graphs, and trend visualisations
- [ ] **Model Retraining** — Online learning pipeline
- [ ] **SMOTE/Oversampling** — Address class imbalance

### v3.0 (Long-term)

- [ ] **Multi-Model Ensemble** — Combine RF + XGBoost + Neural Networks
- [ ] **Docker Deployment** — Containerisation with `docker-compose`
- [ ] **Cloud Deployment** — AWS/Azure deployment guides
- [ ] **Mobile Application** — React Native or Flutter companion app
- [ ] **Distributed Architecture** — Message queues, load balancing

---

## 20. Author & Contact

| Field | Value |
|---|---|
| **Author** | V33R-5H4H (V33R5H4H) |
| **Email** | <veer3.shah@gmail.com> |
| **GitHub** | [github.com/V33R-5H4H](https://github.com/V33R-5H4H) |
| **Project** | [IDS-ML_1.0](https://github.com/V33R-5H4H/IDS-ML_1.0) |
| **Version** | 1.0.0 |
| **License** | MIT |
| **Academic Year** | 2025–2026 |

---

## References

1. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A detailed analysis of the KDD CUP 99 data set.* IEEE Symposium on Computational Intelligence for Security and Defense Applications.
2. Breiman, L. (2001). *Random forests.* Machine Learning, 45(1), 5–32.
3. NSL-KDD Dataset — University of New Brunswick. <https://www.unb.ca/cic/datasets/nsl.html>
4. FastAPI Documentation. <https://fastapi.tiangolo.com/>
5. scikit-learn Documentation. <https://scikit-learn.org/>
6. Pedregosa, F., et al. (2011). *Scikit-learn: Machine learning in Python.* JMLR, 12, 2825–2830.

---

> **Last Updated:** February 15, 2026
