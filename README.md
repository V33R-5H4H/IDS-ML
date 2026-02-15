# 🛡️ IDS-ML: Intrusion Detection System using Machine Learning

**A comprehensive network intrusion detection system powered by Random Forest machine learning algorithm, achieving 85.91% accuracy on the NSL-KDD dataset.**

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green)
![scikit--learn](https://img.shields.io/badge/scikit--learn-1.5.2-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#%EF%B8%8F-system-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Model Performance](#-model-performance)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Technologies Used](#%EF%B8%8F-technologies-used)
- [Screenshots](#-screenshots)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

IDS-ML is an intelligent network intrusion detection system that uses machine learning to identify and classify network attacks in real-time. The system analyzes network traffic patterns and detects various types of attacks including DoS, Probe, R2L, and U2R attacks.

### Key Highlights

- **85.91% Detection Accuracy** on NSL-KDD test dataset
- **Real-time Prediction** via REST API
- **8+ Attack Types** detection capability
- **Interactive Dashboard** for monitoring
- **Automated Testing** with traffic simulator

---

## ✨ Features

### Core Functionality

- ✅ **Multi-Attack Detection**: Detects Neptune, Smurf, PortSweep, Satan, IPSweep, Back, Teardrop, PoD attacks
- ✅ **Real-time Analysis**: Instant prediction via RESTful API
- ✅ **Confidence Scoring**: Provides prediction confidence levels
- ✅ **Severity Classification**: Categorizes attacks as High/Medium/Low severity
- ✅ **Traffic Simulation**: Built-in attack simulator for testing

### Technical Features

- ✅ **Random Forest Classifier** with 300 estimators
- ✅ **Feature Engineering** using 12 critical network features
- ✅ **Data Preprocessing** with StandardScaler and LabelEncoder
- ✅ **REST API** with automatic OpenAPI documentation
- ✅ **CORS Enabled** for cross-origin requests
- ✅ **Responsive Web Dashboard** with real-time updates

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client Layer                         │
│  ┌──────────────────┐      ┌─────────────────────┐      │
│  │  Web Dashboard   │      │  Traffic Simulator  │      │
│  │  (HTML/CSS/JS)   │      │    (Python)         │      │
│  └────────┬─────────┘      └──────────┬──────────┘      │
└───────────┼────────────────────────────┼────────────────┘
            │                            │
            └────────────┬───────────────┘
                         │ HTTP/JSON
┌────────────────────────┼───────────────────────────────┐
│                   API Layer                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │         FastAPI Backend (main.py)                │  │
│  │  • /predict  • /health  • /stats  • /model/info  │  │
│  └───────────────────────┬──────────────────────────┘  │
└──────────────────────────┼─────────────────────────────┘
                           │
┌──────────────────────────┼─────────────────────────────┐
│                   ML Layer                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │         IDS Predictor (predict.py)               │  │
│  │  • Preprocessing  • Feature Encoding             │  │
│  │  • Scaling       • Prediction                    │  │
│  └───────────────────────┬──────────────────────────┘  │
└──────────────────────────┼─────────────────────────────┘
                           │
┌──────────────────────────┼─────────────────────────────┐
│                   Model Layer                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │    Random Forest Model (300 estimators)          │  │
│  │    Trained on NSL-KDD Dataset                    │  │
│  │    Accuracy: 85.91%                              │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager
- 4GB RAM minimum
- 2GB free disk space

### Step 1: Clone Repository

```bash
git clone https://github.com/V33R-5H4H/IDS-ML_1.0.git
cd IDS-ML_1.0
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv backend/.ids1.0_backend
backend\.ids1.0_backend\Scripts\activate

# Linux/Mac
python3 -m venv backend/.ids1.0_backend
source backend/.ids1.0_backend/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r backend/requirements.txt
```

### Step 4: Download NSL-KDD Dataset

Download the NSL-KDD dataset and place files in `data/raw/`:

- `KDDTrain+.txt`
- `KDDTest+.txt`

**Download from:** [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html)

### Step 5: Preprocess Data

```bash
python scripts/preprocess_data.py
```

### Step 6: Train Model

```bash
python scripts/train_model.py
```

---

## 💻 Usage

### Quick Start

**Windows:**

```bash
start.bat
```

**Linux/Mac:**

```bash
chmod +x start.sh
./start.sh
```

**Or use Python:**

```bash
python start.py
```

The system will:

1. Start backend API on <http://localhost:8000>
2. Start frontend server on <http://localhost:3000>
3. Automatically open dashboard in browser

---

### Manual Start

**Terminal 1 - Backend:**

```bash
cd backend
python main.py
```

**Terminal 2 - Frontend:**

```bash
cd frontend
python -m http.server 3000
```

Then open: <http://localhost:3000>

---

### Using the Dashboard

1. **Open** <http://localhost:3000>
2. **Fill in** network traffic features
3. **Click** "Analyze Traffic"
4. **View** prediction results with confidence and severity

---

### Using the API

**Make a prediction:**

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

**Response:**

```json
{
  "prediction": "normal",
  "confidence": 0.9234,
  "is_attack": false,
  "severity": "None",
  "version": "1.0.0"
}
```

---

### Traffic Simulator

Test the system with automated attack simulation:

```bash
python attack_simulator.py
```

**Choose from:**

1. Quick Demo (20 packets)
2. Continuous Simulation (60 seconds)
3. Heavy Attack Simulation (70% attacks)
4. Demonstrate All Attack Types
5. Custom Settings

---

## 📊 Model Performance

### Overall Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 85.91% |
| **Precision** | 86.24% |
| **Recall** | 85.91% |
| **F1-Score** | 85.88% |

### Attack Detection Rates

| Attack Type | Detection Rate | Avg Confidence |
|-------------|----------------|----------------|
| Neptune (DoS) | 98.7% | 97.3% |
| Smurf (DoS) | 96.4% | 95.1% |
| Satan (Probe) | 78.2% | 72.8% |
| PortSweep (Probe) | 81.5% | 75.6% |
| Normal Traffic | 89.3% | 88.7% |

### Features Used (12)

1. **duration** - Connection duration in seconds
2. **protocol_type** - Protocol used (TCP/UDP/ICMP)
3. **service** - Network service (HTTP/FTP/etc)
4. **flag** - Connection flag (SF/S0/REJ/etc)
5. **src_bytes** - Bytes sent from source
6. **dst_bytes** - Bytes sent to destination
7. **logged_in** - Login status (0/1)
8. **count** - Connections to same host
9. **srv_count** - Connections to same service
10. **serror_rate** - SYN error rate
11. **srv_serror_rate** - Service SYN error rate
12. **dst_host_srv_count** - Destination host service count

---

## 📚 API Documentation

### Endpoints

#### `GET /`

Root endpoint returning API information

#### `GET /health`

Health check endpoint

**Response:**

```json
{
  "status": "healthy",
  "model_loaded": true
}
```

#### `GET /model/info`

Get model information and features

**Response:**

```json
{
  "name": "Random Forest IDS v1.0",
  "accuracy": 0.8591,
  "version": "1.0.0",
  "features": ["duration", "protocol_type", ...]
}
```

#### `POST /predict`

Make prediction on network traffic

**Request Body:**

```json
{
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
}
```

#### `GET /stats`

Get system statistics

**Interactive Documentation:** <http://localhost:8000/docs>

---

## 📁 Project Structure

```
IDS-ML_1.0/
├── README.md                      # Project documentation
├── start.py                       # Auto-start script
├── start.bat                      # Windows startup
├── attack_simulator.py            # Traffic simulator
│
├── backend/                       # API Backend
│   ├── main.py                   # FastAPI application
│   ├── config.py                 # Configuration
│   └── requirements.txt          # Python dependencies
│
├── frontend/                      # Web Dashboard
│   ├── index.html                # Dashboard UI
│   ├── style.css                 # Styling
│   └── app.js                    # Frontend logic
│
├── data/                          # Datasets
│   ├── raw/                      # Original NSL-KDD
│   │   ├── KDDTrain+.txt
│   │   └── KDDTest+.txt
│   └── processed/                # Preprocessed data
│       ├── preprocessed_data.pkl
│       └── train_test_data.npz
│
├── models/                        # ML Models
│   ├── random_forest_ids.pkl     # Trained model
│   └── model_metadata.json       # Model info
│
├── scripts/                       # Python Scripts
│   ├── preprocess_data.py        # Data preprocessing
│   ├── train_model.py            # Model training
│   └── predict.py                # Prediction logic
│
├── docs/                          # Documentation
│   ├── API.md                    # API documentation
│   ├── Setup.md                  # Setup guide
│   └── Model.md                  # Model details
│
├── notebooks/                     # Jupyter Notebooks
│   └── 01-eda.ipynb              # Exploratory analysis
│
└── logs/                          # Application logs
    └── .gitkeep
```

---

## 🛠️ Technologies Used

### Backend

- **FastAPI** - Modern web framework for APIs
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation

### Machine Learning

- **scikit-learn** - ML algorithms and preprocessing
- **pandas** - Data manipulation
- **numpy** - Numerical computing
- **joblib** - Model serialization

### Frontend

- **HTML5/CSS3** - Structure and styling
- **JavaScript (ES6+)** - Frontend logic
- **Bootstrap 5** - UI framework
- **Fetch API** - HTTP requests

### Development

- **Python 3.11** - Programming language
- **Git** - Version control
- **VSCode** - IDE

---

## 📸 Screenshots

> **Note:** Screenshots are generated during testing. To capture your own, start the system (`python start.py`) and take screenshots of the dashboard, attack detection results, and the API docs page at `http://localhost:8000/docs`.

### Dashboard

<!-- ![Dashboard](docs/screenshots/dashboard.png) -->
*Start the system and open `http://localhost:3000` to see the live dashboard.*

### Normal Traffic Detection

<!-- ![Normal](docs/screenshots/normal_detection.png) -->
*Submit normal HTTP traffic features using the form to see a green "NORMAL TRAFFIC" result.*

### Attack Detection

<!-- ![Attack](docs/screenshots/attack_detection.png) -->
*Submit Neptune DoS attack features to see a red "ATTACK DETECTED" result with severity.*

### API Documentation

<!-- ![API Docs](docs/screenshots/api_docs.png) -->
*Open `http://localhost:8000/docs` for the interactive Swagger UI.*

---

## 🔮 Future Enhancements

### v2.0 Planned Features

- [ ] **Deep Learning Models** - LSTM/CNN for improved accuracy
- [ ] **Real-time Packet Capture** - Live network monitoring
- [ ] **Database Integration** - PostgreSQL for logging
- [ ] **User Authentication** - JWT-based security
- [ ] **Email Alerts** - Notification system for attacks
- [ ] **Dashboard Analytics** - Charts and visualizations
- [ ] **Model Retraining** - Online learning capabilities
- [ ] **Multi-model Ensemble** - Combine multiple algorithms
- [ ] **Docker Deployment** - Containerization
- [ ] **Cloud Deployment** - AWS/Azure deployment guides

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

- **V33R-5H4H** - *Initial work* - [https://github.com/V33R-5H4H](https://github.com/V33R-5H4H)

---

## 🙏 Acknowledgments

- **NSL-KDD Dataset** - University of New Brunswick
- **FastAPI** - Sebastián Ramírez
- **scikit-learn** - scikit-learn developers
- **Bootstrap** - Twitter team

---

## 📞 Contact

**V33R-5H4H** - <veer3.shah@gmail.com>

**Project Link:** [https://github.com/V33R-5H4H/IDS-ML_1.0](https://github.com/V33R-5H4H/IDS-ML_1.0)

---

## 📖 References

1. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). "A detailed analysis of the KDD CUP 99 data set." *IEEE Symposium on Computational Intelligence for Security and Defense Applications.*
2. Breiman, L. (2001). "Random Forests." *Machine Learning, 45*(1), 5–32.
3. NSL-KDD Dataset — University of New Brunswick: [https://www.unb.ca/cic/datasets/nsl.html](https://www.unb.ca/cic/datasets/nsl.html)

---

**⭐ If you find this project useful, please consider giving it a star!**
