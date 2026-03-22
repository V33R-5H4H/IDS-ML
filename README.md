# 🛡️ IDS-ML v2.0
**Intrusion Detection System powered by Machine Learning**

An enterprise-grade, containerized Network Intrusion Detection System (IDS) that leverages advanced deep learning (CNN/LSTM) and multimodal ensemble models (XGBoost, LightGBM, Random Forest) to intercept and classify network threats in real-time.

![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)

---

## ✨ Features

- **🚀 Live Packet Interception**: Real-time traffic sniffing and deep packet inspection using `Scapy`.
- **🧠 Multimodal AI Ensemble**: Stacking and Soft-Voting ensembles combining CNNs, LSTMs, LightGBM, and XGBoost to achieve **95%+ accuracy** on Zero-Day threats.
- **📁 PCAP File Forensics**: Upload and actively analyze historical `.pcap` and `.pcapng` network captures.
- **🔐 Role-Based Access Control**: Secure JWT Authentication separating privileges across `Admin`, `Analyst`, and `Viewer` accounts.
- **☁️ Cloud Database Architecture**: Primary integration with **Supabase PostgreSQL**, falling back seamlessly to local SQLite if offline.
- **📦 100% Containerized**: The entire Full-Stack platform is containerized using Docker & Nginx for one-click universal deployments.

---

## 🏗️ Architecture

The application is fully decoupled and containerized:

1. **Frontend (`ids-ml-frontend`)**: A lightning-fast, Vanilla JS and Bootstrap 5 dashboard hosted natively inside an Alpine Nginx container on Port `3000`.
2. **Backend Engine (`ids-ml-backend`)**: A highly concurrent FastAPI Python server handling AI inference, PCAP parsing, and JWT authorization on Port `9001`.
3. **Database Layer**: Remote PostgreSQL (Supabase) integration with asynchronous mirror syncing to a local persistent SQLite volume.

---

## 🚀 Quick Start (Docker)

You can launch the entire ML environment, frontend dashboard, and backend database connection anywhere in the world using Docker.

### 1. Requirements
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### 2. Launching the System
Clone the repository and run the setup command:

```bash
git clone https://github.com/V33R-5H4H/IDS-ML.git
cd IDS-ML
docker compose up --build -d
```

### 3. Accessing the Dashboard
Once Docker outputs `Started`, open your browser:
* **Frontend UI:** [http://localhost:3000](http://localhost:3000)
* **Backend API Documentation:** [http://localhost:9001/docs](http://localhost:9001/docs)

**Default Admin Credentials:**
* **Username:** `admin`
* **Password:** `admin123`

---

## 🛠️ Tech Stack

* **Machine Learning:** `TensorFlow`, `Keras`, `XGBoost`, `LightGBM`, `Scikit-Learn`, `Pandas`
* **Network Analysis:** `Scapy`, `tshark`, `libpcap`
* **Backend API:** `FastAPI`, `Uvicorn`, `SQLAlchemy`, `Passlib`, `PyJWT`
* **Frontend:** HTML5, Alpine `Nginx`, `Bootstrap 5`, `Chart.js`
* **DevOps:** `Docker`, `Docker Compose`

---

**Author:** [V33R-5H4H](https://github.com/V33R-5H4H)