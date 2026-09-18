# VASH: AI-Powered Real-Time Fraud Detection & Threat Control System

> **Problem Statement Alignment**: *"Design an AI-powered fraud detection system for identifying suspicious transactions in real time."*

---

## 🎯 Executive Summary & Problem Suitability Evaluation

### Is VASH Suitable for the Problem Statement?
**Yes, 100%. VASH is custom-engineered specifically to solve this problem statement at enterprise scale.**

Unlike traditional rule-based banking filters that rely on static thresholds or error-prone OCR heuristics, **VASH** combines **Machine Learning (Isolation Forest Anomaly Detection)**, **Graph-Network Intelligence (Tarjan's SCC Cycle Detection)**, **Post-Quantum Cryptography (PQC)**, and **Explainable AI (XAI SHAP)** to intercept, analyze, and quarantine suspicious transactions before capital is siphoned.

---

## 🏛️ System Architecture & Key Modules

```
                                +-----------------------------------+
                                |    Incoming Transaction Payload   |
                                +-----------------------------------+
                                                  |
                                                  v
                                +-----------------------------------+
                                |   VASH FastAPI Ingestion Gateway  |
                                +-----------------------------------+
                                                  |
                 +--------------------------------+--------------------------------+
                 |                                |                                |
                 v                                v                                v
  +-----------------------------+  +-----------------------------+  +-----------------------------+
  |    Isolation Forest ML      |  |     Tarjan SCC Graph Net    |  |     Sarvakshan PQC Gate     |
  |  (Anomaly Scoring + SHAP)   |  |   (Laundering Ring Detection) |  |   (HMAC & SDK Verification) |
  +-----------------------------+  +-----------------------------+  +-----------------------------+
                 |                                |                                |
                 +--------------------------------+--------------------------------+
                                                  |
                                                  v
                                +-----------------------------------+
                                |   VASH Security Operations Core   |
                                |  (3D Graph + 10 Security Tabs)    |
                                +-----------------------------------+
```

---

## 🔬 Core Capabilities

### 1. 🤖 AI-Powered Anomaly & Fraud Engine
- **Unsupervised Isolation Forest**: Trains on high-dimensional transaction features (source IP anomaly, amount variance, auth status, velocity burst score) to detect unknown/novel fraud topologies without requiring labeled historical fraud samples.
- **Explainable AI (XAI SHAP Attributions)**: Generates real-time feature attribution scores (e.g. `velocity_impact: 0.45`, `ip_anomaly: 0.30`) so SOC analysts understand exactly *why* a transaction was flagged.

### 2. 🕸️ Graph Network Laundering Detection
- **Tarjan's Strongly Connected Components (SCC)**: Detects circular money laundering cycles (e.g., Bank A $\rightarrow$ Bank B $\rightarrow$ Bank C $\rightarrow$ Bank A) in $O(V + E)$ linear time.
- **Smurfing Hub & Velocity Detection**: Intercepts fan-out smurfing hubs where a single compromised account distributes small amounts to hundreds of recipient accounts in micro-seconds.

### 3. 🔐 Sarvakshan Multi-Factor & SDK Package Security
- **Sarvakshan MFA Challenge**: 2-Step credential and 6-digit OTP verification.
- **VASH PQC SDK Package Validation**: Drag & drop JSON hardware license validation (`vash_sdk.json`), verifying PQC signatures and hardware entropy checksums before granting administrative access.

### 4. 📜 Immutable WORM Audit Trail
- **Cryptographic Merkle Linkage**: Logs all system events, quarantine actions, and analyst interventions into a Write-Once-Read-Many (WORM) audit ledger linked with SHA-256 hashes for zero tamperability.
- **Regulatory Compliance**: Generates automated Suspicious Activity Reports (SARs) compliant with **RBI**, **FinCEN**, **CERT-In**, and **FATF** standards.

---

## 👥 Core Creators (VASH)
- **V**ineet — *Database Architecture & Synthetic Transaction Generators*
- **A**bhiram — *Frontend Engineering & Glassmorphic UI/3D Visualizers*
- **S**akshi — *Motion Design & Interactive UI Workflows*
- **H**imanshu — *System Architecture & Graph Anomaly ML Engines*

---

## 🛠️ Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend UI** | React 18, TypeScript, Vite, Tailwind CSS, Framer Motion, Three.js, react-force-graph-3d |
| **Backend API** | FastAPI (Python 3.10+), SQLite (Relational), Neo4j (Graph Database) |
| **Async Processing** | Celery (Gevent Worker Pool), Redis Broker, Kafka Stream Consumer |
| **Machine Learning** | Scikit-Learn (Isolation Forest), NumPy, NetworkX, SHAP |
| **Cryptography** | HMAC-SHA256 Payload Integrity, AES-256-GCM Envelope Encryption, Dilithium3 PQC |

---

## 🚀 Presentation Pitch Checklist

- [x] **Real-Time Processing**: Sub-millisecond transaction ingestion via FastAPI + Celery.
- [x] **AI & ML Integration**: Isolation Forest anomaly scoring paired with SHAP explainability.
- [x] **Topological Graph Analysis**: 3D interactive galaxy visualizer highlighting smurfing hubs and Tarjan cycles.
- [x] **Zero-Trust Security**: Sarvakshan MFA + VASH SDK PQC license verification.
- [x] **Regulatory Compliance**: Immutable WORM logs and automated CERT-In SAR filing.
