# VASH Comprehensive Project Context & Master Reference

> **Project Name**: VASH — *Autonomous Real-Time Financial Graph Threat Intelligence & Transaction Control Engine*  
> **Repository**: [Hack2ignite-VASH](https://github.com/S-Abhiram05/Hack2ignite-VASH)  
> **Secondary Remote**: [VASH](https://github.com/himanshu-anonymous/VASH)  
> **Creators**: Vineet (Database Architecture) · Abhiram (Frontend & 3D UI) · Sakshi (Motion Design) · Himanshu (System Architecture & ML Engines)  
> **Document Purpose**: Master Technical Context, Complete Codebase Blueprint & Execution Guide  
> **Version**: 2.2 (Fully Hardened, Multi-Tenant Scoped & Vercel SPA Ready)

---

## 1. Project Background & Vision

**VASH** is an enterprise-scale, real-time transaction control and threat detection architecture designed for modern multi-bank financial ecosystems. It provides automated detection and disruption of sophisticated financial fraud topologies—including smurfing hubs, circular money laundering cycles, and velocity bursts—operating across high-volume payment rails (UPI, NEFT, RTGS, SWIFT, Visa, Mastercard).

### 1.1 Core System Capabilities
1. **Real-Time Payload Ingestion**: Sub-millisecond transaction ingestion via FastAPI with HMAC-SHA256 payload verification, UTC timestamp window (300s), and nonce deduplication (`SEEN_NONCES`).
2. **AI-Driven Anomaly Detection**: Unsupervised Isolation Forest model combined with SHAP (SHapley Additive exPlanations) for explainable AI risk attributions.
3. **Topological Graph Analysis**: Neo4j property graph database paired with Tarjan's $O(V+E)$ Strongly Connected Components (SCC) algorithm for detecting circular money laundering rings.
4. **Zero-Trust Administrative Gateway**: 3-stage authentication flow (Credentials $\rightarrow$ Server-side 6-digit MFA OTP Challenge `/api/auth/mfa-verify` $\rightarrow$ Hardware-signed PQC SDK license package verification).
5. **Private Set Intersection (PSI)**: Multi-party computation simulation using salted SHA-256 Web Crypto and Python engines (with explicit `hashlib` imports) to intersect suspect account sets across institutions without exposing non-matching identifiers.
6. **Immutable Cryptographic WORM Audit Log**: Tamper-evident append-only log ledger (`vash_audit_worm.log`) using canonical JSON serialization and SHA-256 Merkle-like hash chaining (`prev_hash` $\rightarrow$ `curr_hash`).
7. **3D Interactive Galaxy Topology SOC**: High-performance glassmorphic React 18 dashboard utilizing Three.js and `react-force-graph-3d` with 10 dedicated security operations tabs and dynamic risk attribution panels.
8. **Vercel Deployment & SPA Routing**: Production frontend configured with `vercel.json` SPA rewrites (`/ (.*) -> /index.html`) eliminating 404 errors on direct route access.

---

## 2. Complete Repository Sitemap & Codebase Architecture

```
d:\program01\satark\
├── .env                              # Environment variable configuration file
├── .gitignore                        # Git exclusion rules
├── ARCHITECTURE.md                   # Technical system architecture specification
├── CONTEXT.md                        # Master project context and complete technical blueprint
├── README.md                         # Project introduction and quick-start summary
├── RUN_GUIDE.md                      # Step-by-step setup and execution instructions
├── SYSTEMDESIGN.md                   # System design patterns and structural specifications
├── VASH-security-recheck-2026-10-02.md# Security recheck audit findings and remediation log
├── VASH_PROJECT_DOCUMENTATION.md    # Detailed project documentation and capabilities overview
├── audit_logger.py                   # Immutable WORM audit logger with SHA-256 hash chaining
├── audit.py                          # Independent WORM log verification utility
├── config.py                         # Centralized configuration and secure secret resolver
├── dashboard.py                      # Streamlit alternative monitoring portal
├── database.py                       # Neo4j graph database driver and connection pool
├── docker-compose.yml                # Docker infrastructure setup for Redis & Neo4j
├── fintech_threat_db.sqlite          # Relational database for accounts, transactions, institutions
├── fl_client.py                      # Federated Learning client simulation node
├── fl_server.py                      # Federated Learning aggregation server
├── generate_threat_network.py        # Enterprise dataset generator and graph seed script
├── how_to_run.txt                    # Execution cheat-sheet and credential reference
├── index.html                        # Root HTML entry template
├── inject_demo_anomaly.py            # Real-time multi-pattern fraud injection utility
├── main.py                           # FastAPI REST server, ingress gateway, and API routes
├── ml_engine.py                      # Isolation Forest model, SHAP XAI, and composite risk scoring
├── probe_server.py                   # Port-probe and liveness verification service
├── psi_engine.py                     # Private Set Intersection (PSI) cryptographic engine
├── requirements.txt                  # Python dependencies declaration
├── tasks.py                          # Celery async worker tasks & Redis velocity ledger
├── test_login.py                     # Integration test script for login authentication
├── vash_sdk.json                     # Standard administrative PQC SDK license file
├── vercel.json                       # Deployment configuration for Vercel with SPA rewrites
├── verify_psi.py                     # Verification script for PSI set intersection
└── frontend/                         # React 18 / Vite / TypeScript Frontend Application
    ├── eslint.config.js              # ESLint 9 configuration with custom rule overrides
    ├── index.html                    # Single Page Application HTML root
    ├── package.json                  # Frontend dependencies and npm script declarations
    ├── tsconfig.json                 # TypeScript compiler configuration
    ├── vite.config.ts                # Vite build bundler and plugin setup
    ├── public/                       # Static public assets and SDK license packages
    │   └── vash_sdk.json             # Public downloadable SDK license file
    └── src/                          # Source code for React frontend
        ├── App.tsx                   # Main router, navigation header, footer, and portal layout
        ├── index.css                 # Global Tailwind CSS styles and glassmorphism themes
        ├── main.tsx                  # React DOM rendering entry point
        ├── components/               # Reusable UI components & modals
        │   ├── BankOnboarding.tsx    # Institution onboarding workflow modal
        │   ├── Footer.tsx            # Global footer with trigger controls
        │   ├── LiveThreatFeed.tsx    # Real-time attack feed ticker
        │   ├── LoginGateway.tsx      # 3-Stage zero-trust authentication gateway
        │   ├── Navbar.tsx            # Glassmorphic top navigation bar with VASH branding
        │   ├── RiskBreakdown.tsx     # SHAP feature attribution breakdown gauge
        │   └── ui/                   # Shared UI primitives (spotlight cards, buttons)
        ├── pages/                    # Main application view pages
        │   ├── BankLogin.tsx         # Alternative institution login page
        │   ├── BankRegister.tsx      # Institution registration page
        │   ├── BankWorkspace.tsx     # Workspace selector portal
        │   ├── Dashboard.tsx         # Main 3D SOC Analyst Dashboard & Risk Panel
        │   ├── Home.tsx              # Landing homepage with threat metrics and exposure checker
        │   ├── Login.tsx             # Standalone login view
        │   └── PSIDashboard.tsx      # Private Set Intersection interactive demo tab
        ├── state/                    # Centralized React State Management
        │   └── StoreContext.tsx      # Master StoreProvider, useVashEngine hook, and mock data
        └── tabs/                     # 10 Security Operations Dashboard Tabs
            ├── AllAttacksTab.tsx     # Comprehensive threat matrix & attack feed
            ├── AuditIncidentTab.tsx  # Immutable WORM log viewer & CERT-In SAR filing
            ├── AuthMonitorTab.tsx    # Zero-trust auth logs & token status
            ├── CryptoTab.tsx         # HMAC signature inspector & AES envelope logs
            ├── DatabaseTab.tsx       # Multi-field database query builder & node search
            ├── MitreAttackTab.tsx    # MITRE ATT&CK framework matrix mapping
            ├── QuantumTab.tsx        # Post-Quantum Cryptography status & QKD coherence
            ├── SecurityMeshTab.tsx   # Security mesh node health & active quarantines
            ├── SystemGraphTab.tsx    # 3D network topology graph & node parameter metrics
            └── TelemetryTab.tsx      # Multi-channel payment stream browser (UPI, NEFT, SWIFT)
```

---

## 3. Detailed Component & Source Code Reference

### 3.1 Central Configuration (`config.py`)
- **Purpose**: Resolves global secrets and environment settings for both backend API (`main.py`) and background workers (`tasks.py`).
- **Key Logic**:
  - `SECRET_KEY`: Reads `os.environ.get("VASH_SECRET_KEY")`. If absent, generates a secure random 256-bit hex key (`secrets.token_hex(32)`).
  - `PSI_SALT`: Reads `os.environ.get("VASH_PSI_SALT")`. If absent, generates a secure random 256-bit hex salt (`secrets.token_hex(32)`).
  - `ALGORITHM`: Defaults to `HS256`.
  - `ACCESS_TOKEN_EXPIRE_MINUTES`: Defaults to `60`.
  - `ISSUER`: `vash.neural.core`.
  - `DB_NAME`: `fintech_threat_db.sqlite`.
  - `REDIS_HOST` & `REDIS_PORT`: Defaults to `localhost:6379`.

### 3.2 FastAPI Ingress Server (`main.py`)
- **Purpose**: REST API gateway handling authentication, payment transaction ingestion, tenant-scoped queries, and PSI set intersection.
- **Key Endpoints**:
  - `GET /`: Health check returning `{"status": "VASH API is live", "version": "1.3"}`.
  - `POST /api/auth/register`: Institution registration with password complexity enforcement (min 8 chars, 1 uppercase, 1 digit) and email format validation.
  - `POST /api/auth/login`: Institution login with bcrypt password verification, returning a pre-MFA JWT bearer token signed with `SECRET_KEY`.
  - `POST /api/auth/mfa-verify`: Server-side MFA challenge verification endpoint issuing the final MFA-verified JWT token (`mfa_verified: True`).
  - `GET /api/auth/me`: Authenticated endpoint returning current institution profile.
  - `POST /ingest_transaction`: Transaction ingestion endpoint verifying payload HMAC-SHA256, UTC timestamp window (300s), nonce uniqueness (`SEEN_NONCES`), and institution bank ID binding. Dispatches `tasks.process_edge.delay(payload)`.
  - `GET /transactions`: Retrieves recent transactions scoped strictly by the authenticated institution's `bank_id`.
  - `GET /accounts`: Retrieves account nodes scoped by `bank_id`.
  - `GET /api/threat-stats`: Returns tenant-scoped total accounts, transactions, blocked networks, and frozen suspicious capital.
  - `GET /api/graph`: Returns tenant-scoped flagged graph nodes and neighbor links (`WHERE neighbor.bank_id = $inst_id OR $inst_id IS NULL`).
  - `POST /api/psi/intersect`: Executes Private Set Intersection on provided ciphertexts and records WORM log.
  - `POST /api/atm/ingest`: Ingests physical ATM transaction telemetry (`terminal_id`, `card_token`, `entry_mode`, `atc`, `amount`, `institution_id`), evaluates skimming risk via `evaluate_atm_skimming_risk`, appends WORM audit log, updates Neo4j ATM terminal nodes, and returns ISO response code `'63'` (Security Violation) or `'00'` (Approved).

### 3.3 Background Task Worker (`tasks.py`)
- **Purpose**: Asynchronous worker running Celery tasks for feature extraction, velocity calculation, graph updates, and model scoring.
- **Key Logic**:
  - Worker setup: `Celery('vash_worker', broker=f'redis://{REDIS_HOST}:{REDIS_PORT}/0')`.
  - `verify_payload_hmac`: Verifies payload signature matching `SECRET_KEY` imported from `config`.
  - `tasks.process_edge`: Processes ingested transaction edges, updates Redis velocity counters, queries Neo4j for Tarjan SCC cycles, computes composite risk scores, and triggers automated micro-freezes if $R \ge 0.75$.
  - `publish_alert`: Writes threat alerts to `vash_alert_v1.2.json` and appends WORM audit logs.

### 3.4 Cryptographic WORM Audit Logger (`audit_logger.py`)
- **Purpose**: Implements Write-Once-Read-Many (WORM) compliant tamper-evident logging.
- **Key Logic**:
  - Reads previous entry's `curr_hash` from `vash_audit_worm.log` (or defaults to 64 zeros for genesis).
  - Serializes `payload_data` to canonical JSON and computes `payload_hash = sha256(...)`.
  - Computes `curr_hash = sha256(f"{timestamp}|{institution_id}|{event_type}|{payload_hash}|{prev_hash}")`.
  - Appends formatted log entry to `vash_audit_worm.log`, producing an unbroken Merkle hash chain.

### 3.5 Machine Learning & Explainable AI (`ml_engine.py`)
- **Purpose**: Calculates unsupervised anomaly scores and SHAP feature attributions.
- **Key Logic**:
  - `IsolationForest`: Scikit-learn model evaluated over transaction feature vectors $X = [\text{source\_ip\_anomaly}, \text{auth\_status\_val}, \text{amount}, \text{velocity}]$.
  - `composite_risk_score`: Combines Isolation Forest score, graph cycle presence, node betweenness, cross-bank transfers, velocity, and time anomalies into unified score $R \in [0.0, 1.0]$.
  - `explain_transaction_risk`: Returns explicit feature contribution breakdown (e.g. `velocity_impact: 0.45`, `ip_anomaly: 0.30`).

### 3.6 Private Set Intersection Engine (`psi_engine.py`)
- **Purpose**: Performs multi-party dataset intersection using salted SHA-256 token hashing.
- **Key Logic**:
  - `PSIEngine`: Uses explicit `import hashlib` to encrypt sets via `sha256((PSI_SALT + str(token)).encode('utf-8'))`.
  - `intersect`: Calculates `set(bank_a).intersection(set(bank_b))`, returning matching ciphertexts without revealing raw account numbers.

### 3.7 Database Connection Pool (`database.py`)
- **Purpose**: Neo4j driver wrapper handling Cypher query execution.
- **Key Logic**:
  - `Neo4jConnection`: Initializes driver for `bolt://localhost:7687` (configurable via `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`).
  - `query`: Executes parameterized Cypher queries with session management.

### 3.8 Dataset Generator & Seed Utility (`generate_threat_network.py`)
- **Purpose**: Seeds SQLite database (`fintech_threat_db.sqlite`) and resets/seeds Neo4j graph.
- **Key Logic**:
  - Creates tables: `institutions`, `banks`, `accounts`, `transactions`.
  - Seeds 5 institutions (`BNK-HDFC` as admin, `BNK-SBI` as supervisor, `BNK-ICICI`, `BNK-AXIS`, `BNK-KOTAK` as analysts) with bcrypt hashed password `password123`.
  - Generates 5,000 Zero-PII account tokens using HMAC-SHA256.
  - Injects precise fraud topologies: Smurfing Hubs, Tarjan SCC Rings, and Velocity Bursts.

### 3.9 Vercel Deployment Config (`vercel.json`)
- **Purpose**: Multi-environment build and SPA routing configuration for Vercel.
- **Key Logic**:
  - `buildCommand`: `cd frontend && npm install && npm run build`.
  - `outputDirectory`: `frontend/dist`.
  - `rewrites`: `[{"source": "/(.*)", "destination": "/index.html"}]` ensuring direct route access (`/login`, `/dashboard`) works seamlessly.

### 3.10 ATM Card Cloning & Skimming Engine (`ml_engine.py`, `main.py`)
- **Purpose**: Synchronous mid-transaction ATM card cloning and skimming interception via ISO 8583 gateway response standard.
- **Key Logic**:
  - `evaluate_atm_skimming_risk`: Evaluates POS/ATM entry mode `'90'` (magstripe fallback on chip account), Application Transaction Counter (ATC) regression ($ATC \le \text{historical\_atc}$), and withdrawal amount.
  - Response standard: Returns ISO response code `'63'` (Security Violation / Transaction Blocked) if risk score $R \ge 0.75$, halting cash dispense mid-stream; returns ISO code `'00'` (Approved) if $R < 0.75$.
  - Audit & Graph: Logs `ATM_SKIMMING_INTERCEPTED` to WORM audit log (`vash_audit_worm.log`) and upserts Neo4j physical ATM terminal nodes (`(:ATMTerminal)-[:DISPENSED_TO]->(:Account)`).

---

## 4. Frontend Architecture & State Management

### 4.1 Master Store Provider (`frontend/src/state/StoreContext.tsx`)
- **Purpose**: Central React Context provider managing system state, mock datasets, active role, and background simulation loops.
- **State Properties**:
  - `isAuthenticated`: Boolean tracking login state.
  - `role`: Current RBAC role (`"ADMIN"` or `"ANALYST"`).
  - `complianceTier`: Active compliance level (`"Tier-1 Audit"`, `"Tier-2 Supervisor"`, `"Standard Analyst"`).
  - `adminAccounts`: Map of registered administrative accounts, passwords, signatures, tiers, and roles.
  - `records`: List of live transaction records.
  - `auditLogs`: Immutable WORM audit trail log entries.
  - `incidents`: CERT-In filed incident reports.
  - `isPresentationMode`: Toggle for guided presentation walkthrough.

### 4.2 Zero-Trust Authentication Gateway (`frontend/src/components/LoginGateway.tsx`)
- **Purpose**: 3-Stage authentication modal enforcing administrative login controls.
- **3-Stage Workflow**:
  1. **Stage 1 — Credentials**: VPA ID and Password check against registered `adminAccounts` or backend API (`/api/auth/login`).
  2. **Stage 2 — MFA OTP**: 6-digit challenge code verification calling `/api/auth/mfa-verify`.
  3. **Stage 3 — SDK Package Upload**: Drag & drop JSON license verification (`vash_sdk.json`).
- **Security Controls**:
  - **Owner Matching**: Verifies `parsed.owner_vpa` matches authenticating user (`vpaId`). Rejects mismatched packages.
  - **Cryptographic Signature Matching**: Verifies `parsed.license_signature` or `parsed.signature` against registered account signature.
  - **RBAC Privilege Assignment**: Sets `user_role` to assigned account role (`ADMIN` vs `ANALYST`) from database record.

---

## 5. Algorithmic Formulations & Mathematics

### 5.1 Isolation Forest Anomaly Scoring
The Isolation Forest isolates anomalies by randomly selecting a feature and splitting value:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

### 5.2 Composite Risk Score Equation
$$R = 0.30 \cdot S_{\text{IF}} + 0.25 \cdot C_{\text{SCC}} + 0.15 \cdot B_{\text{Centrality}} + 0.15 \cdot X_{\text{CrossBank}} + 0.10 \cdot V_{\text{Velocity}} + 0.05 \cdot T_{\text{Time}}$$
Transactions with $R \ge 0.75$ trigger automatic micro-freezes.

### 5.3 Tarjan's Strongly Connected Components Algorithm
Tarjan's algorithm finds strongly connected components in a directed graph $G = (V, E)$ in $O(|V| + |E|)$ time complexity, identifying circular money laundering rings ($A \rightarrow B \rightarrow C \dots \rightarrow A$).

---

## 6. Execution & Operating Guide

### 6.1 Step-by-Step Execution Sequence

1. **Seed Enterprise Threat Database & Neo4j Graph**:
   ```bash
   python generate_threat_network.py
   ```

2. **Start Redis Server**:
   ```bash
   redis-server
   ```

3. **Launch Celery Background Neural Worker**:
   ```bash
   celery -A tasks worker --loglevel=info -P gevent
   ```

4. **Launch FastAPI Ingestion Server**:
   ```bash
   python main.py
   ```

5. **Launch React 3D SOC Dashboard**:
   ```bash
   cd frontend
   npm run dev
   ```

### 6.2 Default Access Credentials
- **Institution Admin ID**: `BNK-HDFC` | Password: `password123` | Role: `ADMIN`
- **Institution Supervisor ID**: `BNK-SBI` | Password: `password123` | Role: `ADMIN`
- **Institution Analyst ID**: `BNK-ICICI` | Password: `password123` | Role: `ANALYST`
- **Standard Admin**: `admin` | Password: `adminpassword` | Role: `ADMIN`
- **Standard SDK License File**: `vash_sdk.json`
