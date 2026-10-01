# VASH Comprehensive Project Context & Master Reference

> **Project Name**: VASH — *Adaptive Variable-Resolution 2.5D LiDAR & Financial Graph Threat Intelligence Engine*  
> **Repository**: [Hack2ignite-VASH](https://github.com/S-Abhiram05/Hack2ignite-VASH)  
> **Secondary Remote**: [VASH](https://github.com/himanshu-anonymous/VASH)  
> **Creators**: Vineet (Database Architecture) · Abhiram (Frontend & 3D UI) · Sakshi (Motion Design) · Himanshu (System Architecture & ML Engines)  
> **Document Purpose**: Master Technical Context, Complete Codebase Blueprint & Execution Guide

---

## 1. Project Background & Vision

**VASH** is an enterprise-scale, real-time transaction control and threat detection architecture designed for modern multi-bank financial ecosystems. It provides automated detection and disruption of sophisticated financial fraud topologies—including smurfing hubs, circular money laundering cycles, and velocity bursts—operating across high-volume payment rails (UPI, NEFT, RTGS, SWIFT, Visa, Mastercard).

### 1.1 Core System Capabilities
1. **Real-Time Payload Ingestion**: Sub-millisecond transaction ingestion via FastAPI with HMAC-SHA256 payload verification and 300-second replay attack protection.
2. **AI-Driven Anomaly Detection**: Unsupervised Isolation Forest model combined with SHAP (SHapley Additive exPlanations) for explainable AI risk attributions.
3. **Topological Graph Analysis**: Neo4j property graph database paired with Tarjan's $O(V+E)$ Strongly Connected Components (SCC) algorithm for detecting circular money laundering rings.
4. **Zero-Trust Administrative Gateway**: 3-stage authentication flow (Credentials $\rightarrow$ 6-digit MFA OTP challenge $\rightarrow$ Hardware-signed PQC SDK license package verification).
5. **Private Set Intersection (PSI)**: Multi-party computation simulation using salted SHA-256 Web Crypto and Python engines to intersect suspect account sets across institutions without exposing non-matching identifiers.
6. **Immutable Cryptographic WORM Audit Log**: Tamper-evident append-only log ledger (`vash_audit_worm.log`) using canonical JSON serialization and SHA-256 Merkle-like hash chaining (`prev_hash` $\rightarrow$ `curr_hash`).
7. **3D Interactive Galaxy Topology SOC**: High-performance glassmorphic React 18 dashboard utilizing Three.js and `react-force-graph-3d` with 10 dedicated security operations tabs and dynamic risk attribution panels.

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
├── vercel.json                       # Deployment configuration for Vercel
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
- **Purpose**: Resolves all global secrets and environment settings for both backend API (`main.py`) and background workers (`tasks.py`).
- **Key Logic**:
  - `SECRET_KEY`: Reads `os.environ.get("VASH_SECRET_KEY")`. If absent, generates a secure random 256-bit hex key (`secrets.token_hex(32)`).
  - `PSI_SALT`: Reads `os.environ.get("VASH_PSI_SALT")`. If absent, generates a secure random 256-bit hex salt (`secrets.token_hex(32)`).
  - `ALGORITHM`: Defaults to `HS256`.
  - `ACCESS_TOKEN_EXPIRE_MINUTES`: Defaults to `60`.
  - `ISSUER`: `vash.neural.core`.
  - `DB_NAME`: `fintech_threat_db.sqlite`.
  - `REDIS_HOST` & `REDIS_PORT`: Defaults to `localhost:6379`.

### 3.2 FastAPI Ingress Server (`main.py`)
- **Purpose**: Main REST API gateway handling authentication, payment transaction ingestion, tenant-scoped queries, and PSI set intersection.
- **Key Endpoints**:
  - `GET /`: Health check returning `{"status": "VASH API is live", "version": "1.3"}`.
  - `POST /api/auth/register`: Institution registration with password complexity enforcement (min 8 chars, 1 uppercase, 1 digit) and email validation.
  - `POST /api/auth/login`: Institution login with bcrypt password verification, returning a JWT bearer token signed with `SECRET_KEY`.
  - `GET /api/auth/me`: Authenticated endpoint returning current institution profile.
  - `POST /ingest_transaction`: Transaction ingestion endpoint verifying payload HMAC-SHA256, UTC timestamp window (300s), and nonce uniqueness (`SEEN_NONCES`). Dispatches `tasks.process_edge.delay(payload)`.
  - `GET /transactions`: Retrieves recent transactions scoped strictly by the authenticated institution's `bank_id`.
  - `GET /accounts`: Retrieves account nodes scoped by `bank_id`.
  - `GET /api/threat-stats`: Returns tenant-scoped total accounts, transactions, blocked networks, and frozen suspicious capital.
  - `GET /api/graph`: Returns tenant-scoped flagged graph nodes and links for 3D rendering.
  - `POST /api/psi/intersect`: Executes Private Set Intersection on provided ciphertexts and records WORM log.

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
  - `IsolationForest`: Scikit-learn model evaluated over transaction feature vectors $X = [\text{IP\_Val}, \text{Auth\_Val}, \text{Amount}, \text{Velocity}]$.
  - `composite_risk_score`: Combines Isolation Forest score, graph cycle presence, node betweenness, cross-bank transfers, velocity, and time anomalies into unified score $R \in [0.0, 1.0]$.
  - `explain_transaction_risk`: Returns explicit feature contribution breakdown (e.g. `velocity_impact: 0.45`, `ip_anomaly: 0.30`).

### 3.6 Private Set Intersection Engine (`psi_engine.py`)
- **Purpose**: Performs multi-party dataset intersection using salted SHA-256 token hashing.
- **Key Logic**:
  - `PSIEngine`: Encrypts sets using `sha256((PSI_SALT + str(token)).encode())`.
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

### 3.9 Dynamic Fraud Injector (`inject_demo_anomaly.py`)
- **Purpose**: Programmatically injects multi-pattern fraud topology scenarios into running system for live demonstration.
- **Injected Scenarios**:
  - **Smurfing Hub**: 21 nodes funneling micro-amounts into an aggregator account.
  - **Tarjan SCC Cycle**: 10-node circular money laundering ring ($A \rightarrow B \rightarrow C \dots \rightarrow A$).
  - **Velocity Burst**: Single sender dispatching 15 rapid transactions within milliseconds.

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
  - `presentationStep`: Current step in presentation mode (1 through 6).

### 4.2 Zero-Trust Authentication Gateway (`frontend/src/components/LoginGateway.tsx`)
- **Purpose**: 3-Stage authentication modal enforcing administrative login controls.
- **3-Stage Workflow**:
  1. **Stage 1 — Credentials**: VPA ID and Password check against registered `adminAccounts` or backend API (`/api/auth/login`).
  2. **Stage 2 — MFA OTP**: 6-digit challenge code verification with audit log entry.
  3. **Stage 3 — SDK Package Upload**: Drag & drop JSON license verification (`vash_sdk.json`).
- **Security Controls**:
  - **Owner Matching**: Verifies `parsed.owner_vpa` matches authenticating user (`vpaId`). Rejects mismatched packages.
  - **Cryptographic Signature Matching**: Verifies `parsed.license_signature` or `parsed.signature` against registered account signature.
  - **RBAC Privilege Assignment**: Sets `user_role` to assigned account role (`ADMIN` vs `ANALYST`) from database record.

### 4.3 3D SOC Analyst Dashboard (`frontend/src/pages/Dashboard.tsx`)
- **Purpose**: Primary security operations workspace.
- **Key Features**:
  - **3D Interactive Galaxy Topology**: Rendered using Three.js and `react-force-graph-3d`, displaying nodes colored by risk status (Red = FLAGGED, Orange = ELEVATED, Cyan = CLEAN).
  - **Dynamic SHAP Risk Panel**: Right-side panel showing transaction risk gauge, SHAP feature attribution bars, node metadata, and manual quarantine/unfreeze controls.
  - **Tab Navigator**: Switches between 10 specialized Security Operations tabs.

### 4.4 10 Security Operations Tabs (`frontend/src/tabs/`)
1. **`SystemGraphTab`**: 3D network topology visualization, gravitational controls, and graph density metrics.
2. **`AllAttacksTab`**: Comprehensive attack matrix, real-time threat feed, and risk-ranked account list.
3. **`AuditIncidentTab`**: Cryptographic WORM audit trail inspector with SHA-256 hash chain verification & CERT-In SAR dispatcher.
4. **`AuthMonitorTab`**: Zero-trust authentication logs, active token status, and MFA challenge history.
5. **`CryptoTab`**: HMAC signature inspector, AES-256 envelope status, and key rotation metrics.
6. **`DatabaseTab`**: Multi-field SQL/Graph search builder for exploring accounts and transaction records.
7. **`MitreAttackTab`**: Interactive mapping of detected fraud techniques to MITRE ATT&CK framework tactics.
8. **`QuantumTab`**: Post-Quantum Cryptography status, Dilithium3 signature checks, and QKD coherence metrics.
9. **`SecurityMeshTab`**: Node health monitors, active quarantine controls, and circuit breaker status.
10. **`TelemetryTab`**: Multi-channel payment stream browser for UPI, NEFT, RTGS, Visa, Mastercard, and SWIFT.

---

## 5. Algorithmic Formulations & Mathematics

### 5.1 Isolation Forest Anomaly Scoring
The Isolation Forest isolates anomalies by randomly selecting a feature and splitting value. The anomaly score $s(x, n)$ for an instance $x$ given dataset size $n$ is defined as:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
Where:
- $h(x)$ is the path length of instance $x$ in an isolation tree.
- $E(h(x))$ is the average path length across a collection of isolation trees.
- $c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in a Binary Search Tree.

### 5.2 Composite Risk Score Equation
The unified transaction risk score $R$ is calculated as:
$$R = w_1 \cdot S_{\text{IF}} + w_2 \cdot C_{\text{SCC}} + w_3 \cdot B_{\text{Centrality}} + w_4 \cdot X_{\text{CrossBank}} + w_5 \cdot V_{\text{Velocity}} + w_6 \cdot T_{\text{Time}}$$
Where weights are calibrated to:
- $w_1 = 0.30$ (Isolation Forest Anomaly Score)
- $w_2 = 0.25$ (Tarjan SCC Cycle Detection Flag: $1$ if in cycle, $0$ otherwise)
- $w_3 = 0.15$ (Node Betweenness Centrality)
- $w_4 = 0.15$ (Cross-Bank Transfer Anomaly Flag)
- $w_5 = 0.10$ (Redis Velocity Counter / Threshold Ratio)
- $w_6 = 0.05$ (Off-Hours Time Anomaly Flag)

If $R \ge 0.75$, the system flags the transaction as high risk and initiates automated micro-freezes.

### 5.3 Tarjan's Strongly Connected Components Algorithm
Tarjan's algorithm finds strongly connected components in a directed graph $G = (V, E)$ in $O(|V| + |E|)$ time:
1. Performs a Depth-First Search (DFS), assigning each node $v$ an index `dfn[v]` and low-link value `low[v]`.
2. Maintains a stack of visited nodes.
3. When `low[v] == dfn[v]`, node $v$ is the root of a strongly connected component, and all nodes above $v$ on the stack are popped to form the SCC cycle.

---

## 6. Regulatory & Compliance Framework Alignment

| Regulation / Standard | Authority | VASH Architectural Implementation |
| :--- | :--- | :--- |
| **DPDP Act 2023** | Govt of India | Zero-PII HMAC tokenization masking raw account numbers and primary keys. |
| **RBI AML/CFT Guidelines** | Reserve Bank of India | Sub-second velocity burst interception & automatic Suspicious Activity Report (SAR) filing. |
| **CERT-In Cyber Rules** | Ministry of Electronics & IT | Immutable WORM audit logging (`vash_audit_worm.log`) with mandatory 6-hour incident reporting payload generation. |
| **FinCEN Anti-Money Laundering** | US Treasury | Tarjan SCC graph ring detection pinpointing multi-hop circular laundering hubs. |
| **FATF Recommendation 16** | Financial Action Task Force | Cross-border and cross-bank Private Set Intersection (PSI) for collaborative threat intelligence sharing. |

---

## 7. Execution & Operating Guide

### 7.1 Prerequisites
- **Python**: 3.10+ with `pip`
- **Node.js**: 18+ with `npm`
- **Neo4j Desktop / Server**: Running on `bolt://localhost:7687` (Credentials: `neo4j` / `password`)
- **Redis Server**: Running on `localhost:6379`

### 7.2 Step-by-Step Execution Sequence

1. **Seed Enterprise Threat Database & Neo4j Graph**:
   ```bash
   python generate_threat_network.py
   ```

2. **Start Redis Server**:
   ```bash
   redis-server
   # OR via Docker:
   docker run -d -p 6379:6379 redis
   ```

3. **Launch Celery Background Neural Worker**:
   ```bash
   celery -A tasks worker --loglevel=info -P gevent
   ```

4. **Launch FastAPI Ingestion Server**:
   ```bash
   python main.py
   # API will be active at http://localhost:8000
   ```

5. **Launch React 3D SOC Dashboard**:
   ```bash
   cd frontend
   npm run dev
   # Dashboard will be active at http://localhost:5173
   ```

6. **Inject Real-Time Multi-Pattern Fraud (Optional)**:
   ```bash
   python inject_demo_anomaly.py
   ```

### 7.3 Default Access Credentials
- **Institution Admin ID**: `BNK-HDFC` | Password: `password123` | Role: `ADMIN`
- **Institution Supervisor ID**: `BNK-SBI` | Password: `password123` | Role: `ADMIN`
- **Institution Analyst ID**: `BNK-ICICI` | Password: `password123` | Role: `ANALYST`
- **Standard Admin**: `admin` | Password: `adminpassword` | Role: `ADMIN`
- **Standard SDK License File**: `vash_sdk.json` (located in root and `frontend/public/`)
