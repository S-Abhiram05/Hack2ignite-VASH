# VASH System Design & Data Schema Specifications

> **System Title**: VASH Autonomous Transaction Control & Threat Intelligence Platform  
> **Authors**: Vineet · Abhiram · Sakshi · Himanshu  
> **Document Status**: Production System Design Document  

---

## 1. Design Goals & System Constraints

1. **Sub-Second End-to-End Latency**: Ingest, analyze, score, and commit/quarantine transactions in $\le 50\text{ms}$.
2. **Privacy-Preserving Architecture**: Zero exposure of raw Personally Identifiable Information (PII) across bank boundaries using blind HMAC hashing.
3. **High-Throughput Concurrent Processing**: Asynchronous API stream handling up to 10,000 transactions/second.
4. **Deterministic Graph Ring Detection**: Detect circular money laundering cycles in real time using $O(V + E)$ graph algorithms.
5. **Explainability & Auditability**: Every automated decision must provide XAI SHAP feature attributions and an immutable SHA-256 Merkle audit proof.

---

## 2. Data Schemas & Models

### 2.1 SQLite Database Schema (`fintech_threat_db.sqlite`)

```sql
-- Transaction Ledger Table
CREATE TABLE IF NOT EXISTS ledger (
    telemetry_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    auth_status TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    waf_alert_level TEXT NOT NULL,
    payment_rail TEXT NOT NULL,
    clearing_network TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    amount REAL NOT NULL,
    sender_token TEXT NOT NULL,
    receiver_token TEXT NOT NULL,
    risk_score REAL NOT NULL,
    anomaly_isolated INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for sub-second retrieval
CREATE INDEX IF NOT EXISTS idx_ledger_sender ON ledger(sender_token);
CREATE INDEX IF NOT EXISTS idx_ledger_receiver ON ledger(receiver_token);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger(timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_risk ON ledger(risk_score);

-- Institutional Users Table (RBAC)
CREATE TABLE IF NOT EXISTS institutional_users (
    user_id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 2.2 Neo4j Graph Model

```cypher
// Node Definition
(:Account {
    token: "0x3F8A...",          // Cryptographic tokenized hash
    institution: "BNK-HDFC",      // Originating bank node
    risk_status: "FLAGGED"        // Status: 'NORMAL' | 'SUSPECT' | 'FLAGGED'
})

// Relationship Definition
(:Account)-[:TRANSFERRED_TO {
    txn_id: "TXN_171800293",
    amount: 250000.00,
    timestamp: "2026-09-17T22:30:00Z",
    velocity_count: 12,
    is_flagged: 1
}]->(:Account)
```

### 2.3 Cryptographic SDK License Package Schema (`vash_sdk.json`)

```json
{
  "sdk_identifier": "VASH-PQC-SECURE-SDK-v2.0",
  "owner_vpa": "admin",
  "hardware_token_id": "hsm-slot-9a",
  "compliance_tier": "Tier-1 Audit",
  "license_signature": "3045022100a1b2c3d4e5f60708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202200deadbeef",
  "hw_entropy_checksum": "a8f39b1a0d3f221415b8e90708010214a1e909a8bf02419aee981bf09b02cd4a",
  "status": "VERIFIED_COMPLIANT",
  "creation_epoch": 1773789000000,
  "issuer": "VASH Security Operations Gate"
}
```

---

## 3. Subsystem Detailed Design

### 3.1 VASH FastAPI Ingestion Gateway (`main.py`)
The Ingestion Gateway exposes REST endpoints for incoming transaction payloads:

- **`POST /ingest_transaction`**:
  - Validates HMAC payload signature using `SECRET_KEY`.
  - Rejects replay attacks outside the 300-second window.
  - Logs payload to WORM file (`vash_audit_worm.log`).
  - Enqueues `tasks.process_edge.delay(payload)` for Celery worker consumption.

- **`GET /api/v1/analytics/dashboard`**:
  - Fetches transaction volume, isolated threat counts, and SHAP XAI attributions for the front-end SOC portal.

- **`POST /api/v1/auth/verify-sdk`**:
  - Validates uploaded hardware SDK licenses and PQC signature headers.

### 3.2 Machine Learning & Anomaly Scoring (`ml_engine.py`)
- **Isolation Forest Engine (`VASH_MLEngine`)**:
  - Features: $X = [\text{IP\_Anomaly\_Score}, \text{Auth\_Discrepancy}, \text{Amount\_Normalized}, \text{Velocity\_Count}]$.
  - Fits on background transaction streams and returns score $S \in [0, 1]$.
- **SHAP Value Explainer**:
  - Computes contribution weights for each feature vector to display in the Right Risk Panel.

### 3.3 Topological Graph Engine (`generate_threat_network.py`, `database.py`)
- **Neo4j Connection Pool (`Neo4jConnection`)**:
  - Executes Cypher queries over Bolt driver (`bolt://localhost:7687`).
- **Laundering Topology Injector**:
  - Seeds 5,000 baseline nodes and injects 3 precise fraud topologies:
    1. **Smurfing Hub**: 21 nodes funneling funds to a central hub.
    2. **Tarjan SCC Cycle**: 10-node circular money laundering ring.
    3. **Velocity Burst**: Single sender dispatching 15 rapid transfers in under 2 seconds.

### 3.4 Private Set Intersection (PSI) Engine (`psi_engine.py`)
- **Cross-Bank Matching**:
  - Bank A and Bank B execute an elliptic-curve Diffie-Hellman style key exchange over tokenized account IDs.
  - Calculates $H(VPA)^{a \cdot b}$ to find overlapping suspicious accounts without revealing non-flagged accounts.

### 3.5 Immutable WORM Audit Trail (`audit_logger.py`)
- **Write-Once-Read-Many Log Writer**:
  - Appends JSON records with SHA-256 hash chains (`prev_hash` $\rightarrow$ `curr_hash`).
  - Verifies tamper-free status during administrative audits.

---

## 4. Frontend State & Component Architecture (`frontend/src/`)

```
App (StoreProvider)
 ├── NavigationBar (Landing Page Navigation)
 ├── AnimatedRoutes
 │    ├── Home (VASH 3D Landing Page)
 │    ├── AboutUs (The Architects)
 │    ├── LoginGateway (Sarvakshan 3-Step MFA + SDK Upload)
 │    └── VashWorkspacePortal (Security Operations Center)
 │         ├── VashNavbar (System Indicators + Command Terminal)
 │         ├── EventQueueBanner (Real-Time Threat Feed Stream)
 │         ├── PaymentRailBrowser (UPI/NEFT/RTGS/SWIFT Selector)
 │         ├── TabWorkspace (10 Security Operations Tabs)
 │         │    ├── SystemGraphTab (Fused 3D Force Graph + Tarjan SCC)
 │         │    ├── AllAttacksTab
 │         │    ├── AuditIncidentTab (WORM Audit Logs + SAR Filing)
 │         │    ├── AuthMonitorTab
 │         │    ├── CryptoTab
 │         │    ├── DatabaseTab
 │         │    ├── MitreAttackTab (MITRE ATT&CK Matrix)
 │         │    ├── QuantumTab (Post-Quantum Cryptography)
 │         │    ├── SecurityMeshTab
 │         │    └── TelemetryTab
 │         ├── RightRiskPanel (Live Gauge + SHAP XAI Attributions)
 │         └── VashWorkspaceFooter
 └── VashFooter (Landing Page Footer)
```

---

## 5. Security & Access Control Matrix

| User Role | Sarvakshan MFA | PQC SDK File | Graph Access | Manual Unfreeze | WORM Log Verification |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Guest / Anonymous** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Analyst** | ✅ | ❌ | Read-Only | ❌ | Read-Only |
| **SOC Supervisor** | ✅ | ✅ | Full Access | ✅ | Read-Only |
| **System Admin** | ✅ | ✅ | Full Access | ✅ | Full Audit & Merkle Proof |

---

## 6. Real-Time Failure & Fault Tolerance Strategy

1. **Database Fallback**: If Neo4j connection fails, the system logs the incident into SQLite WAL ledger and queues the transaction for graph retry.
2. **Circuit Breaker Mechanism**: Manual or automatic circuit breaker trip halts processing on target payment rails during high-volume DDoS or replay attacks.
3. **Queue Overflow Buffer**: `ALERT_QUEUE` maintains a 5,000-item buffer using non-blocking eviction (`put_nowait`) to prevent backpressure drops under high load.
