import React, { createContext, useContext, useState, useEffect, useRef } from "react";

export type FlagType =
  | "HMAC_SIGNATURE_MISMATCH"
  | "PII_TOKEN_LEAK_RISK"
  | "MITRE_TACTIC_SPIKE"
  | "AES_ENVELOPE_CORRUPT"
  | "QUANTUM_REPLAY_ATTACK"
  | "DB_ACID_ROLLBACK_VIOLATION"
  | "UNAUTHORIZED_ZERO_TRUST_AUTH"
  | "VELOCITY_SPIKE"
  | "MULE_NODE_AGGREGATION"
  | "NORMAL";

export interface AuthDetails {
  tokenStatus: "VALID" | "REVOKED" | "EXPIRED" | "TAMPERED";
  mfaChallenge: "PASSED" | "FAILED" | "BYPASSED";
  zeroTrustScore: number;
  authDecision: "ALLOW" | "QUARANTINE" | "BLOCK";
}

export interface DbStatus {
  acidTxId: string;
  tableState: "COMMITTED" | "ISOLATED_QUARANTINE" | "PENDING_ROLLBACK" | "MUTATION_BLOCKED";
  rollbackTriggered: boolean;
  latencyMs: number;
}

export interface CryptoLogs {
  piiTokenizer: {
    rawPiiSample: string;
    blindHmacIndex: string;
    aesEncryptedToken: string;
    status: "SECURE" | "LEAK_RISK";
  };
  hmacSigner: {
    receivedSig: string;
    calculatedSig: string;
    algorithm: string;
    isValid: boolean;
  };
  aesEnvelope: {
    kekId: string;
    iv: string;
    tag: string;
    envelopeStatus: "VERIFIED" | "CORRUPTED";
  };
}

export interface TxRecord {
  id: string;
  timestamp: string;
  rail: string;
  network: string;
  amount: number;
  risk: number;
  escrow: "CLEAR" | "PENDING" | "ISOLATED" | "RATE_LIMITED" | "AUTO_FROZEN" | "MULE_SUSPENDED";
  vpa: string;
  ip: string;
  velocity: number;
  flagged: boolean;
  flagReason?: string;
  flagType: FlagType;
  mitreTactics: string[];
  authDetails: AuthDetails;
  dbStatus: DbStatus;
  cryptoLogs: CryptoLogs;
  auditId: string;
  wormMerkleProof: string;
  manualAuditStatus: "PENDING" | "QUARANTINED" | "SESSION_REVOKED" | "SAR_FILED" | "ROLLED_BACK" | "OVERRIDDEN";
  manualAuditActionLog: string[];
  shap: {
    ip_anomaly: number;
    auth_discrepancy: number;
    velocity_impact: number;
    quantum_channel_instability: number;
    entropy_drain: number;
    pqc_decryption_anomalies: number;
  };
}

export interface EventQueueItem {
  id: string;
  timestamp: string;
  eventType: string;
  source: string;
  targetVpa: string;
  status: "QUEUED" | "PROCESSING" | "CRYPTO_VERIFIED" | "AUDIT_LOGGED" | "REPORTED";
  severity: "LOW" | "HIGH" | "CRITICAL";
  txId?: string;
  details: string;
}

export interface AuditLog {
  timestamp: string;
  role: "ANALYST" | "ADMIN";
  action: string;
  status: "SUCCESS" | "DENIED" | "BLOCKED" | "AUTO_FREEZE" | "CRITICAL";
  prevHash: string;
  currHash: string;
  txId?: string;
}

export interface CertInIncident {
  id: string;
  vpa: string;
  rail: string;
  amount: number;
  detectionTime: string;
  slaDeadline: string;
  severity: "LOW" | "HIGH" | "CRITICAL";
  source: string;
  status: string;
  channel: "INTERNAL_SOC" | "EXTERNAL_REGULATORY" | "DUAL_DISPATCH";
}

const RAILS = ["UPI", "NEFT", "RTGS", "Visa", "Mastercard", "PayPal"];
const DOMESTIC_NETS = ["NPCI", "RBI-RTGS"];
const CROSS_NETS = ["VISA-NET", "MCTR-NET", "SWIFT-CROSS"];

export async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

export function checkAdminPassword(password: string): boolean {
  return password === "adminpassword";
}

export function useSugrivaEngine() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [complianceTier, setComplianceTier] = useState<string>(() => localStorage.getItem("vash_user_tier") || "Tier-1 Audit");
  const [adminAccounts, setAdminAccounts] = useState<Record<string, { password: string; signature: string; complianceTier?: string }>>({
    "admin": { password: "adminpassword", signature: "VASH-PQC-SECURE-SDK-v2.0", complianceTier: "Tier-1 Audit" }
  });

  const registerAdminAccount = (vpa: string, pass: string, sig: string, tier: string = "Tier-1 Audit") => {
    setAdminAccounts(prev => ({
      ...prev,
      [vpa]: { password: pass, signature: sig, complianceTier: tier }
    }));
  };

  const [records, setRecords] = useState<TxRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [incidents, setIncidents] = useState<CertInIncident[]>([]);
  const [eventQueue, setEventQueue] = useState<EventQueueItem[]>([]);

  const [isPresentationMode, setIsPresentationMode] = useState<boolean>(false);
  const [presentationStep, setPresentationStep] = useState<number>(1);
  const [selectedDemoTxId, setSelectedDemoTxId] = useState<string | null>(null);

  const [role, setRole] = useState<"ANALYST" | "ADMIN">("ANALYST");
  const [threshold, setThreshold] = useState<number>(0.75);
  const [circuitBreaker, setCircuitBreaker] = useState<"CLOSED" | "OPEN">("CLOSED");

  const [qkdCoherence, setQkdCoherence] = useState<number>(99.4);
  const [trngEntropy, setTrngEntropy] = useState<number>(100.0);
  const [pqcFailures, setPqcFailures] = useState<number>(0);

  const lastAuditHash = useRef<string>("0".repeat(64));

  const writeAudit = async (action: string, status: AuditLog["status"] = "SUCCESS", txId?: string) => {
    const ts = new Date().toISOString().replace("T", " ").substring(0, 23);
    const rawPayload = `${ts} | ROLE:${role} | ACTION:${action} | STATUS:${status} | TX:${txId || "GLOBAL"} | prev:${lastAuditHash.current}`;
    const currHash = await sha256(rawPayload);

    const entry: AuditLog = {
      timestamp: ts,
      role,
      action,
      status,
      prevHash: lastAuditHash.current,
      currHash,
      txId
    };

    lastAuditHash.current = currHash;
    setAuditLogs(prev => [entry, ...prev].slice(0, 500));
    return currHash;
  };

  const verifyWormChain = async (): Promise<{ isTamperFree: boolean; nodeCount: number; merkleRoot: string }> => {
    let prev = "0".repeat(64);
    let tampered = false;

    for (let i = auditLogs.length - 1; i >= 0; i--) {
      const log = auditLogs[i];
      if (log.prevHash !== prev) {
        tampered = true;
        break;
      }
      const rawPayload = `${log.timestamp} | ROLE:${log.role} | ACTION:${log.action} | STATUS:${log.status} | TX:${log.txId || "GLOBAL"} | prev:${log.prevHash}`;
      const calc = await sha256(rawPayload);
      if (calc !== log.currHash) {
        tampered = true;
        break;
      }
      prev = log.currHash;
    }

    const merkleRoot = await sha256(auditLogs.map(l => l.currHash).join(":"));
    return {
      isTamperFree: !tampered,
      nodeCount: auditLogs.length,
      merkleRoot: merkleRoot.substring(0, 32)
    };
  };

  const pushEventQueue = (
    eventType: string,
    source: string,
    targetVpa: string,
    severity: EventQueueItem["severity"],
    details: string,
    txId?: string
  ) => {
    const item: EventQueueItem = {
      id: `EVT-${Date.now().toString(36).toUpperCase()}-${Math.floor(100 + Math.random() * 899)}`,
      timestamp: new Date().toLocaleTimeString(),
      eventType,
      source,
      targetVpa,
      status: "QUEUED",
      severity,
      details,
      txId
    };

    setEventQueue(prev => [item, ...prev].slice(0, 100));

    setTimeout(() => {
      setEventQueue(prev =>
        prev.map(evt => (evt.id === item.id ? { ...evt, status: "PROCESSING" } : evt))
      );
    }, 400);

    setTimeout(() => {
      setEventQueue(prev =>
        prev.map(evt => (evt.id === item.id ? { ...evt, status: "CRYPTO_VERIFIED" } : evt))
      );
    }, 900);

    setTimeout(() => {
      setEventQueue(prev =>
        prev.map(evt => (evt.id === item.id ? { ...evt, status: severity === "LOW" ? "CRYPTO_VERIFIED" : "AUDIT_LOGGED" } : evt))
      );
    }, 1500);
  };

  const triggerUnfreeze = (vpa: string) => {
    writeAudit(`Manual Administrative Unfreeze Triggered for account '${vpa}'`, "SUCCESS");
  };

  const executeCommand = (cmd: string) => {
    const clean = cmd.trim().toLowerCase();
    if (clean === "presentation" || clean === "/demo") {
      setIsPresentationMode(true);
      return { success: true, message: "Presentation Mode Activated." };
    }
    return { success: false, message: "Unknown command." };
  };

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString();
      const rail = RAILS[Math.floor(Math.random() * RAILS.length)];
      const network = rail === "UPI" || rail === "NEFT" || rail === "RTGS" 
        ? DOMESTIC_NETS[Math.floor(Math.random() * DOMESTIC_NETS.length)]
        : CROSS_NETS[Math.floor(Math.random() * CROSS_NETS.length)];
      
      const vpa = `usr_${Math.floor(100 + Math.random() * 899)}@banknode`;
      const amount = Math.floor(50 + Math.random() * 45000);
      const isRisk = Math.random() > 0.85;
      const riskScore = isRisk ? parseFloat((0.75 + Math.random() * 0.24).toFixed(2)) : parseFloat((Math.random() * 0.4).toFixed(2));
      const id = `TXN-${Date.now().toString(36).toUpperCase()}-${Math.floor(1000 + Math.random() * 8999)}`;

      const record: TxRecord = {
        id,
        timestamp: timeStr,
        rail,
        network,
        amount,
        risk: riskScore,
        escrow: riskScore >= 0.75 ? "ISOLATED" : "CLEAR",
        vpa,
        ip: `192.168.1.${Math.floor(1 + Math.random() * 254)}`,
        velocity: Math.floor(1 + Math.random() * 15),
        flagged: riskScore >= 0.75,
        flagReason: riskScore >= 0.75 ? "ANOMALOUS_VELOCITY_BURST_DETECTED" : undefined,
        flagType: riskScore >= 0.75 ? "VELOCITY_SPIKE" : "NORMAL",
        mitreTactics: riskScore >= 0.75 ? ["T1557", "T1110"] : [],
        authDetails: {
          tokenStatus: "VALID",
          mfaChallenge: "PASSED",
          zeroTrustScore: riskScore >= 0.75 ? 42 : 98,
          authDecision: riskScore >= 0.75 ? "QUARANTINE" : "ALLOW"
        },
        dbStatus: {
          acidTxId: `ACID-${id}`,
          tableState: riskScore >= 0.75 ? "ISOLATED_QUARANTINE" : "COMMITTED",
          rollbackTriggered: false,
          latencyMs: Math.floor(4 + Math.random() * 18)
        },
        cryptoLogs: {
          piiTokenizer: {
            rawPiiSample: vpa,
            blindHmacIndex: `HMAC-${id.substring(0, 8)}`,
            aesEncryptedToken: `ENC-${id}`,
            status: "SECURE"
          },
          hmacSigner: {
            receivedSig: `SIG-${id}`,
            calculatedSig: `SIG-${id}`,
            algorithm: "HMAC-SHA256",
            isValid: true
          },
          aesEnvelope: {
            kekId: "KEK-MASTER-2026",
            iv: "IV-16BYTE-RANDOM",
            tag: "TAG-GCM-VAL",
            envelopeStatus: "VERIFIED"
          }
        },
        auditId: `AUD-${id}`,
        wormMerkleProof: `MERKLE-${id}`,
        manualAuditStatus: "PENDING",
        manualAuditActionLog: [],
        shap: {
          ip_anomaly: parseFloat((Math.random() * 0.3).toFixed(2)),
          auth_discrepancy: parseFloat((Math.random() * 0.25).toFixed(2)),
          velocity_impact: riskScore >= 0.75 ? 0.45 : parseFloat((Math.random() * 0.1).toFixed(2)),
          quantum_channel_instability: 0.05,
          entropy_drain: 0.02,
          pqc_decryption_anomalies: 0.01
        }
      };

      if (isRisk || riskScore >= 0.75) {
        pushEventQueue(
          "ANOMALOUS_TRANSACTION_BURST",
          `${rail}_GATEWAY`,
          vpa,
          "HIGH",
          `High-risk anomaly payload: ₹${amount} (Risk Score: ${riskScore})`,
          id
        );
      } else if (Math.random() > 0.6) {
        pushEventQueue(
          "TELEMETRY_INGESTION",
          `${rail}_GATEWAY`,
          vpa,
          "LOW",
          `Standard transaction telemetry processed: ₹${amount}`,
          id
        );
      }

      setRecords(prev => [record, ...prev].slice(0, 50));
    }, 2500);

    return () => clearInterval(interval);
  }, []);

  const triggerStuffing = async () => {
    pushEventQueue("CREDENTIAL_STUFFING", "AUTH_GATEWAY", "admin_vpa@bank", "HIGH", "Simulated Credential Stuffing Attack");
    await writeAudit("Simulated Credential Stuffing Attack triggered", "CRITICAL");
  };

  const triggerLiquidation = async () => {
    pushEventQueue("MULE_LIQUIDATION", "NEFT_ENGINE", "mule_vpa@bank", "CRITICAL", "Simulated Rapid Mule Account Liquidation");
    await writeAudit("Simulated Mule Liquidation Attack triggered", "CRITICAL");
  };

  const triggerFlood = async () => {
    pushEventQueue("VELOCITY_FLOOD", "UPI_GATEWAY", "flood_vpa@bank", "HIGH", "Simulated High-Velocity Micro-Transaction Burst");
    await writeAudit("Simulated Velocity Burst Attack triggered", "CRITICAL");
  };

  const triggerQuantumExploit = async () => {
    pushEventQueue("QUANTUM_KEY_COMPROMISE", "PQC_NODE", "qkd_gateway", "CRITICAL", "Simulated Quantum Channel Entanglement Exploit");
    await writeAudit("Simulated Quantum Key Compromise Attack triggered", "CRITICAL");
  };

  const executeManualAudit = async (txId: string, action: string) => {
    await writeAudit(`Manual Audit Executed on ${txId}: ${action}`, "SUCCESS", txId);
  };

  const dispatchOperationalReport = async (_target?: string) => {
    await writeAudit("Operational SLA Incident Report Dispatched to CERT-In Portal", "SUCCESS");
  };

  const dispatchRegulatoryReport = async (_target?: string) => {
    await writeAudit("Regulatory Compliance Incident Report Dispatched to FIU-IND Portal", "SUCCESS");
  };

  return {
    isAuthenticated,
    setIsAuthenticated,
    complianceTier,
    setComplianceTier,
    adminAccounts,
    registerAdminAccount,
    records,
    setRecords,
    auditLogs,
    incidents,
    setIncidents,
    eventQueue,
    isPresentationMode,
    setIsPresentationMode,
    presentationStep,
    setPresentationStep,
    selectedDemoTxId,
    setSelectedDemoTxId,
    role,
    setRole,
    threshold,
    setThreshold,
    circuitBreaker,
    setCircuitBreaker,
    qkdCoherence,
    setQkdCoherence,
    trngEntropy,
    setTrngEntropy,
    pqcFailures,
    setPqcFailures,
    writeAudit,
    verifyWormChain,
    pushEventQueue,
    triggerUnfreeze,
    executeCommand,
    triggerStuffing,
    triggerLiquidation,
    triggerFlood,
    triggerQuantumExploit,
    executeManualAudit,
    dispatchOperationalReport,
    dispatchRegulatoryReport
  };
}

export type SugrivaEngineType = ReturnType<typeof useSugrivaEngine>;

const StoreContext = createContext<SugrivaEngineType | null>(null);

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const store = useSugrivaEngine();
  return (
    <StoreContext.Provider value={store}>
      {children}
    </StoreContext.Provider>
  );
};

export const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) {
    throw new Error("useStore must be used within a StoreProvider");
  }
  return context;
};
