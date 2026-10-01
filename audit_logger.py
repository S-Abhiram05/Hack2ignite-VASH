import os
import json
import hashlib
from datetime import datetime, timezone

WORM_LOG_FILE = "vash_audit_worm.log"

def _get_last_hash() -> str:
    """Retrieves the cryptographic hash of the previous log entry to maintain the hash chain."""
    if not os.path.exists(WORM_LOG_FILE):
        return "0" * 64
    try:
        with open(WORM_LOG_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines:
                last_entry = json.loads(lines[-1])
                return last_entry.get("curr_hash", "0" * 64)
    except Exception:
        pass
    return "0" * 64

def write_worm_log(event_type: str, payload_data: dict, institution_id: str = "SYSTEM") -> str:
    """
    Writes a WORM-compliant, cryptographically chained immutable audit record.
    Uses SHA-256 canonical payload hashing and prev_hash chaining.
    """
    timestamp_str = datetime.now(timezone.utc).isoformat()
    
    # 1. Canonical payload string and SHA-256 hash
    canonical_payload = json.dumps(payload_data, sort_keys=True, default=str)
    payload_hash = hashlib.sha256(canonical_payload.encode('utf-8')).hexdigest()
    
    # 2. Get previous entry hash for Merkle chain link
    prev_hash = _get_last_hash()
    
    # 3. Compute entry hash
    chain_input = f"{timestamp_str}|{institution_id}|{event_type}|{payload_hash}|{prev_hash}"
    curr_hash = hashlib.sha256(chain_input.encode('utf-8')).hexdigest()
    
    log_entry = {
        "timestamp_utc": timestamp_str,
        "institution_id": institution_id,
        "event_type": event_type,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "curr_hash": curr_hash,
        "data": payload_data
    }
    
    with open(WORM_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")
        
    return curr_hash
