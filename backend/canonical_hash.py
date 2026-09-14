"""
Canonical Hash Computation for Evidence Integrity.
Matches the AI_ML canonical JSON logic for deterministic hashing.
"""

import json
import hashlib
from typing import Dict, Any


def compute_canonical_hash(analysis_dict: Dict[str, Any]) -> str:
    """
    Compute canonical SHA-256 hash of the analysis result.
    Removes non-deterministic fields (timestamp, latency) and sorts keys.
    
    This matches the AI_ML AnalysisResult.to_canonical_json() logic.
    """
    # Create a copy to avoid modifying original
    d = analysis_dict.copy()
    
    # Remove non-deterministic fields
    if "metadata" in d:
        meta = d["metadata"].copy()
        meta.pop("analysis_timestamp", None)
        meta.pop("execution_time_ms", None)
        meta.pop("blockchain_tx_hash", None)
        meta.pop("blockchain_block_number", None)
        meta.pop("on_chain_status", None)
        meta.pop("narrative", None)
        d["metadata"] = meta
    
    # Remove model_metadata latency_ms if present
    if "risk" in d and "ml_signals" in d["risk"]:
        ml_sig = d["risk"]["ml_signals"].copy()
        # Keep phishing_probability, bec_probability, model_name, confidence
        # These are deterministic from the model
    
    # Sort keys for deterministic JSON
    canonical_json = json.dumps(d, sort_keys=True, separators=(",", ":"))
    
    # Compute SHA-256
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_evidence_hash(raw_bytes: bytes) -> str:
    """Compute SHA-256 of raw email bytes (exact payload)."""
    return hashlib.sha256(raw_bytes).hexdigest()


def verify_canonical_hash(analysis_dict: Dict[str, Any], expected_hash: str) -> bool:
    """Verify that the canonical hash of analysis matches expected."""
    computed = compute_canonical_hash(analysis_dict)
    return computed.lower() == expected_hash.lower()
