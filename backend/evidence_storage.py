"""
Forensic Evidence Storage & Integrity Verification.
Preserves exact unparsed raw .eml bytes on physical disk and verifies cryptographic chain-of-custody.
"""

import os
import re
from typing import Optional, Dict, Any

from backend.repositories import calculate_sha256

# Root evidence directory: data/evidence/
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EVIDENCE_DIR = os.path.join(ROOT_DIR, "data", "evidence")

SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def get_evidence_base_dir(custom_dir: Optional[str] = None) -> str:
    """Returns the absolute base directory for evidence storage."""
    return os.path.abspath(custom_dir or os.environ.get("SIH_EVIDENCE_DIR", DEFAULT_EVIDENCE_DIR))


def sanitize_identifier(identifier: str) -> str:
    """Sanitizes an identifier to prevent path traversal attacks."""
    if not identifier or not SAFE_ID_PATTERN.match(identifier):
        raise ValueError(f"Invalid characters in identifier: '{identifier}'. Must be alphanumeric with hyphens/underscores.")
    return identifier


def save_evidence(
    case_id: str,
    evidence_id: str,
    raw_bytes: bytes,
    base_dir: Optional[str] = None
) -> str:
    """
    Saves exact original raw .eml bytes to disk under:
    <base_dir>/<case_id>/<evidence_id>.eml
    
    Returns standard normalized relative storage reference:
    data/evidence/<case_id>/<evidence_id>.eml
    """
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) == 0:
        raise ValueError("Cannot store empty or non-bytes evidence payload.")

    safe_case_id = sanitize_identifier(case_id)
    safe_evidence_id = sanitize_identifier(evidence_id)

    root = get_evidence_base_dir(base_dir)
    target_dir = os.path.join(root, safe_case_id)
    os.makedirs(target_dir, exist_ok=True)

    file_path = os.path.join(target_dir, f"{safe_evidence_id}.eml")
    
    # Write exact unmodified bytes
    with open(file_path, "wb") as f:
        f.write(raw_bytes)

    # Return standard relative storage reference with forward slashes
    return f"data/evidence/{safe_case_id}/{safe_evidence_id}.eml"


def resolve_evidence_path(storage_reference: str, base_dir: Optional[str] = None) -> str:
    """
    Resolves storage reference to absolute path while enforcing boundary safety.
    """
    root = get_evidence_base_dir(base_dir)
    
    # Normalize reference
    normalized_ref = storage_reference.replace("\\", "/").strip()
    if normalized_ref.startswith("data/evidence/"):
        rel_path = normalized_ref[len("data/evidence/"):]
    else:
        rel_path = normalized_ref.lstrip("/")

    abs_path = os.path.abspath(os.path.join(root, rel_path))

    # Security check: ensure resolved path is strictly within the evidence root
    if not abs_path.startswith(root):
        raise PermissionError(f"Access denied: storage reference '{storage_reference}' resolves outside evidence root.")

    return abs_path


def read_evidence(storage_reference: str, base_dir: Optional[str] = None) -> bytes:
    """
    Reads preserved raw .eml bytes from physical disk.
    Raises FileNotFoundError if file is missing.
    """
    abs_path = resolve_evidence_path(storage_reference, base_dir)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Evidence file not found at reference: '{storage_reference}'")

    with open(abs_path, "rb") as f:
        return f.read()


def verify_evidence_file(
    storage_reference: str,
    expected_sha256: str,
    base_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cryptographically verifies the physical evidence file against expected SHA-256 hash.
    """
    try:
        raw_bytes = read_evidence(storage_reference, base_dir)
    except FileNotFoundError:
        return {
            "is_valid": False,
            "expected_sha256": expected_sha256,
            "calculated_sha256": None,
            "file_size": None,
            "storage_reference": storage_reference,
            "reason": "Preserved evidence file is missing from disk storage.",
        }
    except Exception as exc:
        return {
            "is_valid": False,
            "expected_sha256": expected_sha256,
            "calculated_sha256": None,
            "file_size": None,
            "storage_reference": storage_reference,
            "reason": f"Failed to access evidence file: {str(exc)}",
        }

    actual_hash = calculate_sha256(raw_bytes)
    is_valid = (actual_hash == expected_sha256)

    return {
        "is_valid": is_valid,
        "expected_sha256": expected_sha256,
        "calculated_sha256": actual_hash,
        "file_size": len(raw_bytes),
        "storage_reference": storage_reference,
        "reason": "Cryptographic SHA-256 integrity verified." if is_valid else "Hash mismatch: preserved file differs from ingestion digest (tampering or corruption detected).",
    }
