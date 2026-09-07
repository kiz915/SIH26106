"""
Tests for Physical Evidence Storage and Cryptographic Integrity Verification.
"""

import os
import tempfile
import shutil
import pytest

from backend.evidence_storage import (
    save_evidence,
    read_evidence,
    verify_evidence_file,
    resolve_evidence_path,
)
from backend.repositories import calculate_sha256


@pytest.fixture
def temp_evidence_dir():
    """Provides an isolated temporary evidence storage directory."""
    temp_dir = tempfile.mkdtemp(prefix="sih_test_evidence_")
    yield temp_dir
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


def test_evidence_file_creation_and_exact_bytes(temp_evidence_dir):
    case_id = "CASE-20260906-ABC1"
    evidence_id = "EVID-20260906-XYZ1"
    raw_bytes = b"From: test@example.com\r\nSubject: Critical Test\r\n\r\nExact Payload Byte 123!"

    storage_ref = save_evidence(
        case_id=case_id,
        evidence_id=evidence_id,
        raw_bytes=raw_bytes,
        base_dir=temp_evidence_dir
    )

    # 1. Verify storage reference format
    assert storage_ref == f"data/evidence/{case_id}/{evidence_id}.eml"

    # 2. Verify file exists on disk
    expected_path = os.path.join(temp_evidence_dir, case_id, f"{evidence_id}.eml")
    assert os.path.exists(expected_path)

    # 3. Verify byte-for-byte exact equality
    read_bytes = read_evidence(storage_ref, base_dir=temp_evidence_dir)
    assert read_bytes == raw_bytes
    assert len(read_bytes) == len(raw_bytes)


def test_evidence_sha256_verification_success(temp_evidence_dir):
    case_id = "CASE-20260906-VERIFY1"
    evidence_id = "EVID-20260906-VERIFY1"
    raw_bytes = b"Authentication-Results: pass\n\nContent for verification."

    expected_hash = calculate_sha256(raw_bytes)
    storage_ref = save_evidence(
        case_id=case_id,
        evidence_id=evidence_id,
        raw_bytes=raw_bytes,
        base_dir=temp_evidence_dir
    )

    result = verify_evidence_file(
        storage_reference=storage_ref,
        expected_sha256=expected_hash,
        base_dir=temp_evidence_dir
    )

    assert result["is_valid"] is True
    assert result["expected_sha256"] == expected_hash
    assert result["calculated_sha256"] == expected_hash
    assert result["file_size"] == len(raw_bytes)
    assert "verified" in result["reason"].lower()


def test_tampered_evidence_file_produces_hash_mismatch(temp_evidence_dir):
    case_id = "CASE-20260906-TAMPER"
    evidence_id = "EVID-20260906-TAMPER"
    original_bytes = b"Original uncorrupted message."

    original_hash = calculate_sha256(original_bytes)
    storage_ref = save_evidence(
        case_id=case_id,
        evidence_id=evidence_id,
        raw_bytes=original_bytes,
        base_dir=temp_evidence_dir
    )

    # Tamper with file on disk (flip bytes)
    file_path = resolve_evidence_path(storage_ref, base_dir=temp_evidence_dir)
    with open(file_path, "wb") as f:
        f.write(b"Tampered and corrupted message by attacker.")

    result = verify_evidence_file(
        storage_reference=storage_ref,
        expected_sha256=original_hash,
        base_dir=temp_evidence_dir
    )

    assert result["is_valid"] is False
    assert result["calculated_sha256"] != original_hash
    assert "mismatch" in result["reason"].lower() or "tampering" in result["reason"].lower()


def test_missing_evidence_file_handling(temp_evidence_dir):
    result = verify_evidence_file(
        storage_reference="data/evidence/CASE-MISSING/EVID-MISSING.eml",
        expected_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        base_dir=temp_evidence_dir
    )

    assert result["is_valid"] is False
    assert result["calculated_sha256"] is None
    assert "missing" in result["reason"].lower()


def test_path_traversal_prevention(temp_evidence_dir):
    # Invalid characters in IDs
    with pytest.raises(ValueError):
        save_evidence(
            case_id="../escaped_case",
            evidence_id="evil",
            raw_bytes=b"123",
            base_dir=temp_evidence_dir
        )

    with pytest.raises(PermissionError):
        resolve_evidence_path("../../etc/passwd", base_dir=temp_evidence_dir)
