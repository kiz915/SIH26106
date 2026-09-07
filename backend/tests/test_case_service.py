"""
Tests for CaseService, Physical Evidence Preservation, and FastAPI Endpoints.
"""

import os
import tempfile
import shutil
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import init_db
from backend.case_service import CaseService
from backend.repositories import calculate_sha256
from backend.evidence_storage import resolve_evidence_path

client = TestClient(app)

SAMPLE_EML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "samples",
    "suspicious_email.eml"
)


@pytest.fixture
def isolated_service():
    """Provides an isolated CaseService with its own temporary database and evidence directory."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path)

    evid_dir = tempfile.mkdtemp(prefix="sih_test_evid_")
    service = CaseService(db_path=db_path, evidence_dir=evid_dir)

    yield service

    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(evid_dir):
        shutil.rmtree(evid_dir)


def test_service_process_and_store_email(isolated_service):
    with open(SAMPLE_EML_PATH, "rb") as f:
        raw_bytes = f.read()

    expected_hash = calculate_sha256(raw_bytes)
    result = isolated_service.process_and_store_email(raw_bytes, "suspicious_email.eml")

    # 1. Verify returned analysis response
    assert result.case_id.startswith("CASE-")
    assert result.risk.score >= 70

    # 2. Verify stored case detail
    case_detail = isolated_service.get_case_detail(result.case_id)
    assert case_detail is not None
    assert case_detail.case.case_id == result.case_id
    assert case_detail.case.original_filename == "suspicious_email.eml"
    assert case_detail.case.status == "ANALYZED"
    assert case_detail.case.risk_score == result.risk.score

    # 3. Verify stored evidence & physical storage reference
    assert case_detail.evidence is not None
    assert case_detail.evidence.sha256 == expected_hash
    assert case_detail.evidence.file_size == len(raw_bytes)
    assert case_detail.evidence.storage_reference.startswith("data/evidence/")
    assert case_detail.evidence.storage_reference.endswith(".eml")

    # 4. Verify physical file exists on disk and matches exactly
    physical_file_path = resolve_evidence_path(
        case_detail.evidence.storage_reference,
        base_dir=isolated_service.evidence_dir
    )
    assert os.path.exists(physical_file_path)
    with open(physical_file_path, "rb") as f:
        disk_bytes = f.read()
    assert disk_bytes == raw_bytes

    # 5. Verify cryptographic verification service
    verification = isolated_service.verify_case_evidence(result.case_id)
    assert verification is not None
    assert verification["is_valid"] is True
    assert verification["calculated_sha256"] == expected_hash

    # 6. Verify tampering makes verification fail
    with open(physical_file_path, "wb") as f:
        f.write(b"Tampered content")
    tampered_verification = isolated_service.verify_case_evidence(result.case_id)
    assert tampered_verification["is_valid"] is False


def test_api_case_endpoints_integration():
    with open(SAMPLE_EML_PATH, "rb") as f:
        eml_bytes = f.read()

    expected_sha256 = calculate_sha256(eml_bytes)

    # 1. Analyze email via API
    analyze_resp = client.post(
        "/analyze",
        files={"file": ("suspicious_email.eml", eml_bytes, "message/rfc822")}
    )
    assert analyze_resp.status_code == 200
    analyze_data = analyze_resp.json()
    case_id = analyze_data["case_id"]

    # 2. GET /cases
    cases_resp = client.get("/cases")
    assert cases_resp.status_code == 200
    cases_data = cases_resp.json()
    assert cases_data["total"] >= 1
    found = any(c["case_id"] == case_id for c in cases_data["cases"])
    assert found is True

    # 3. GET /cases/{case_id}
    detail_resp = client.get(f"/cases/{case_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["case"]["case_id"] == case_id
    assert detail_data["case"]["status"] == "ANALYZED"
    assert detail_data["evidence"]["sha256"] == expected_sha256
    assert detail_data["evidence"]["storage_reference"].startswith("data/evidence/")
    assert detail_data["analysis"]["case_id"] == case_id

    # 4. GET /cases/{case_id}/evidence
    evid_resp = client.get(f"/cases/{case_id}/evidence")
    assert evid_resp.status_code == 200
    evid_data = evid_resp.json()
    assert evid_data["case_id"] == case_id
    assert evid_data["sha256"] == expected_sha256
    assert evid_data["file_size"] == len(eml_bytes)
    assert evid_data["storage_reference"].startswith("data/evidence/")

    # 5. Non-existent case 404s
    missing_case = client.get("/cases/CASE-DOES-NOT-EXIST")
    assert missing_case.status_code == 404

    missing_evid = client.get("/cases/CASE-DOES-NOT-EXIST/evidence")
    assert missing_evid.status_code == 404
