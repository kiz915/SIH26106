"""
Tests for backend/database.py, backend/repositories.py, and SHA-256 evidence hashing.
"""

import os
import tempfile
import sqlite3
import pytest

from backend.database import init_db, get_db_connection
from backend.db_models import CaseRecord, EvidenceRecord, AnalysisRecord
from backend.repositories import (
    CaseRepository,
    EvidenceRepository,
    AnalysisRepository,
    calculate_sha256,
)


@pytest.fixture
def temp_db():
    """Provides a temporary SQLite database file for isolated testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_calculate_sha256_exact_bytes():
    payload = b"Subject: Test Message\n\nExact raw email payload bytes."
    hash1 = calculate_sha256(payload)
    hash2 = calculate_sha256(payload)
    
    assert hash1 == hash2
    assert len(hash1) == 64
    # Ensure invalid type raises TypeError
    with pytest.raises(TypeError):
        calculate_sha256("string not bytes")


def test_database_initialization_tables_exist(temp_db):
    conn = get_db_connection(temp_db)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}
    conn.close()

    assert "cases" in tables
    assert "evidence" in tables
    assert "analysis" in tables


def test_case_repository_crud(temp_db):
    repo = CaseRepository(temp_db)

    case = CaseRecord(
        case_id="CASE-20260906-TEST01",
        created_at="2026-09-06T12:00:00Z",
        updated_at="2026-09-06T12:00:00Z",
        original_filename="test1.eml",
        file_size=1024,
        status="ANALYZED",
        risk_score=75,
        classification="HIGH RISK",
    )

    # 1. Create
    created = repo.create_case(case)
    assert created.case_id == "CASE-20260906-TEST01"

    # 2. Get
    fetched = repo.get_case("CASE-20260906-TEST01")
    assert fetched is not None
    assert fetched.original_filename == "test1.eml"
    assert fetched.risk_score == 75
    assert fetched.classification == "HIGH RISK"

    # 3. List
    cases, total = repo.list_cases(limit=10, offset=0)
    assert total == 1
    assert len(cases) == 1
    assert cases[0].case_id == "CASE-20260906-TEST01"

    # 4. Get non-existent
    assert repo.get_case("NON_EXISTENT") is None


def test_evidence_repository_crud(temp_db):
    case_repo = CaseRepository(temp_db)
    evidence_repo = EvidenceRepository(temp_db)

    # Create parent case first
    case_repo.create_case(
        CaseRecord(
            case_id="CASE-20260906-EVID01",
            created_at="2026-09-06T12:00:00Z",
            updated_at="2026-09-06T12:00:00Z",
            original_filename="sample.eml",
            file_size=512,
            status="ANALYZED",
            risk_score=20,
            classification="LOW RISK",
        )
    )

    evidence = EvidenceRecord(
        evidence_id="EVID-20260906-0001",
        case_id="CASE-20260906-EVID01",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        original_filename="sample.eml",
        file_size=512,
        collected_at="2026-09-06T12:00:00Z",
        storage_reference="raw_payload/CASE-20260906-EVID01/sample.eml",
    )

    created_evid = evidence_repo.create_evidence(evidence)
    assert created_evid.evidence_id == "EVID-20260906-0001"

    # Fetch by case_id
    by_case = evidence_repo.get_evidence_by_case("CASE-20260906-EVID01")
    assert by_case is not None
    assert by_case.sha256 == evidence.sha256

    # Fetch by evidence_id
    by_id = evidence_repo.get_evidence("EVID-20260906-0001")
    assert by_id is not None
    assert by_id.evidence_id == "EVID-20260906-0001"


def test_analysis_repository_crud(temp_db):
    case_repo = CaseRepository(temp_db)
    analysis_repo = AnalysisRepository(temp_db)

    case_repo.create_case(
        CaseRecord(
            case_id="CASE-20260906-AN01",
            created_at="2026-09-06T12:00:00Z",
            updated_at="2026-09-06T12:00:00Z",
            original_filename="an.eml",
            file_size=256,
            status="ANALYZED",
            risk_score=10,
            classification="LOW RISK",
        )
    )

    analysis = AnalysisRecord(
        case_id="CASE-20260906-AN01",
        analysis_json='{"risk": {"score": 10}}',
        analysis_timestamp="2026-09-06T12:00:00Z",
        parser_version="1.0.0-prototype",
    )

    analysis_repo.save_analysis(analysis)
    fetched = analysis_repo.get_analysis("CASE-20260906-AN01")
    assert fetched is not None
    assert fetched.parser_version == "1.0.0-prototype"
    assert "score" in fetched.analysis_json


def test_foreign_key_cascade_deletion(temp_db):
    case_repo = CaseRepository(temp_db)
    evidence_repo = EvidenceRepository(temp_db)
    analysis_repo = AnalysisRepository(temp_db)

    case_id = "CASE-CASCADE-TEST"
    case_repo.create_case(
        CaseRecord(
            case_id=case_id,
            created_at="2026-09-06T12:00:00Z",
            updated_at="2026-09-06T12:00:00Z",
            original_filename="cascade.eml",
            file_size=100,
            status="ANALYZED",
            risk_score=0,
            classification="LOW RISK",
        )
    )

    evidence_repo.create_evidence(
        EvidenceRecord(
            evidence_id="EVID-CASCADE-1",
            case_id=case_id,
            sha256="abc123456",
            original_filename="cascade.eml",
            file_size=100,
            collected_at="2026-09-06T12:00:00Z",
            storage_reference="ref",
        )
    )

    analysis_repo.save_analysis(
        AnalysisRecord(
            case_id=case_id,
            analysis_json="{}",
            analysis_timestamp="2026-09-06T12:00:00Z",
            parser_version="1.0.0-prototype",
        )
    )

    # Delete parent case
    conn = get_db_connection(temp_db)
    with conn:
        conn.execute("DELETE FROM cases WHERE case_id = ?;", (case_id,))
    conn.close()

    assert case_repo.get_case(case_id) is None
    assert evidence_repo.get_evidence_by_case(case_id) is None
    assert analysis_repo.get_analysis(case_id) is None
