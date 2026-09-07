"""
Data Access Layer (Repository Pattern) for Cases, Evidence, and Analysis records.
Includes cryptographic SHA-256 evidence hashing directly from raw bytes.
"""

import hashlib
import sqlite3
from typing import List, Optional, Tuple

from backend.database import get_db_connection
from backend.db_models import CaseRecord, EvidenceRecord, AnalysisRecord


def calculate_sha256(data: bytes) -> str:
    """
    Computes deterministic SHA-256 hex digest strictly from raw payload bytes.
    Must never be calculated on decoded or altered content.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("calculate_sha256 expects raw bytes input.")
    return hashlib.sha256(data).hexdigest()


class CaseRepository:
    """Data access repository for Case management."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def create_case(self, case: CaseRecord, conn: Optional[sqlite3.Connection] = None) -> CaseRecord:
        """Persists a new Case record."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO cases (
                        case_id, created_at, updated_at, original_filename,
                        file_size, status, risk_score, classification
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        case.case_id,
                        case.created_at,
                        case.updated_at,
                        case.original_filename,
                        case.file_size,
                        case.status,
                        case.risk_score,
                        case.classification,
                    ),
                )
            return case
        finally:
            if should_close:
                conn.close()

    def get_case(self, case_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[CaseRecord]:
        """Fetches a Case by its unique case_id."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            cursor = conn.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return CaseRecord(
                case_id=row["case_id"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                original_filename=row["original_filename"],
                file_size=row["file_size"],
                status=row["status"],
                risk_score=row["risk_score"],
                classification=row["classification"],
            )
        finally:
            if should_close:
                conn.close()

    def list_cases(
        self, limit: int = 50, offset: int = 0, conn: Optional[sqlite3.Connection] = None
    ) -> Tuple[List[CaseRecord], int]:
        """Lists cases sorted by created_at DESC, returning (cases, total_count)."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            count_cursor = conn.execute("SELECT COUNT(*) as total FROM cases;")
            total = count_cursor.fetchone()["total"]

            cursor = conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cases = [
                CaseRecord(
                    case_id=r["case_id"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    original_filename=r["original_filename"],
                    file_size=r["file_size"],
                    status=r["status"],
                    risk_score=r["risk_score"],
                    classification=r["classification"],
                )
                for r in rows
            ]
            return cases, total
        finally:
            if should_close:
                conn.close()


class EvidenceRepository:
    """Data access repository for digital Evidence records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def create_evidence(self, evidence: EvidenceRecord, conn: Optional[sqlite3.Connection] = None) -> EvidenceRecord:
        """Persists a new digital Evidence record."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO evidence (
                        evidence_id, case_id, sha256, original_filename,
                        file_size, collected_at, storage_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        evidence.evidence_id,
                        evidence.case_id,
                        evidence.sha256,
                        evidence.original_filename,
                        evidence.file_size,
                        evidence.collected_at,
                        evidence.storage_reference,
                    ),
                )
            return evidence
        finally:
            if should_close:
                conn.close()

    def get_evidence_by_case(self, case_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[EvidenceRecord]:
        """Fetches the evidence record associated with a given case_id."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            cursor = conn.execute("SELECT * FROM evidence WHERE case_id = ?;", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return EvidenceRecord(
                evidence_id=row["evidence_id"],
                case_id=row["case_id"],
                sha256=row["sha256"],
                original_filename=row["original_filename"],
                file_size=row["file_size"],
                collected_at=row["collected_at"],
                storage_reference=row["storage_reference"],
            )
        finally:
            if should_close:
                conn.close()

    def get_evidence(self, evidence_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[EvidenceRecord]:
        """Fetches an evidence record by its primary evidence_id."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            cursor = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?;", (evidence_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return EvidenceRecord(
                evidence_id=row["evidence_id"],
                case_id=row["case_id"],
                sha256=row["sha256"],
                original_filename=row["original_filename"],
                file_size=row["file_size"],
                collected_at=row["collected_at"],
                storage_reference=row["storage_reference"],
            )
        finally:
            if should_close:
                conn.close()


class AnalysisRepository:
    """Data access repository for serialized Analysis reports."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def save_analysis(self, analysis: AnalysisRecord, conn: Optional[sqlite3.Connection] = None) -> AnalysisRecord:
        """Persists or updates an analysis report for a case."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO analysis (
                        case_id, analysis_json, analysis_timestamp, parser_version
                    ) VALUES (?, ?, ?, ?);
                    """,
                    (
                        analysis.case_id,
                        analysis.analysis_json,
                        analysis.analysis_timestamp,
                        analysis.parser_version,
                    ),
                )
            return analysis
        finally:
            if should_close:
                conn.close()

    def get_analysis(self, case_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[AnalysisRecord]:
        """Fetches the analysis record for a given case_id."""
        should_close = False
        if conn is None:
            conn = get_db_connection(self.db_path)
            should_close = True

        try:
            cursor = conn.execute("SELECT * FROM analysis WHERE case_id = ?;", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AnalysisRecord(
                case_id=row["case_id"],
                analysis_json=row["analysis_json"],
                analysis_timestamp=row["analysis_timestamp"],
                parser_version=row["parser_version"],
            )
        finally:
            if should_close:
                conn.close()
