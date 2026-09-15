"""
Data Access Layer (Repository Pattern) for Cases, Evidence, and Analysis records.
Uses async SQLAlchemy for PostgreSQL/SQLite.
Includes cryptographic SHA-256 evidence hashing directly from raw bytes.
"""

import hashlib
import json
from typing import List, Optional, Tuple, Any
from datetime import datetime

from sqlalchemy import text, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db_session, init_db, init_db_sync
from db_models import CaseRecord, EvidenceRecord, AnalysisRecord


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

    async def create_case(self, case: CaseRecord, session: Optional[AsyncSession] = None) -> CaseRecord:
        """Persists a new Case record."""
        if session:
            await self._create_case_impl(case, session)
            return case
        async with get_db_session() as s:
            await self._create_case_impl(case, s)
        return case

    async def _create_case_impl(self, case: CaseRecord, session: AsyncSession):
        await session.execute(
            text("""
                INSERT INTO cases (
                    case_id, created_at, updated_at, original_filename,
                    file_size, status, risk_score, classification
                ) VALUES (:case_id, :created_at, :updated_at, :original_filename,
                          :file_size, :status, :risk_score, :classification);
            """),
            {
                "case_id": case.case_id,
                "created_at": case.created_at,
                "updated_at": case.updated_at,
                "original_filename": case.original_filename,
                "file_size": case.file_size,
                "status": case.status,
                "risk_score": case.risk_score,
                "classification": case.classification,
            }
        )

    async def get_case(self, case_id: str, session: Optional[AsyncSession] = None) -> Optional[CaseRecord]:
        """Fetches a Case by its unique case_id."""
        if session:
            return await self._get_case_impl(case_id, session)
        async with get_db_session() as s:
            return await self._get_case_impl(case_id, s)

    async def _get_case_impl(self, case_id: str, session: AsyncSession) -> Optional[CaseRecord]:
        result = await session.execute(
            text("SELECT * FROM cases WHERE case_id = :case_id;"),
            {"case_id": case_id}
        )
        row = result.first()
        if not row:
            return None
        return CaseRecord(
            case_id=row.case_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
            original_filename=row.original_filename,
            file_size=row.file_size,
            status=row.status,
            risk_score=row.risk_score,
            classification=row.classification,
        )

    async def list_cases(
        self, limit: int = 50, offset: int = 0, session: Optional[AsyncSession] = None
    ) -> Tuple[List[CaseRecord], int]:
        """Lists cases sorted by created_at DESC, returning (cases, total_count)."""
        if session:
            return await self._list_cases_impl(limit, offset, session)
        async with get_db_session() as s:
            return await self._list_cases_impl(limit, offset, s)

    async def _list_cases_impl(
        self, limit: int, offset: int, session: AsyncSession
    ) -> Tuple[List[CaseRecord], int]:
        count_result = await session.execute(text("SELECT COUNT(*) as total FROM cases;"))
        total = count_result.scalar() or 0

        result = await session.execute(
            text("SELECT * FROM cases ORDER BY created_at DESC LIMIT :limit OFFSET :offset;"),
            {"limit": limit, "offset": offset}
        )
        rows = result.fetchall()
        cases = [
            CaseRecord(
                case_id=r.case_id,
                created_at=r.created_at,
                updated_at=r.updated_at,
                original_filename=r.original_filename,
                file_size=r.file_size,
                status=r.status,
                risk_score=r.risk_score,
                classification=r.classification,
            )
            for r in rows
        ]
        return cases, total


class EvidenceRepository:
    """Data access repository for digital Evidence records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    async def create_evidence(self, evidence: EvidenceRecord, session: Optional[AsyncSession] = None) -> EvidenceRecord:
        """Persists a new digital Evidence record."""
        if session:
            await self._create_evidence_impl(evidence, session)
            return evidence
        async with get_db_session() as s:
            await self._create_evidence_impl(evidence, s)
        return evidence

    async def _create_evidence_impl(self, evidence: EvidenceRecord, session: AsyncSession):
        await session.execute(
            text("""
                INSERT INTO evidence (
                    evidence_id, case_id, sha256, original_filename,
                    file_size, collected_at, storage_reference
                ) VALUES (
                    :evidence_id, :case_id, :sha256, :original_filename,
                    :file_size, :collected_at, :storage_reference
                );
            """),
            {
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "sha256": evidence.sha256,
                "original_filename": evidence.original_filename,
                "file_size": evidence.file_size,
                "collected_at": evidence.collected_at,
                "storage_reference": evidence.storage_reference,
            }
        )

    async def get_evidence_by_case(self, case_id: str, session: Optional[AsyncSession] = None) -> Optional[EvidenceRecord]:
        """Fetches the evidence record associated with a given case_id."""
        if session:
            return await self._get_evidence_by_case_impl(case_id, session)
        async with get_db_session() as s:
            return await self._get_evidence_by_case_impl(case_id, s)

    async def _get_evidence_by_case_impl(self, case_id: str, session: AsyncSession) -> Optional[EvidenceRecord]:
        result = await session.execute(
            text("SELECT * FROM evidence WHERE case_id = :case_id;"),
            {"case_id": case_id}
        )
        row = result.first()
        if not row:
            return None
        return EvidenceRecord(
            evidence_id=row.evidence_id,
            case_id=row.case_id,
            sha256=row.sha256,
            original_filename=row.original_filename,
            file_size=row.file_size,
            collected_at=row.collected_at,
            storage_reference=row.storage_reference,
        )

    async def get_evidence(self, evidence_id: str, session: Optional[AsyncSession] = None) -> Optional[EvidenceRecord]:
        """Fetches an evidence record by its primary evidence_id."""
        if session:
            return await self._get_evidence_impl(evidence_id, session)
        async with get_db_session() as s:
            return await self._get_evidence_impl(evidence_id, s)

    async def _get_evidence_impl(self, evidence_id: str, session: AsyncSession) -> Optional[EvidenceRecord]:
        result = await session.execute(
            text("SELECT * FROM evidence WHERE evidence_id = :evidence_id;"),
            {"evidence_id": evidence_id}
        )
        row = result.first()
        if not row:
            return None
        return EvidenceRecord(
            evidence_id=row.evidence_id,
            case_id=row.case_id,
            sha256=row.sha256,
            original_filename=row.original_filename,
            file_size=row.file_size,
            collected_at=row.collected_at,
            storage_reference=row.storage_reference,
        )


class AnalysisRepository:
    """Data access repository for serialized Analysis reports."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    async def save_analysis(self, analysis: AnalysisRecord, session: Optional[AsyncSession] = None) -> AnalysisRecord:
        """Persists or updates an analysis report for a case."""
        if session:
            await self._save_analysis_impl(analysis, session)
            return analysis
        async with get_db_session() as s:
            await self._save_analysis_impl(analysis, s)
        return analysis

    async def _save_analysis_impl(self, analysis: AnalysisRecord, session: AsyncSession):
        # Convert analysis_json to JSON string if it's a dict
        analysis_json = analysis.analysis_json
        if isinstance(analysis_json, dict):
            analysis_json = json.dumps(analysis_json)
        
        await session.execute(
            text("""
                INSERT OR REPLACE INTO analysis (
                    case_id, analysis_json, analysis_timestamp, parser_version
                ) VALUES (
                    :case_id, :analysis_json, :analysis_timestamp, :parser_version
                );
            """),
            {
                "case_id": analysis.case_id,
                "analysis_json": analysis_json,
                "analysis_timestamp": analysis.analysis_timestamp,
                "parser_version": analysis.parser_version,
            }
        )

    async def get_analysis(self, case_id: str, session: Optional[AsyncSession] = None) -> Optional[AnalysisRecord]:
        """Fetches the analysis record for a given case_id."""
        if session:
            return await self._get_analysis_impl(case_id, session)
        async with get_db_session() as s:
            return await self._get_analysis_impl(case_id, s)

    async def _get_analysis_impl(self, case_id: str, session: AsyncSession) -> Optional[AnalysisRecord]:
        result = await session.execute(
            text("SELECT * FROM analysis WHERE case_id = :case_id;"),
            {"case_id": case_id}
        )
        row = result.first()
        if not row:
            return None
        
        # Parse JSONB/JSON
        analysis_json = row.analysis_json
        if isinstance(analysis_json, str):
            try:
                analysis_json = json.loads(analysis_json)
            except:
                pass
        
        return AnalysisRecord(
            case_id=row.case_id,
            analysis_json=analysis_json,
            analysis_timestamp=row.analysis_timestamp,
            parser_version=row.parser_version,
        )


# Backwards compatibility: synchronous wrappers for existing sync code
class SyncCaseRepository:
    """Synchronous wrapper for CaseRepository."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
    
    def create_case(self, case: CaseRecord, conn=None) -> CaseRecord:
        import asyncio
        if conn is None:
            # Use sync init_db for backwards compat
            init_db_sync(self.db_path)
        return asyncio.run(self._async_create(case))
    
    async def _async_create(self, case: CaseRecord):
        async with get_db_session() as s:
            await CaseRepository()._create_case_impl(case, s)
        return case
    
    def get_case(self, case_id: str, conn=None) -> Optional[CaseRecord]:
        import asyncio
        return asyncio.run(self._async_get(case_id))
    
    async def _async_get(self, case_id: str):
        async with get_db_session() as s:
            return await CaseRepository()._get_case_impl(case_id, s)
    
    def list_cases(self, limit=50, offset=0, conn=None) -> Tuple[List[CaseRecord], int]:
        import asyncio
        return asyncio.run(self._async_list(limit, offset))
    
    async def _async_list(self, limit, offset):
        async with get_db_session() as s:
            return await CaseRepository()._list_cases_impl(limit, offset, s)


class SyncEvidenceRepository:
    """Synchronous wrapper for EvidenceRepository."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
    
    def create_evidence(self, evidence: EvidenceRecord, conn=None) -> EvidenceRecord:
        import asyncio
        if conn is None:
            init_db_sync(self.db_path)
        asyncio.run(self._async_create(evidence))
        return evidence
    
    async def _async_create(self, evidence: EvidenceRecord):
        async with get_db_session() as s:
            await EvidenceRepository()._create_evidence_impl(evidence, s)
    
    def get_evidence_by_case(self, case_id: str, conn=None) -> Optional[EvidenceRecord]:
        import asyncio
        return asyncio.run(self._async_get_by_case(case_id))
    
    async def _async_get_by_case(self, case_id: str):
        async with get_db_session() as s:
            return await EvidenceRepository()._get_evidence_by_case_impl(case_id, s)
    
    def get_evidence(self, evidence_id: str, conn=None) -> Optional[EvidenceRecord]:
        import asyncio
        return asyncio.run(self._async_get(evidence_id))
    
    async def _async_get(self, evidence_id: str):
        async with get_db_session() as s:
            return await EvidenceRepository()._get_evidence_impl(evidence_id, s)


class SyncAnalysisRepository:
    """Synchronous wrapper for AnalysisRepository."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
    
    def save_analysis(self, analysis: AnalysisRecord, conn=None) -> AnalysisRecord:
        import asyncio
        if conn is None:
            init_db_sync(self.db_path)
        asyncio.run(self._async_save(analysis))
        return analysis
    
    async def _async_save(self, analysis: AnalysisRecord):
        async with get_db_session() as s:
            await AnalysisRepository()._save_analysis_impl(analysis, s)
    
    def get_analysis(self, case_id: str, conn=None) -> Optional[AnalysisRecord]:
        import asyncio
        return asyncio.run(self._async_get(case_id))
    
    async def _async_get(self, case_id: str):
        async with get_db_session() as s:
            return await AnalysisRepository()._get_analysis_impl(case_id, s)
