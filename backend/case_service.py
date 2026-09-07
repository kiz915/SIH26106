"""
Case Management & Evidence Service Layer.
Coordinates hashing, physical disk evidence preservation, analysis orchestration, and database persistence.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any

from backend.models import EmailAnalysisResponse
from backend.db_models import (
    CaseRecord,
    EvidenceRecord,
    AnalysisRecord,
    CaseDetailResponse,
    CaseListResponse,
)
from backend.repositories import (
    CaseRepository,
    EvidenceRepository,
    AnalysisRepository,
    calculate_sha256,
)
from backend.evidence_storage import (
    save_evidence,
    read_evidence,
    verify_evidence_file,
)
from backend.analyzer import analyze_email_bytes, generate_case_id


class CaseService:
    """Service handling case management, physical evidence capture, and forensic workflows."""

    def __init__(self, db_path: Optional[str] = None, evidence_dir: Optional[str] = None):
        self.db_path = db_path
        self.evidence_dir = evidence_dir
        self.case_repo = CaseRepository(db_path)
        self.evidence_repo = EvidenceRepository(db_path)
        self.analysis_repo = AnalysisRepository(db_path)

    def process_and_store_email(
        self,
        raw_bytes: bytes,
        filename: str,
    ) -> EmailAnalysisResponse:
        """
        Executes end-to-end analysis on raw email bytes and atomically persists:
        1. Exact physical .eml evidence file under data/evidence/<case_id>/<evidence_id>.eml
        2. Exact SHA-256 evidence record with storage_reference
        3. Case management record
        4. Full serialized forensic analysis report
        
        Returns the EmailAnalysisResponse for client consumers.
        """
        # 1. Cryptographic hashing of exact raw bytes
        sha256_hash = calculate_sha256(raw_bytes)
        file_size = len(raw_bytes)

        # 2. Identifiers and Timestamps
        case_id = generate_case_id()
        evidence_id = f"EVID-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        # 3. Preserve exact original raw bytes to physical evidence directory
        storage_reference = save_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            raw_bytes=raw_bytes,
            base_dir=self.evidence_dir
        )

        # 4. Execute forensic analysis
        analysis_result = analyze_email_bytes(
            raw_bytes=raw_bytes,
            file_name=filename,
            case_id=case_id
        )

        # 5. Create database records
        case_record = CaseRecord(
            case_id=case_id,
            created_at=now_ts,
            updated_at=now_ts,
            original_filename=filename,
            file_size=file_size,
            status="ANALYZED",
            risk_score=analysis_result.risk.score,
            classification=analysis_result.risk.classification.value,
        )

        evidence_record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            sha256=sha256_hash,
            original_filename=filename,
            file_size=file_size,
            collected_at=now_ts,
            storage_reference=storage_reference,
        )

        analysis_record = AnalysisRecord(
            case_id=case_id,
            analysis_json=analysis_result.model_dump_json(by_alias=True),
            analysis_timestamp=analysis_result.metadata.analysis_timestamp,
            parser_version=analysis_result.metadata.parser_version,
        )

        # 6. Persist to SQLite
        self.case_repo.create_case(case_record)
        self.evidence_repo.create_evidence(evidence_record)
        self.analysis_repo.save_analysis(analysis_record)

        return analysis_result

    def list_cases(self, limit: int = 50, offset: int = 0) -> CaseListResponse:
        """Retrieves a paginated list of cases."""
        cases, total = self.case_repo.list_cases(limit=limit, offset=offset)
        return CaseListResponse(total=total, cases=cases)

    def get_case_detail(self, case_id: str) -> Optional[CaseDetailResponse]:
        """Retrieves complete case record, associated evidence, and analysis report."""
        case = self.case_repo.get_case(case_id)
        if not case:
            return None

        evidence = self.evidence_repo.get_evidence_by_case(case_id)
        analysis_rec = self.analysis_repo.get_analysis(case_id)

        analysis_dict = None
        if analysis_rec and analysis_rec.analysis_json:
            try:
                analysis_dict = json.loads(analysis_rec.analysis_json)
            except Exception:
                analysis_dict = {"raw": analysis_rec.analysis_json}

        return CaseDetailResponse(
            case=case,
            evidence=evidence,
            analysis=analysis_dict
        )

    def get_case_evidence(self, case_id: str) -> Optional[EvidenceRecord]:
        """Retrieves evidence record for a specific case."""
        case = self.case_repo.get_case(case_id)
        if not case:
            return None
        return self.evidence_repo.get_evidence_by_case(case_id)

    def verify_case_evidence(self, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Cryptographically verifies the preserved physical evidence file against the stored SHA-256 hash.
        """
        evidence = self.get_case_evidence(case_id)
        if not evidence:
            return None

        verification = verify_evidence_file(
            storage_reference=evidence.storage_reference,
            expected_sha256=evidence.sha256,
            base_dir=self.evidence_dir
        )
        verification["case_id"] = case_id
        verification["evidence_id"] = evidence.evidence_id
        return verification
