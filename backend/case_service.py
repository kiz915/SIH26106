"""
Case Management & Evidence Service Layer.
Coordinates hashing, physical disk evidence preservation, analysis orchestration, and database persistence.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any

from db_models import (
    CaseRecord,
    EvidenceRecord,
    AnalysisRecord,
    CaseDetailResponse,
    CaseListResponse,
)
from repositories import (
    CaseRepository,
    EvidenceRepository,
    AnalysisRepository,
    calculate_sha256,
)
from evidence_storage import (
    save_evidence,
    read_evidence,
    verify_evidence_file,
)
from analyzer import analyze_email_bytes_frontend, generate_case_id
from blockchain_service import get_blockchain_service

logger = logging.getLogger("backend.case_service")


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
    ) -> Dict[str, Any]:
        """
        Executes end-to-end analysis on raw email bytes and atomically persists:
        1. Exact physical .eml evidence file under data/evidence/<case_id>/<evidence_id>.eml
        2. Exact SHA-256 evidence record with storage_reference
        3. Case management record
        4. Full serialized forensic analysis report (frontend-shaped JSON)
        5. Register evidence hash on blockchain (graceful degradation if unavailable)
        
        Returns the frontend-shaped analysis dict for client consumers.
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

        # 4. Execute forensic analysis (returns frontend-shaped dict)
        analysis_result = analyze_email_bytes_frontend(
            raw_bytes=raw_bytes,
            file_name=filename,
            case_id=case_id,
            evidence_id=evidence_id,
            evidence_hash=sha256_hash,
        )

        # 5. Register evidence on blockchain (graceful degradation)
        on_chain_status = "pending"
        blockchain_tx_hash = None
        blockchain_block_number = None
        
        try:
            blockchain_service = get_blockchain_service()
            if blockchain_service and blockchain_service.is_available():
                # Use evidence_id as the blockchain evidence identifier
                stage = "FORENSIC_ANALYSIS"
                result = blockchain_service.register_evidence(
                    evidence_id=evidence_id,
                    sha256_hash=sha256_hash,
                    stage=stage
                )
                on_chain_status = "confirmed" if result.get("success") else "failed"
                blockchain_tx_hash = result.get("transaction_hash")
                blockchain_block_number = result.get("block_number")
                logger.info(f"Registered evidence {evidence_id} on blockchain: {blockchain_tx_hash}")
            else:
                logger.info("Blockchain service not available, evidence hash not registered on-chain")
        except Exception as exc:
            logger.warning(f"Blockchain registration failed for {evidence_id} (continuing): {exc}")
            on_chain_status = "error"

        # Add blockchain info to analysis result metadata
        analysis_result["metadata"]["on_chain_status"] = on_chain_status
        if blockchain_tx_hash:
            analysis_result["metadata"]["blockchain_tx_hash"] = blockchain_tx_hash
        if blockchain_block_number:
            analysis_result["metadata"]["blockchain_block_number"] = blockchain_block_number

        # 6. Create database records
        case_record = CaseRecord(
            case_id=case_id,
            created_at=now_ts,
            updated_at=now_ts,
            original_filename=filename,
            file_size=file_size,
            status="ANALYZED",
            risk_score=analysis_result["risk"]["score"],
            classification=analysis_result["risk"]["classification"],
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

        # Store frontend-shaped analysis JSON
        analysis_json = json.dumps(analysis_result)
        analysis_record = AnalysisRecord(
            case_id=case_id,
            analysis_json=analysis_json,
            analysis_timestamp=analysis_result["metadata"]["analysis_timestamp"],
            parser_version=analysis_result["metadata"]["parser_version"],
        )

        # 7. Persist to SQLite
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
