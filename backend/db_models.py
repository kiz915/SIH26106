"""
Database models and Case Management API Schemas.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CaseRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str = Field(..., description="Unique case identifier (e.g. CASE-20260906-ABCD)")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp of case creation")
    updated_at: str = Field(..., description="ISO 8601 UTC timestamp of last update")
    original_filename: str = Field(..., description="Original filename of uploaded .eml file")
    file_size: int = Field(..., description="Size of email file in bytes")
    status: str = Field(default="ANALYZED", description="Status: PENDING | ANALYZED | FAILED")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated forensic risk score (0-100)")
    classification: str = Field(..., description="Risk tier classification")


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str = Field(..., description="Unique evidence identifier (e.g. EVID-20260906-ABCD)")
    case_id: str = Field(..., description="Associated case identifier")
    sha256: str = Field(..., description="Cryptographic SHA-256 digest of exact raw .eml payload")
    original_filename: str = Field(..., description="Filename when evidence was collected")
    file_size: int = Field(..., description="Exact payload byte count")
    collected_at: str = Field(..., description="ISO 8601 UTC timestamp when evidence was ingested")
    storage_reference: str = Field(..., description="Internal storage/chain-of-custody reference")


class AnalysisRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str = Field(..., description="Associated case identifier")
    analysis_json: str = Field(..., description="Serialized JSON containing full analysis report")
    analysis_timestamp: str = Field(..., description="Timestamp of analysis generation")
    parser_version: str = Field(..., description="Version of forensic analyzer used")


class CaseDetailResponse(BaseModel):
    case: CaseRecord
    evidence: Optional[EvidenceRecord] = None
    analysis: Optional[Dict[str, Any]] = None


class CaseListResponse(BaseModel):
    total: int
    cases: List[CaseRecord]
