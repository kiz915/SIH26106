"""
Central Analyzer Orchestrator.
Coordinates email parsing, authentication checks, IOC extraction, relay analysis,
risk assessment, IP geolocation intelligence, and domain DNS intelligence.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from backend.models import (
    EmailAnalysisResponse,
    AnalysisMetadata,
    EmailMetadata,
    AuthResults,
    IOCs,
    RiskAssessment
)
from backend.header_parser import parse_email_headers
from backend.relay_parser import parse_relay_path
from backend.ioc_extractor import extract_iocs
from backend.risk_engine import calculate_risk
from backend.ip_intelligence import IPIntelligenceService
from backend.domain_intelligence import DomainIntelligenceService

PARSER_VERSION = "1.0.0-prototype"

# Shared intelligence services with in-memory caching
ip_intel_service = IPIntelligenceService()
domain_intel_service = DomainIntelligenceService()


def generate_case_id() -> str:
    """Generates a unique forensic case ID (e.g. CASE-20260906-A1B2C3D4)."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:8].upper()
    return f"CASE-{date_str}-{unique_suffix}"


def analyze_email_bytes(
    raw_bytes: bytes,
    file_name: Optional[str] = "uploaded_email.eml",
    case_id: Optional[str] = None
) -> EmailAnalysisResponse:
    """
    Main analysis pipeline function.
    Safely parses raw email bytes and generates a forensic analysis report with IP and domain intelligence.
    """
    if not raw_bytes or len(raw_bytes.strip()) == 0:
        raise ValueError("Cannot analyze empty email content.")

    start_time = time.perf_counter()
    active_case_id = case_id or generate_case_id()
    analysis_ts = datetime.now(timezone.utc).isoformat()
    file_size = len(raw_bytes)

    # 1. Parse Headers & Body
    email_meta, auth_results, plain_body, html_body, msg_obj = parse_email_headers(raw_bytes)

    # 2. Parse Relay Path
    relay_hops = parse_relay_path(msg_obj)

    # 3. Extract IOCs
    header_emails = []
    if email_meta.from_address:
        header_emails.append(email_meta.from_address)
    if email_meta.reply_to:
        header_emails.append(email_meta.reply_to)
    if email_meta.return_path:
        header_emails.append(email_meta.return_path)
    header_emails.extend(email_meta.to)
    header_emails.extend(email_meta.cc)

    iocs = extract_iocs(plain_body, html_body, header_emails)

    # 4. Calculate Risk
    risk = calculate_risk(
        email_meta=email_meta,
        auth=auth_results,
        iocs=iocs,
        relay_hops=relay_hops,
        plain_body=plain_body
    )

    # 5. IP Intelligence & Network Geolocation Enrichment
    all_ips = list(iocs.ips)
    for hop in relay_hops:
        if hop.ip and hop.ip not in all_ips:
            all_ips.append(hop.ip)

    try:
        ip_intel_records = ip_intel_service.lookup_ips(all_ips)
        ip_intel_json = [r.model_dump(by_alias=True) for r in ip_intel_records]
    except Exception:
        ip_intel_json = []

    # 6. Domain Intelligence & DNS Resolution Enrichment
    try:
        domain_intel_records = domain_intel_service.lookup_domains(iocs.domains)
        domain_intel_json = [d.model_dump(by_alias=True) for d in domain_intel_records]
    except Exception:
        domain_intel_json = []

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    metadata = AnalysisMetadata(
        analysis_timestamp=analysis_ts,
        parser_version=PARSER_VERSION,
        file_name=file_name,
        file_size_bytes=file_size,
        execution_time_ms=elapsed_ms
    )

    return EmailAnalysisResponse(
        case_id=active_case_id,
        email=email_meta,
        authentication=auth_results,
        iocs=iocs,
        relay_path=relay_hops,
        risk=risk,
        ip_intelligence=ip_intel_json,
        domain_intelligence=domain_intel_json,
        metadata=metadata
    )
