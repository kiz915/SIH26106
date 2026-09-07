"""
Data models and API schemas for SIH26106 Email Threat Detection & Forensic Intelligence Platform.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class RiskClassification(str, Enum):
    LOW_RISK = "LOW RISK"
    MEDIUM_RISK = "MEDIUM RISK"
    HIGH_RISK = "HIGH RISK"
    CRITICAL_RISK = "CRITICAL RISK"


class EmailMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_address: Optional[str] = Field(default=None, alias="from", description="Sender address from 'From' header")
    to: List[str] = Field(default_factory=list, description="Recipient addresses from 'To' header")
    cc: List[str] = Field(default_factory=list, description="Carbon copy addresses from 'Cc' header")
    reply_to: Optional[str] = Field(default=None, description="Address specified in 'Reply-To' header")
    return_path: Optional[str] = Field(default=None, description="Address specified in 'Return-Path' header")
    subject: Optional[str] = Field(default=None, description="Email subject line")
    message_id: Optional[str] = Field(default=None, description="Unique Message-ID header value")
    date: Optional[str] = Field(default=None, description="Date header value")
    content_type: Optional[str] = Field(default=None, description="MIME content type")
    body_preview: Optional[str] = Field(default=None, description="Sanitized plain-text preview of email body")


class AuthResults(BaseModel):
    spf: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="SPF verification result")
    dkim: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="DKIM verification result")
    dmarc: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="DMARC verification result")
    raw_results: List[str] = Field(default_factory=list, description="Original raw authentication header lines")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed breakdown of auth parameters")


class IOCs(BaseModel):
    urls: List[str] = Field(default_factory=list, description="Extracted and cleaned URLs")
    ips: List[str] = Field(default_factory=list, description="Validated IPv4 and IPv6 addresses")
    domains: List[str] = Field(default_factory=list, description="Extracted domain names")
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses")


class RelayHop(BaseModel):
    hop_number: int = Field(..., description="1-indexed hop order (1 = closest to original sender)")
    receiving_server: Optional[str] = Field(default=None, description="Server receiving this hop (by ...)")
    sending_server: Optional[str] = Field(default=None, description="Server transmitting this hop (from ...)")
    ip: Optional[str] = Field(default=None, description="Validated IP address associated with hop")
    ip_type: Optional[str] = Field(
        default=None,
        description="IP classification: 'rfc1918' | 'loopback' | 'link-local' | 'documentation' | 'reserved' | 'public'"
    )
    timestamp: Optional[str] = Field(default=None, description="Timestamp recorded in Received header")
    raw_header: str = Field(..., description="Full raw Received header string")
    is_private_ip: bool = Field(default=False, description="True if IP is RFC1918 private or IPv6 ULA")
    delay_seconds: Optional[float] = Field(default=None, description="Transit delay relative to previous hop")
    forensic_notes: Optional[str] = Field(default=None, description="Forensic integrity commentary")


class RiskSignal(BaseModel):
    name: str = Field(..., description="Identifier for detected signal")
    score_impact: int = Field(..., description="Score points added by this signal")
    severity: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    description: str = Field(..., description="Explanation of why this signal was flagged")


class MLIntelligence(BaseModel):
    model: str = Field(default="placeholder-roberta-phishing", description="AI/ML model identifier")
    classification: Optional[str] = Field(default=None, description="Model prediction: Phishing, BEC, Clean")
    confidence: Optional[float] = Field(default=None, description="Confidence score 0.0 to 1.0")
    explanation: Optional[str] = Field(default=None, description="SHAP or attention-based explanation")


class IPIntelligence(BaseModel):
    status: str = Field(default="unavailable", description="Lookup status: available | unavailable | error")
    provider: str = Field(default="none", description="IP intelligence provider name")
    country: Optional[str] = Field(default=None, description="Country name/code")
    region: Optional[str] = Field(default=None, description="Region / State")
    city: Optional[str] = Field(default=None, description="City")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number")
    isp: Optional[str] = Field(default=None, description="ISP / Organization")
    is_hosting: Optional[bool] = Field(default=None, description="Hosting / Cloud indicator")
    is_vpn_tor: Optional[bool] = Field(default=None, description="VPN / TOR exit node indicator")
    disclaimer: str = Field(
        default="IP geolocation reflects network infrastructure routing, not physical attacker identity.",
        description="Forensic evidentiary disclaimer"
    )


class RiskAssessment(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Deterministic risk score between 0 and 100")
    classification: RiskClassification = Field(..., description="Risk tier classification")
    reasons: List[str] = Field(default_factory=list, description="Human-readable forensic rationale")
    signals: List[RiskSignal] = Field(default_factory=list, description="Detailed list of triggered rule signals")
    scoring_type: str = Field(
        default="deterministic_rule_based_prototype",
        description="Indicates this is deterministic forensic rule scoring, not ML inference"
    )
    ml_signals: Optional[MLIntelligence] = Field(
        default=None,
        description="Pluggable interface for AI/ML teammate's predictions"
    )
    ip_intelligence: Optional[IPIntelligence] = Field(
        default=None,
        description="Pluggable interface for IP threat intelligence"
    )


class AnalysisMetadata(BaseModel):
    analysis_timestamp: str = Field(..., description="ISO 8601 UTC timestamp of analysis")
    parser_version: str = Field(default="1.0.0-prototype", description="Forensic engine version")
    file_name: Optional[str] = Field(default=None, description="Uploaded file name")
    file_size_bytes: Optional[int] = Field(default=None, description="File size in bytes")
    execution_time_ms: Optional[float] = Field(default=None, description="Analysis elapsed time in milliseconds")


class EmailAnalysisResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    case_id: str = Field(..., description="Unique investigation case identifier (e.g. CASE-20260906-ABCD)")
    email: EmailMetadata = Field(..., description="Parsed email header metadata")
    authentication: AuthResults = Field(..., description="Email authentication results (SPF/DKIM/DMARC)")
    iocs: IOCs = Field(..., description="Extracted Indicators of Compromise (URLs, IPs, Domains, Emails)")
    relay_path: List[RelayHop] = Field(default_factory=list, description="Ordered Received-header relay hops")
    risk: RiskAssessment = Field(..., description="Forensic risk assessment and signal details")
    ip_intelligence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Network infrastructure intelligence for extracted IP addresses"
    )
    domain_intelligence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="DNS & infrastructure intelligence for extracted domains"
    )
    metadata: AnalysisMetadata = Field(..., description="Execution and parser metadata")


class HealthResponse(BaseModel):
    status: str = "online"
    service: str = "SIH26106 Email Threat Detection API"
    version: str = "1.0.0-prototype"
    timestamp: str
