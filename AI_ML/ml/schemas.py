from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class ReceivedHop(BaseModel):
    hop: int
    from_host: str | None = None
    from_ip: str | None = None
    to_host: str | None = None
    timestamp: str | None = None


class AuthResults(BaseModel):
    spf: Literal["pass", "fail", "softfail", "none", "unknown"] = "none"
    dkim: Literal["pass", "fail", "none", "unknown"] = "none"
    dmarc: Literal["pass", "fail", "none", "unknown"] = "none"


class Attachment(BaseModel):
    filename: str
    content_type: str
    size_bytes: int


class ParsedEmail(BaseModel):
    message_id: str = ""
    from_address: str = ""
    from_display_name: str = ""
    reply_to: str | None = None
    to: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    body_html: str | None = None
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    auth_results: AuthResults | None = None
    headers_raw: dict[str, str] = Field(default_factory=dict)
    urls_in_body: list[str] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)


class Classification(BaseModel):
    label: str
    confidence: float
    all_scores: dict[str, float]


class FlaggedSpan(BaseModel):
    text: str
    start: int
    end: int
    reason: str
    weight: float


class TextAnalysis(BaseModel):
    flagged_spans: list[FlaggedSpan] = Field(default_factory=list)
    urgency_detected: bool = False
    impersonation_detected: bool = False
    financial_request: bool = False
    credential_request: bool = False


class Anomaly(BaseModel):
    feature: str
    value: str
    contribution: float


class HeaderAnalysis(BaseModel):
    anomalies: list[Anomaly] = Field(default_factory=list)
    auth_explanations: dict[str, str] = Field(default_factory=dict)


class UrlAnalysis(BaseModel):
    url: str
    malicious_prob: float
    flags: list[str] = Field(default_factory=list)


class IOCs(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    reply_to_addresses: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class Reason(BaseModel):
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    text: str


class ModelMetadata(BaseModel):
    text_mode: str
    model_versions: dict[str, str] = Field(default_factory=dict)
    latency_ms: float


class TowerScores(BaseModel):
    text: float = 0.0
    url: float = 0.0
    header: float = 0.0


class AnalysisResult(BaseModel):
    schema_version: str = "1.0"
    message_id: str
    fraud_score: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    classification: Classification
    threat_category: str
    tower_scores: TowerScores
    text_analysis: TextAnalysis
    header_analysis: HeaderAnalysis
    url_analysis: list[UrlAnalysis] = Field(default_factory=list)
    iocs: IOCs
    reasons: list[Reason] = Field(default_factory=list)
    model_metadata: ModelMetadata
    generated_at: str

    def to_canonical_dict(self) -> dict:
        d = self.model_dump()
        d["model_metadata"] = {**d["model_metadata"], "latency_ms": 0.0}
        d.pop("generated_at", None)
        return d

    def to_canonical_json(self) -> str:
        import json
        return json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":"))


LABELS = [
    "LEGITIMATE",
    "SUSPICIOUS",
    "PHISHING",
    "IMPERSONATION",
    "BEC_PAYMENT_DIVERSION",
    "CREDENTIAL_HARVESTING",
    "MALWARE_DELIVERY",
]
