"""
Tests for backend/analyzer.py and backend/main.py API endpoints.
"""

import pytest
import os
from fastapi.testclient import TestClient
from backend.main import app
from backend.analyzer import analyze_email_bytes
from backend.models import RiskClassification, AuthStatus

client = TestClient(app)

SAMPLE_EML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "samples",
    "suspicious_email.eml"
)


def test_get_root_health():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "SIH26106" in data["service"]
    assert "version" in data
    assert "timestamp" in data


def test_get_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"


def test_analyze_empty_file_fails():
    with pytest.raises(ValueError):
        analyze_email_bytes(b"")

    # Via API endpoint
    response = client.post(
        "/analyze",
        files={"file": ("empty.eml", b"", "message/rfc822")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_analyze_malformed_email():
    """Malformed emails should not crash the server and should produce structured response."""
    malformed_bytes = b"Some random garbage not conforming to RFC5322\n\nBody content."
    result = analyze_email_bytes(malformed_bytes, file_name="corrupted.eml")
    assert result.case_id.startswith("CASE-")
    assert result.metadata.parser_version == "1.0.0-prototype"


def test_analyze_suspicious_sample_email():
    assert os.path.exists(SAMPLE_EML_PATH), f"Sample file not found at {SAMPLE_EML_PATH}"
    with open(SAMPLE_EML_PATH, "rb") as f:
        eml_content = f.read()

    result = analyze_email_bytes(eml_content, file_name="suspicious_email.eml")

    # Verify Case ID
    assert result.case_id.startswith("CASE-")

    # Verify Email Metadata
    assert result.email.from_address == "ceo@legit-corp.example"
    assert result.email.reply_to == "finance-processing@external-secure-portal.xyz"
    assert "URGENT" in result.email.subject

    # Verify Authentication
    assert result.authentication.spf == AuthStatus.FAIL
    assert result.authentication.dkim == AuthStatus.FAIL
    assert result.authentication.dmarc == AuthStatus.FAIL

    # Verify IOCs
    assert any("198.51.100.42" in url for url in result.iocs.urls)
    assert "198.51.100.42" in result.iocs.ips
    assert "external-secure-portal.xyz" in result.iocs.domains

    # Verify Relay Path
    assert len(result.relay_path) == 3
    # First chronological hop
    assert result.relay_path[0].hop_number == 1
    assert result.relay_path[0].ip == "203.0.113.88"
    assert result.relay_path[0].ip_type == "documentation"
    assert result.relay_path[0].is_private_ip is False
    assert "RFC 5737" in result.relay_path[0].forensic_notes

    # Second hop
    assert result.relay_path[1].ip == "198.51.100.42"
    assert result.relay_path[1].ip_type == "documentation"
    assert result.relay_path[1].is_private_ip is False

    # Third hop
    assert result.relay_path[2].ip == "192.0.2.10"
    assert result.relay_path[2].ip_type == "documentation"
    assert result.relay_path[2].is_private_ip is False

    # Verify Risk Assessment
    assert result.risk.score >= 70
    assert result.risk.classification in (RiskClassification.HIGH_RISK, RiskClassification.CRITICAL_RISK)
    assert result.risk.scoring_type == "deterministic_rule_based_prototype"

    # Verify IP Intelligence placeholder
    assert result.risk.ip_intelligence.status == "unavailable"
    assert result.risk.ip_intelligence.provider == "none"


def test_post_analyze_api_endpoint():
    with open(SAMPLE_EML_PATH, "rb") as f:
        eml_bytes = f.read()

    response = client.post(
        "/analyze",
        files={"file": ("suspicious_email.eml", eml_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()

    assert "case_id" in data
    assert "email" in data
    assert "from" in data["email"]
    assert "authentication" in data
    assert data["authentication"]["spf"] == "FAIL"
    assert "iocs" in data
    assert len(data["iocs"]["urls"]) > 0
    assert "relay_path" in data
    assert len(data["relay_path"]) == 3
    assert "risk" in data
    assert data["risk"]["score"] >= 70
    assert "metadata" in data
    assert "analysis_timestamp" in data["metadata"]
