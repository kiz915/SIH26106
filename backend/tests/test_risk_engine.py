"""
Tests for backend/risk_engine.py
"""

import pytest
from backend.models import (
    EmailMetadata,
    AuthResults,
    AuthStatus,
    IOCs,
    RelayHop,
    RiskClassification
)
from backend.risk_engine import (
    calculate_risk,
    evaluate_authentication_signals,
    evaluate_header_anomalies,
    evaluate_content_keywords
)


def test_clean_email_low_risk():
    meta = EmailMetadata(
        from_address="colleague@legit-company.com",
        to=["recipient@legit-company.com"],
        reply_to="colleague@legit-company.com",
        subject="Project Status Update",
        message_id="<msg-clean-123@legit-company.com>"
    )
    auth = AuthResults(
        spf=AuthStatus.PASS,
        dkim=AuthStatus.PASS,
        dmarc=AuthStatus.PASS
    )
    iocs = IOCs(
        urls=["https://internal.legit-company.com/wiki"],
        ips=["93.184.216.34"],
        domains=["legit-company.com"],
        emails=["colleague@legit-company.com"]
    )
    relay_hops = [
        RelayHop(hop_number=1, raw_header="Received: from mail.legit-company.com by mx.google.com")
    ]
    
    risk = calculate_risk(meta, auth, iocs, relay_hops, "Here is the weekly status report for our team.")
    assert risk.score <= 25
    assert risk.classification == RiskClassification.LOW_RISK


def test_missing_auth_does_not_penalize_as_fail():
    """Missing SPF/DKIM/DMARC (NONE/UNKNOWN) must not trigger failure penalties."""
    meta = EmailMetadata(
        from_address="newsletter@example.com",
        to=["user@example.com"],
        reply_to="newsletter@example.com",
        subject="Weekly Newsletter",
        message_id="<news-123@example.com>"
    )
    auth = AuthResults(
        spf=AuthStatus.NONE,
        dkim=AuthStatus.NONE,
        dmarc=AuthStatus.NONE
    )
    iocs = IOCs(urls=[], ips=[], domains=[], emails=[])
    relay_hops = [RelayHop(hop_number=1, raw_header="Received: from example.com by mx.example.com")]

    risk = calculate_risk(meta, auth, iocs, relay_hops, "Read our latest articles.")
    assert risk.score <= 25
    assert not any("AUTH_" in s.name for s in risk.signals)


def test_reply_to_mismatch_and_auth_fail():
    meta = EmailMetadata(
        from_address="ceo@mycompany.com",
        to=["finance@mycompany.com"],
        reply_to="ceo-personal@attacker-domain.xyz",
        subject="URGENT: Confidential Wire Transfer Payment",
        message_id="<fake-msg-1@attacker-domain.xyz>"
    )
    auth = AuthResults(
        spf=AuthStatus.FAIL,
        dkim=AuthStatus.FAIL,
        dmarc=AuthStatus.FAIL
    )
    iocs = IOCs(
        urls=["http://198.51.100.50/login", "https://phishing.xyz/auth"],
        ips=["198.51.100.50"],
        domains=["attacker-domain.xyz", "phishing.xyz"],
        emails=["ceo@mycompany.com", "ceo-personal@attacker-domain.xyz"]
    )
    relay_hops = [RelayHop(hop_number=1, raw_header="Received: from fake by mx")]

    body = "Immediate action required. Please execute the wire transfer and bank transfer immediately."
    risk = calculate_risk(meta, auth, iocs, relay_hops, body)

    assert risk.score >= 80
    assert risk.classification == RiskClassification.CRITICAL_RISK
    signal_names = [s.name for s in risk.signals]
    assert "AUTH_SPF_FAIL" in signal_names
    assert "AUTH_DKIM_FAIL" in signal_names
    assert "AUTH_DMARC_FAIL" in signal_names
    assert "REPLY_TO_DOMAIN_MISMATCH" in signal_names
    assert "RAW_IP_URL" in signal_names
    assert "URGENCY_LANGUAGE" in signal_names
    assert "FINANCIAL_BEC_LANGUAGE" in signal_names
