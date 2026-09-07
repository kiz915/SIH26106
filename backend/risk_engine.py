"""
Deterministic Forensic Risk Engine & Threat Signal Analyzer.
Evaluates email authentication, header anomalies, keyword triggers, and relay integrity.
Provides modular pluggable interfaces for AI/ML and IP intelligence integration.
"""

from typing import List, Optional, Tuple
from email.utils import parseaddr
import re
import ipaddress

from backend.models import (
    EmailMetadata,
    AuthResults,
    AuthStatus,
    IOCs,
    RelayHop,
    RiskAssessment,
    RiskClassification,
    RiskSignal,
    MLIntelligence,
    IPIntelligence
)


# Threat keywords with assigned categories and weights
URGENCY_KEYWORDS = [
    r"\burgent\b",
    r"\bimmediate action required\b",
    r"\baccount suspended\b",
    r"\bverify your account\b",
    r"\bsecurity alert\b",
    r"\bpassword expired\b",
    r"\bunauthorized access\b",
    r"\b24 hours to verify\b",
    r"\bfailure to respond\b",
]

FINANCIAL_BEC_KEYWORDS = [
    r"\bwire transfer\b",
    r"\bgift card\b",
    r"\bpayroll update\b",
    r"\bdirect deposit\b",
    r"\binvoice attached\b",
    r"\boverdue invoice\b",
    r"\bbank transfer\b",
    r"\bcrypto\b",
    r"\bbitcoin\b",
    r"\bconfidential transaction\b",
    r"\bpayment request\b",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".work", ".link", ".gq", ".ml", ".cf", ".ga", ".tk", ".ru", ".buzz", ".cam"
}


def get_domain_from_email(address: Optional[str]) -> Optional[str]:
    """Extracts domain part from an email address."""
    if not address:
        return None
    _, clean = parseaddr(address)
    if "@" in clean:
        return clean.split("@")[-1].strip().lower()
    return None


def evaluate_authentication_signals(auth: AuthResults) -> List[RiskSignal]:
    """
    Evaluates SPF, DKIM, and DMARC status.
    NOTE: Missing results (NONE/UNKNOWN) are NOT penalized as failures.
    """
    signals = []

    # SPF Evaluation
    if auth.spf == AuthStatus.FAIL:
        signals.append(RiskSignal(
            name="AUTH_SPF_FAIL",
            score_impact=20,
            severity="HIGH",
            description="SPF verification explicitly failed for the sender IP."
        ))

    # DKIM Evaluation
    if auth.dkim == AuthStatus.FAIL:
        signals.append(RiskSignal(
            name="AUTH_DKIM_FAIL",
            score_impact=15,
            severity="HIGH",
            description="DKIM cryptographic signature verification failed or was tampered."
        ))

    # DMARC Evaluation
    if auth.dmarc == AuthStatus.FAIL:
        signals.append(RiskSignal(
            name="AUTH_DMARC_FAIL",
            score_impact=25,
            severity="CRITICAL",
            description="DMARC alignment policy failed for the domain specified in From header. Indicates unaligned or unauthorized sender source."
        ))

    return signals


def evaluate_header_anomalies(email_meta: EmailMetadata) -> List[RiskSignal]:
    """Evaluates From vs Reply-To mismatches and header inconsistencies."""
    signals = []

    from_domain = get_domain_from_email(email_meta.from_address)
    reply_to_domain = get_domain_from_email(email_meta.reply_to)

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        signals.append(RiskSignal(
            name="REPLY_TO_DOMAIN_MISMATCH",
            score_impact=25,
            severity="HIGH",
            description=f"Reply-To domain '{reply_to_domain}' does not match From domain '{from_domain}'. Common BEC indicator."
        ))

    # Check Return-Path mismatch
    return_path_domain = get_domain_from_email(email_meta.return_path)
    if from_domain and return_path_domain and from_domain != return_path_domain:
        signals.append(RiskSignal(
            name="RETURN_PATH_MISMATCH",
            score_impact=10,
            severity="MEDIUM",
            description=f"Return-Path domain '{return_path_domain}' differs from From domain '{from_domain}'."
        ))

    # Missing Subject
    if not email_meta.subject or not email_meta.subject.strip():
        signals.append(RiskSignal(
            name="EMPTY_SUBJECT",
            score_impact=5,
            severity="LOW",
            description="Email has an empty or missing Subject header."
        ))

    # Missing Message-ID
    if not email_meta.message_id:
        signals.append(RiskSignal(
            name="MISSING_MESSAGE_ID",
            score_impact=10,
            severity="MEDIUM",
            description="Email is missing a standard RFC Message-ID header."
        ))

    return signals


def evaluate_ioc_signals(iocs: IOCs) -> List[RiskSignal]:
    """Evaluates IOC risks like raw IP hostnames in URLs and suspicious TLDs."""
    signals = []

    ip_url_count = 0
    suspicious_tld_count = 0

    for url in iocs.urls:
        # Check if URL uses raw IP address instead of domain name
        for ip in iocs.ips:
            if ip in url:
                ip_url_count += 1
                break

        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if tld in url.lower():
                suspicious_tld_count += 1
                break

    if ip_url_count > 0:
        signals.append(RiskSignal(
            name="RAW_IP_URL",
            score_impact=20,
            severity="HIGH",
            description=f"Detected {ip_url_count} URL(s) referencing raw IP addresses instead of legitimate hostnames."
        ))

    if suspicious_tld_count > 0:
        signals.append(RiskSignal(
            name="SUSPICIOUS_TLD_URL",
            score_impact=15,
            severity="MEDIUM",
            description=f"Detected {suspicious_tld_count} URL(s) with high-risk top-level domains ({', '.join(SUSPICIOUS_TLDS)})."
        ))

    return signals


def evaluate_content_keywords(subject: Optional[str], body: str) -> List[RiskSignal]:
    """Scans subject and body for urgency, credential harvesting, and financial BEC keywords."""
    signals = []
    text = f"{subject or ''}\n{body}".lower()

    found_urgency = []
    for pattern in URGENCY_KEYWORDS:
        if re.search(pattern, text):
            found_urgency.append(pattern.replace(r"\b", ""))

    if found_urgency:
        signals.append(RiskSignal(
            name="URGENCY_LANGUAGE",
            score_impact=15,
            severity="MEDIUM",
            description=f"Urgency / panic triggers detected: {', '.join(found_urgency[:3])}."
        ))

    found_financial = []
    for pattern in FINANCIAL_BEC_KEYWORDS:
        if re.search(pattern, text):
            found_financial.append(pattern.replace(r"\b", ""))

    if found_financial:
        signals.append(RiskSignal(
            name="FINANCIAL_BEC_LANGUAGE",
            score_impact=20,
            severity="HIGH",
            description=f"Financial / payment manipulation keywords detected: {', '.join(found_financial[:3])}."
        ))

    return signals


def evaluate_relay_signals(relay_hops: List[RelayHop]) -> List[RiskSignal]:
    """Forensic evaluation of relay path anomalies."""
    signals = []

    if not relay_hops:
        signals.append(RiskSignal(
            name="NO_RECEIVED_HEADERS",
            score_impact=15,
            severity="MEDIUM",
            description="No Received headers present; email relay provenance cannot be forensically traced."
        ))
    elif len(relay_hops) > 10:
        signals.append(RiskSignal(
            name="EXCESSIVE_RELAY_HOPS",
            score_impact=10,
            severity="LOW",
            description=f"Abnormally high relay count ({len(relay_hops)} hops), potential open relay or routing loop."
        ))

    return signals


def get_default_ip_intelligence() -> IPIntelligence:
    """
    Default IP Intelligence interface placeholder.
    Explicitly reports 'unavailable' and 'none' provider per requirements.
    """
    return IPIntelligence(
        status="unavailable",
        provider="none",
        country=None,
        region=None,
        city=None,
        asn=None,
        isp=None,
        is_hosting=None,
        is_vpn_tor=None,
        disclaimer="IP geolocation reflects network infrastructure routing, not physical attacker identity."
    )


def calculate_risk(
    email_meta: EmailMetadata,
    auth: AuthResults,
    iocs: IOCs,
    relay_hops: List[RelayHop],
    plain_body: str,
    ml_signals: Optional[MLIntelligence] = None,
    ip_intel: Optional[IPIntelligence] = None
) -> RiskAssessment:
    """
    Calculates deterministic prototype forensic risk score (0-100) and maps to risk tiers.
    """
    signals: List[RiskSignal] = []

    # Gather all rule signals
    signals.extend(evaluate_authentication_signals(auth))
    signals.extend(evaluate_header_anomalies(email_meta))
    signals.extend(evaluate_ioc_signals(iocs))
    signals.extend(evaluate_content_keywords(email_meta.subject, plain_body))
    signals.extend(evaluate_relay_signals(relay_hops))

    # Calculate raw sum score
    total_score = sum(s.score_impact for s in signals)

    # Cap score strictly between 0 and 100
    capped_score = max(0, min(100, total_score))

    # Classify risk level
    if capped_score <= 25:
        classification = RiskClassification.LOW_RISK
    elif capped_score <= 55:
        classification = RiskClassification.MEDIUM_RISK
    elif capped_score <= 80:
        classification = RiskClassification.HIGH_RISK
    else:
        classification = RiskClassification.CRITICAL_RISK

    # Human-readable forensic reasons
    reasons = [s.description for s in signals]
    if not reasons:
        reasons.append("No suspicious forensic signals or authentication anomalies detected.")

    return RiskAssessment(
        score=capped_score,
        classification=classification,
        reasons=reasons,
        signals=signals,
        scoring_type="deterministic_rule_based_prototype",
        ml_signals=ml_signals,
        ip_intelligence=ip_intel or get_default_ip_intelligence()
    )
