import re
from dataclasses import dataclass, asdict
from typing import Dict, Any
from config.config import HEADER_FEATURE_WEIGHTS

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

@dataclass
class HeaderFeatureResult:
    spf_fail: bool
    dkim_fail: bool
    dmarc_fail: bool
    sender_reply_to_mismatch: bool
    sender_domain_mismatch: bool
    suspicious_received_chain: bool
    details: Dict[str, str]
    score: float
    flags: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_domain(email_str: str) -> str:
    """Extracts the domain from an email address string like 'Name <user@domain.com>' or 'user@domain.com'"""
    if not email_str:
        return ""
    match = re.search(r'@([\w.-]+)', email_str)
    if match:
        return match.group(1).lower()
    return email_str.lower()


def extract_header_features(headers: dict, sender: str, authentication: dict) -> HeaderFeatureResult:
    """
    Extracts risk features from email headers and authentication metadata.
    """
    if headers is None:
        headers = {}
    if authentication is None:
        authentication = {}
    if sender is None:
        sender = ""

    spf_status = authentication.get('spf', '').lower()
    dkim_status = authentication.get('dkim', '').lower()
    dmarc_status = authentication.get('dmarc', '').lower()

    spf_fail = any(x in spf_status for x in ['fail', 'softfail', 'none']) if spf_status else False
    dkim_fail = any(x in dkim_status for x in ['fail', 'none']) if dkim_status else False
    dmarc_fail = any(x in dmarc_status for x in ['fail', 'none']) if dmarc_status else False

    sender_domain = _extract_domain(sender)
    
    reply_to = headers.get('Reply-To', '')
    reply_to_domain = _extract_domain(reply_to)
    sender_reply_to_mismatch = bool(sender_domain and reply_to_domain and sender_domain != reply_to_domain)

    from_header = headers.get('From', '')
    from_domain = _extract_domain(from_header)
    sender_domain_mismatch = bool(sender_domain and from_domain and sender_domain != from_domain)

    received_headers = headers.get('Received', [])
    if isinstance(received_headers, str):
        received_headers = [received_headers]

    suspicious_received_chain = False
    if len(received_headers) > 5:
        suspicious_received_chain = True
    
    details = {}
    if spf_fail:
        details['spf'] = f"SPF verification failed or missing: {spf_status or 'Not provided'}"
    if dkim_fail:
        details['dkim'] = f"DKIM verification failed or missing: {dkim_status or 'Not provided'}"
    if dmarc_fail:
        details['dmarc'] = f"DMARC verification failed or missing: {dmarc_status or 'Not provided'}"
    if sender_reply_to_mismatch:
        details['reply_to'] = f"Sender domain ({sender_domain}) does not match Reply-To domain ({reply_to_domain})"
    if sender_domain_mismatch:
        details['from_mismatch'] = f"Sender domain ({sender_domain}) does not match From domain ({from_domain})"
    if suspicious_received_chain:
        details['received'] = f"Suspicious Received chain ({len(received_headers)} hops)"

    flags = {
        'spf_fail': spf_fail,
        'dkim_fail': dkim_fail,
        'dmarc_fail': dmarc_fail,
        'sender_reply_to_mismatch': sender_reply_to_mismatch,
        'sender_domain_mismatch': sender_domain_mismatch,
        'suspicious_received_chain': suspicious_received_chain
    }

    score = 0.0
    total_weight = sum(HEADER_FEATURE_WEIGHTS.values()) if HEADER_FEATURE_WEIGHTS else 1.0
    if total_weight > 0:
        weighted_sum = sum(HEADER_FEATURE_WEIGHTS.get(f, 0.0) for f, val in flags.items() if val)
        score = (weighted_sum / total_weight) * 100.0
        score = max(0.0, min(100.0, score))

    return HeaderFeatureResult(
        spf_fail=spf_fail,
        dkim_fail=dkim_fail,
        dmarc_fail=dmarc_fail,
        sender_reply_to_mismatch=sender_reply_to_mismatch,
        sender_domain_mismatch=sender_domain_mismatch,
        suspicious_received_chain=suspicious_received_chain,
        details=details,
        score=score,
        flags=flags
    )
