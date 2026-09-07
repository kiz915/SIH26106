"""
Email header parser and authentication validator.
Parses RFC 5322/2047 headers, addresses, and evaluates SPF/DKIM/DMARC status.
"""

import email
from email import policy
from email.header import decode_header, make_header
from email.utils import parseaddr, getaddresses
from typing import Tuple, List, Dict, Any, Optional
import re

from backend.models import EmailMetadata, AuthResults, AuthStatus


def decode_mime_header(header_value: Optional[str]) -> Optional[str]:
    """Safely decodes RFC 2047 encoded email headers."""
    if not header_value:
        return None
    try:
        decoded = decode_header(header_value)
        return str(make_header(decoded)).strip()
    except Exception:
        return str(header_value).strip()


def extract_clean_address(raw_header: Optional[str]) -> Optional[str]:
    """Extracts raw email address from a header value using parseaddr."""
    if not raw_header:
        return None
    _, addr = parseaddr(raw_header)
    return addr.strip().lower() if addr else None


def extract_address_list(raw_header: Optional[str]) -> List[str]:
    """Extracts list of clean email addresses from a multi-address header."""
    if not raw_header:
        return []
    addresses = getaddresses([raw_header])
    result = []
    for _, addr in addresses:
        clean = addr.strip().lower()
        if clean and clean not in result:
            result.append(clean)
    return result


def extract_body(msg: email.message.EmailMessage) -> Tuple[str, str]:
    """
    Safely extracts plain-text and HTML body content from an EmailMessage.
    Never executes or evaluates scripts or external resources.
    """
    plain_parts = []
    html_parts = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition.lower():
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")

                    if content_type == "text/plain":
                        plain_parts.append(text)
                    elif content_type == "text/html":
                        html_parts.append(text)
                except Exception:
                    continue
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_parts.append(text)
                else:
                    plain_parts.append(text)
    except Exception:
        pass

    plain_body = "\n".join(plain_parts).strip()
    html_body = "\n".join(html_parts).strip()

    # If no plain text exists but HTML does, produce a basic stripped version for preview
    if not plain_body and html_body:
        # Strip script and style tags, then basic HTML tags
        clean_text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r"<[^>]+>", " ", clean_text)
        plain_body = re.sub(r"\s+", " ", clean_text).strip()

    return plain_body, html_body


def parse_authentication_headers(msg: email.message.EmailMessage) -> AuthResults:
    """
    Interprets SPF, DKIM, and DMARC results from Authentication-Results,
    Received-SPF, DKIM-Signature, and ARC headers.
    
    IMPORTANT:
    - Missing Authentication-Results MUST NOT automatically become FAIL.
    - If no auth headers are found, status is NONE or UNKNOWN.
    """
    auth_headers = msg.get_all("Authentication-Results", [])
    received_spf_headers = msg.get_all("Received-SPF", [])
    dkim_signatures = msg.get_all("DKIM-Signature", [])
    arc_results = msg.get_all("ARC-Authentication-Results", [])

    all_raw_auth = []
    for h in auth_headers:
        all_raw_auth.append(f"Authentication-Results: {h}")
    for h in received_spf_headers:
        all_raw_auth.append(f"Received-SPF: {h}")
    for h in arc_results:
        all_raw_auth.append(f"ARC-Authentication-Results: {h}")

    spf_status = AuthStatus.UNKNOWN
    dkim_status = AuthStatus.UNKNOWN
    dmarc_status = AuthStatus.UNKNOWN
    details: Dict[str, Any] = {}

    has_any_auth_header = bool(auth_headers or received_spf_headers or arc_results or dkim_signatures)

    if not has_any_auth_header:
        # Explicit requirement: Missing headers must NOT be FAIL
        return AuthResults(
            spf=AuthStatus.NONE,
            dkim=AuthStatus.NONE,
            dmarc=AuthStatus.NONE,
            raw_results=[],
            details={"note": "No authentication headers present in email message"}
        )

    # 1. Parse Authentication-Results (and ARC-Authentication-Results as secondary)
    combined_auth_text = " ".join(auth_headers + arc_results).lower()

    # SPF parsing
    if "spf=" in combined_auth_text:
        match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror|unknown)", combined_auth_text)
        if match:
            res = match.group(1)
            details["spf_auth_result"] = res
            if res == "pass":
                spf_status = AuthStatus.PASS
            elif res in ("fail", "softfail", "permerror"):
                spf_status = AuthStatus.FAIL
            elif res == "none":
                spf_status = AuthStatus.NONE
            else:
                spf_status = AuthStatus.UNKNOWN
    elif received_spf_headers:
        spf_line = received_spf_headers[0].lower()
        details["received_spf_header"] = received_spf_headers[0]
        if spf_line.startswith("pass"):
            spf_status = AuthStatus.PASS
        elif spf_line.startswith(("fail", "softfail", "permerror")):
            spf_status = AuthStatus.FAIL
        elif spf_line.startswith("none"):
            spf_status = AuthStatus.NONE
        else:
            spf_status = AuthStatus.UNKNOWN
    else:
        spf_status = AuthStatus.NONE

    # DKIM parsing
    if "dkim=" in combined_auth_text:
        match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror|unknown)", combined_auth_text)
        if match:
            res = match.group(1)
            details["dkim_auth_result"] = res
            if res == "pass":
                dkim_status = AuthStatus.PASS
            elif res in ("fail", "permerror"):
                dkim_status = AuthStatus.FAIL
            elif res == "none":
                dkim_status = AuthStatus.NONE
            else:
                dkim_status = AuthStatus.UNKNOWN
    elif dkim_signatures:
        # Signature is present on message, but no Authentication-Results verification header found
        dkim_status = AuthStatus.UNKNOWN
        details["dkim_signature_present"] = True
    else:
        dkim_status = AuthStatus.NONE

    # DMARC parsing
    if "dmarc=" in combined_auth_text:
        match = re.search(r"dmarc=(pass|fail|temperror|permerror|none|unknown)", combined_auth_text)
        if match:
            res = match.group(1)
            details["dmarc_auth_result"] = res
            if res == "pass":
                dmarc_status = AuthStatus.PASS
            elif res in ("fail", "permerror"):
                dmarc_status = AuthStatus.FAIL
            elif res == "none":
                dmarc_status = AuthStatus.NONE
            else:
                dmarc_status = AuthStatus.UNKNOWN
    else:
        # If DMARC header not explicitly present
        dmarc_status = AuthStatus.NONE

    return AuthResults(
        spf=spf_status,
        dkim=dkim_status,
        dmarc=dmarc_status,
        raw_results=all_raw_auth,
        details=details
    )


def parse_email_headers(raw_bytes: bytes) -> Tuple[EmailMetadata, AuthResults, str, str, email.message.EmailMessage]:
    """
    Main entry point for parsing raw email bytes into structured metadata and auth results.
    Returns: (EmailMetadata, AuthResults, plain_body, html_body, raw_msg_obj)
    """
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)
    except Exception as exc:
        raise ValueError(f"Failed to parse email structure: {str(exc)}")

    # Extract headers
    from_raw = decode_mime_header(msg.get("From"))
    to_raw = decode_mime_header(msg.get("To"))
    cc_raw = decode_mime_header(msg.get("Cc"))
    reply_to_raw = decode_mime_header(msg.get("Reply-To"))
    return_path_raw = decode_mime_header(msg.get("Return-Path"))
    subject = decode_mime_header(msg.get("Subject"))
    message_id = msg.get("Message-ID", "").strip() or None
    date = msg.get("Date", "").strip() or None
    content_type = msg.get_content_type()

    # Extract clean addresses
    from_clean = extract_clean_address(from_raw) or from_raw
    to_list = extract_address_list(to_raw)
    if not to_list and to_raw:
        to_list = [to_raw.strip()]
    cc_list = extract_address_list(cc_raw)
    reply_to_clean = extract_clean_address(reply_to_raw) or reply_to_raw
    return_path_clean = extract_clean_address(return_path_raw) or return_path_raw

    # Extract bodies
    plain_body, html_body = extract_body(msg)
    preview = (plain_body[:500] + "...") if len(plain_body) > 500 else plain_body

    email_metadata = EmailMetadata(
        from_address=from_clean,
        to=to_list,
        cc=cc_list,
        reply_to=reply_to_clean,
        return_path=return_path_clean,
        subject=subject,
        message_id=message_id,
        date=date,
        content_type=content_type,
        body_preview=preview if preview else None
    )

    auth_results = parse_authentication_headers(msg)

    return email_metadata, auth_results, plain_body, html_body, msg
