"""
IOC Extractor: Extracts and normalizes URLs, IPs, Domains, and Emails from email content.
Uses Python standard library ipaddress for strict IP validation.
Zero external network calls are performed.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Tuple
from email.utils import parseaddr

from backend.models import IOCs


# Regular expressions for candidate extraction
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|hxxps?://|ftp://|www\d{0,3}\.)[^\s<>"'{}|\\^`\[\]]+)"""
)

# Potential IPv4: 4 octets separated by dots
IPV4_CANDIDATE_REGEX = re.compile(
    r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b"
)

# IPv6 candidate
IPV6_CANDIDATE_REGEX = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"
)

# Email address regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Characters that commonly attach to the end of URLs in natural text/HTML
TRAILING_PUNCTUATION = ".,;:!?)'\"<>[]`*\\"


def clean_url(raw_url: str) -> str:
    """Cleans leading and trailing punctuation, parentheses, and brackets from extracted URLs."""
    url = raw_url.strip()
    
    # Strip leading quotes, brackets, and angle brackets
    url = url.lstrip("<([\"'`")

    # Handle defanged scheme
    if url.lower().startswith("hxxp://"):
        url = "http://" + url[7:]
    elif url.lower().startswith("hxxps://"):
        url = "https://" + url[8:]
    elif url.lower().startswith("www."):
        url = "http://" + url

    # Strip trailing punctuation
    while url and url[-1] in TRAILING_PUNCTUATION:
        # Check if closing paren matches an opening paren in the URL
        if url[-1] == ")" and "(" in url:
            open_count = url.count("(")
            close_count = url.count(")")
            if open_count == close_count:
                break
        url = url[:-1]

    return url.strip()


def validate_ip_address(candidate: str) -> bool:
    """Validates an IP address using Python's ipaddress module."""
    if not candidate:
        return False
    try:
        ip = ipaddress.ip_address(candidate.strip())
        return True
    except ValueError:
        return False


def extract_domain_from_url(url: str) -> str:
    """Extracts hostname/domain from a normalized URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        return hostname.lower() if hostname else ""
    except Exception:
        return ""


def extract_iocs(
    plain_body: str,
    html_body: str,
    header_emails: List[str]
) -> IOCs:
    """
    Extracts, validates, de-duplicates, and normalizes IOCs from email headers and body.
    """
    combined_text = f"{plain_body}\n{html_body}"

    seen_urls: Set[str] = set()
    cleaned_urls: List[str] = []

    seen_ips: Set[str] = set()
    valid_ips: List[str] = []

    seen_domains: Set[str] = set()
    valid_domains: List[str] = []

    seen_emails: Set[str] = set()
    valid_emails: List[str] = []

    # 1. Extract and Clean URLs
    for match in URL_REGEX.finditer(combined_text):
        raw_url = match.group(0)
        c_url = clean_url(raw_url)
        if c_url and len(c_url) > 7 and c_url not in seen_urls:
            seen_urls.add(c_url)
            cleaned_urls.append(c_url)

            # Extract domain from URL
            domain = extract_domain_from_url(c_url)
            if domain and not validate_ip_address(domain):
                if domain not in seen_domains and "." in domain:
                    seen_domains.add(domain)
                    valid_domains.append(domain)

    # 2. Extract Validated IPv4 and IPv6 Addresses
    for match in IPV4_CANDIDATE_REGEX.finditer(combined_text):
        candidate = match.group(1)
        if validate_ip_address(candidate):
            # Avoid false positives like version numbers '1.0.0.0' or common timestamps if strictly invalid
            # Ensure each octet <= 255 (handled by ipaddress.ip_address)
            if candidate not in seen_ips:
                seen_ips.add(candidate)
                valid_ips.append(candidate)

    for match in IPV6_CANDIDATE_REGEX.finditer(combined_text):
        candidate = match.group(0)
        if validate_ip_address(candidate):
            if candidate not in seen_ips:
                seen_ips.add(candidate)
                valid_ips.append(candidate)

    # 3. Extract and Normalize Email Addresses
    # First include any header emails passed in
    for email_addr in header_emails:
        if email_addr:
            _, clean_addr = parseaddr(email_addr)
            clean_addr = clean_addr.strip().lower()
            if clean_addr and "@" in clean_addr:
                if clean_addr not in seen_emails:
                    seen_emails.add(clean_addr)
                    valid_emails.append(clean_addr)
                # Domain extraction
                domain = clean_addr.split("@")[-1]
                if domain and domain not in seen_domains and "." in domain:
                    seen_domains.add(domain)
                    valid_domains.append(domain)

    # Next scan body for email addresses
    for match in EMAIL_REGEX.finditer(combined_text):
        clean_addr = match.group(0).lower().strip()
        if clean_addr not in seen_emails:
            seen_emails.add(clean_addr)
            valid_emails.append(clean_addr)
            domain = clean_addr.split("@")[-1]
            if domain and domain not in seen_domains and "." in domain:
                seen_domains.add(domain)
                valid_domains.append(domain)

    return IOCs(
        urls=cleaned_urls,
        ips=valid_ips,
        domains=valid_domains,
        emails=valid_emails
    )
