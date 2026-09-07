"""Email preprocessing utilities."""

import re
from typing import NamedTuple
import logging

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class PreprocessedEmail(NamedTuple):
    subject: str
    body_text: str
    combined_text: str
    urls: list[str]
    ips: list[str]
    domains: list[str]
    reply_to_addresses: list[str]


def strip_html(html_content: str | None) -> str:
    """Remove HTML tags and return plain text."""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    return soup.get_text(separator=" ", strip=True)


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text."""
    return re.sub(r"\s+", " ", text).strip()


def assemble_combined_text(subject: str, body_text: str, max_tokens: int = 512) -> str:
    """Combine subject and body, truncated to max_tokens."""
    combined = f"{subject} [SEP] {body_text}"
    words = combined.split()
    if len(words) <= max_tokens:
        return combined
    return " ".join(words[:max_tokens])


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text using regex."""
    url_pattern = re.compile(
        r"https?://[^\s<>\"]+|www\.[^\s<>\"]+|[^\s<>\"]+\.(com|org|net|edu|gov|info|biz|xyz|tk|buzz|top|io|ai|co|us|uk|ca|au)[^\s<>\"]*",
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def extract_ips(text: str) -> list[str]:
    """Extract IP addresses from text."""
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    return list(set(ip_pattern.findall(text)))


def extract_domains(text: str) -> list[str]:
    """Extract domain names from email addresses and URLs."""
    domains = set()
    email_pattern = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]+", re.IGNORECASE)
    for match in email_pattern.findall(text):
        domains.add(match.lower())
    url_domain_pattern = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
    for match in url_domain_pattern.findall(text):
        domain = match.lower().rstrip('.')
        if domain:
            domains.add(domain)
    return list(domains)


def extract_reply_to_addresses(email_dict: dict) -> list[str]:
    """Extract reply-to addresses from email dict."""
    reply_to = email_dict.get("reply_to")
    if not reply_to:
        return []
    return [reply_to]


def preprocess_email(email_dict: dict) -> PreprocessedEmail:
    """
    Preprocess a ParsedEmail dict into structured text for analysis.
    
    Args:
        email_dict: ParsedEmail dict from Backend
        
    Returns:
        PreprocessedEmail namedtuple with cleaned text and extracted IoCs
    """
    subject = normalize_whitespace(email_dict.get("subject", ""))
    body_html = email_dict.get("body_html")
    body_text = email_dict.get("body_text", "")
    
    if body_html:
        body_text = strip_html(body_html)
    body_text = normalize_whitespace(body_text)
    
    combined_text = assemble_combined_text(subject, body_text)
    
    urls_in_body = email_dict.get("urls_in_body", [])
    text_for_url_extraction = f"{subject} {body_text}"
    extracted_urls = extract_urls(text_for_url_extraction)
    all_urls = list(set(urls_in_body + extracted_urls))
    
    extracted_ips = extract_ips(text_for_url_extraction)
    extracted_domains = extract_domains(text_for_url_extraction)
    url_domains = extract_domains(" ".join(all_urls))
    extracted_domains = list(set(extracted_domains + url_domains))
    reply_to_addresses = extract_reply_to_addresses(email_dict)
    
    return PreprocessedEmail(
        subject=subject,
        body_text=body_text,
        combined_text=combined_text,
        urls=all_urls,
        ips=extracted_ips,
        domains=extracted_domains,
        reply_to_addresses=reply_to_addresses
    )
