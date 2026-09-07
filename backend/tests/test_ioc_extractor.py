"""
Tests for backend/ioc_extractor.py
"""

import pytest
from backend.ioc_extractor import clean_url, validate_ip_address, extract_iocs


def test_clean_url():
    assert clean_url("https://example.com/login.") == "https://example.com/login"
    assert clean_url("https://example.com/path,") == "https://example.com/path"
    assert clean_url("https://example.com/test)") == "https://example.com/test"
    assert clean_url("<https://example.com/link>") == "https://example.com/link"
    assert clean_url("hxxps://bad-domain.xyz/login") == "https://bad-domain.xyz/login"
    assert clean_url("www.example.org/page") == "http://www.example.org/page"


def test_validate_ip_address():
    # Valid IPv4
    assert validate_ip_address("192.168.1.1") is True
    assert validate_ip_address("8.8.8.8") is True
    assert validate_ip_address("198.51.100.25") is True

    # Invalid IPv4 (out of bounds octet)
    assert validate_ip_address("300.1.1.1") is False
    assert validate_ip_address("192.168.1.999") is False
    assert validate_ip_address("1.2.3") is False
    assert validate_ip_address("abc.def.ghi.jkl") is False

    # Valid IPv6
    assert validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert validate_ip_address("::1") is True


def test_extract_iocs():
    plain = """
    Please check https://legit-portal.com/update and http://198.51.100.50/admin?id=12.
    Contact security@legit-portal.com or analyst@defense.example.
    Server IP: 203.0.113.195 and invalid IP: 999.123.456.789.
    """
    html = '<p>Click <a href="https://phishing-site.xyz/confirm">here</a></p>'
    header_emails = ["sender@corporate.com", "recipient@target.com"]

    iocs = extract_iocs(plain, html, header_emails)

    # Verify URLs
    assert "https://legit-portal.com/update" in iocs.urls
    assert "http://198.51.100.50/admin?id=12" in iocs.urls
    assert "https://phishing-site.xyz/confirm" in iocs.urls

    # Verify IPs (invalid should NOT be in ips)
    assert "198.51.100.50" in iocs.ips
    assert "203.0.113.195" in iocs.ips
    assert "999.123.456.789" not in iocs.ips

    # Verify Domains
    assert "legit-portal.com" in iocs.domains
    assert "phishing-site.xyz" in iocs.domains
    assert "corporate.com" in iocs.domains

    # Verify Emails
    assert "security@legit-portal.com" in iocs.emails
    assert "sender@corporate.com" in iocs.emails
