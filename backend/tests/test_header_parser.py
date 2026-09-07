"""
Tests for backend/header_parser.py
"""

import pytest
from backend.header_parser import parse_email_headers, extract_clean_address, extract_address_list, decode_mime_header
from backend.models import AuthStatus


def test_decode_mime_header():
    # Plain text
    assert decode_mime_header("Simple Subject") == "Simple Subject"
    assert decode_mime_header(None) is None
    # RFC 2047 encoded
    encoded = "=?UTF-8?B?U2VjdXJpdHkgQWxlcnQ=?="
    assert decode_mime_header(encoded) == "Security Alert"


def test_extract_clean_address():
    assert extract_clean_address('"John Doe" <john.doe@example.com>') == "john.doe@example.com"
    assert extract_clean_address("admin@domain.com") == "admin@domain.com"
    assert extract_clean_address(None) is None


def test_extract_address_list():
    raw = "alice@example.com, Bob Smith <bob@example.com>, <charlie@example.com>"
    addrs = extract_address_list(raw)
    assert addrs == ["alice@example.com", "bob@example.com", "charlie@example.com"]


def test_missing_auth_headers_returns_none_not_fail():
    """Missing Authentication-Results must NOT automatically become FAIL."""
    raw_email = b"""From: sender@example.com
To: recipient@example.com
Subject: Friendly Update
Date: Sun, 6 Sep 2026 12:00:00 +0000
Message-ID: <12345@example.com>

Hello world, this is a plain message without any authentication headers.
"""
    meta, auth, plain, html, _ = parse_email_headers(raw_email)
    assert auth.spf == AuthStatus.NONE
    assert auth.dkim == AuthStatus.NONE
    assert auth.dmarc == AuthStatus.NONE
    assert auth.spf != AuthStatus.FAIL
    assert meta.from_address == "sender@example.com"
    assert "Friendly Update" in meta.subject


def test_auth_headers_pass():
    raw_email = b"""Authentication-Results: mx.example.com;
 spf=pass (sender IP 93.184.216.34) smtp.mailfrom=sender@example.com;
 dkim=pass header.d=example.com;
 dmarc=pass action=none header.from=example.com
From: sender@example.com
To: recipient@example.com
Subject: Verified Email
Message-ID: <msg-pass-1@example.com>

Legitimate email with passing auth.
"""
    meta, auth, plain, html, _ = parse_email_headers(raw_email)
    assert auth.spf == AuthStatus.PASS
    assert auth.dkim == AuthStatus.PASS
    assert auth.dmarc == AuthStatus.PASS


def test_auth_headers_fail():
    raw_email = b"""Authentication-Results: mx.example.com;
 spf=fail smtp.mailfrom=spoofed@victim.com;
 dkim=fail header.d=victim.com;
 dmarc=fail header.from=victim.com
From: spoofed@victim.com
To: recipient@example.com
Subject: Spoofed Email
Message-ID: <msg-fail-1@example.com>

Malicious email.
"""
    meta, auth, plain, html, _ = parse_email_headers(raw_email)
    assert auth.spf == AuthStatus.FAIL
    assert auth.dkim == AuthStatus.FAIL
    assert auth.dmarc == AuthStatus.FAIL
