"""
Tests for backend/relay_parser.py
"""

import email
from email import policy
import pytest
from backend.relay_parser import (
    parse_relay_path,
    extract_ip_from_header,
    classify_ip_address,
    validate_ip
)


def test_classify_ip_address_all_categories():
    # 1. RFC 1918 Private IPv4 and IPv6 ULA
    for ip in ["10.0.0.1", "172.16.5.20", "192.168.1.254"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "rfc1918"
        assert is_priv is True
        assert "RFC 1918" in note

    cat, is_priv, note = classify_ip_address("fc00::1")
    assert cat == "rfc1918"
    assert is_priv is True

    # 2. Loopback
    for ip in ["127.0.0.1", "127.0.0.53", "::1"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "loopback"
        assert is_priv is False
        assert "Loopback" in note

    # 3. Link-Local
    for ip in ["169.254.10.5", "fe80::1"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "link-local"
        assert is_priv is False
        assert "Link-local" in note

    # 4. Documentation / Test Ranges (RFC 5737 / RFC 3849)
    for ip in ["192.0.2.10", "198.51.100.42", "203.0.113.88", "2001:db8::1"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "documentation"
        assert is_priv is False
        assert "RFC 5737" in note or "documentation" in note.lower()

    # 5. Reserved / Special-use (CGNAT, Multicast, Reserved)
    for ip in ["100.64.0.1", "224.0.0.1", "240.0.0.1"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "reserved"
        assert is_priv is False

    # 6. Public / Globally Routable
    for ip in ["8.8.8.8", "93.184.216.34", "142.250.190.46"]:
        cat, is_priv, note = classify_ip_address(ip)
        assert cat == "public"
        assert is_priv is False
        assert "Publicly routable" in note


def test_extract_ip_from_header():
    hdr1 = "from mail.sender.example (mail.sender.example [93.184.216.34]) by mx.receiver.example"
    assert extract_ip_from_header(hdr1) == "93.184.216.34"

    hdr2 = "from [10.0.0.5] by mail.internal.example"
    assert extract_ip_from_header(hdr2) == "10.0.0.5"

    hdr3 = "from localhost by mail.internal"
    assert extract_ip_from_header(hdr3) is None


def test_parse_relay_path_chronological_and_ip_types():
    raw_email = b"""Received: from mx-edge.victim.com (mx-edge.victim.com [93.184.216.34])
	by mailbox.victim.com (Postfix) with ESMTP id 333
	for <user@victim.com>; Sun, 6 Sep 2026 12:02:00 +0000 (UTC)
Received: from test-gateway.example (test-gateway.example [198.51.100.42])
	by mx-edge.victim.com (Postfix) with ESMTP id 222
	for <user@victim.com>; Sun, 6 Sep 2026 12:01:00 +0000 (UTC)
Received: from internal-client (internal-client [10.0.1.25])
	by test-gateway.example (Postfix) with ESMTP id 111
	for <user@victim.com>; Sun, 6 Sep 2026 12:00:00 +0000 (UTC)
From: sender@example.com
To: user@victim.com
Subject: Test Relay Ordering

Test Body
"""
    msg = email.message_from_bytes(raw_email, policy=policy.compat32)
    hops = parse_relay_path(msg)

    assert len(hops) == 3

    # Hop 1 (earliest hop, RFC1918 internal client: 10.0.1.25)
    assert hops[0].hop_number == 1
    assert hops[0].ip == "10.0.1.25"
    assert hops[0].ip_type == "rfc1918"
    assert hops[0].is_private_ip is True
    assert "RFC 1918" in hops[0].forensic_notes

    # Hop 2 (middle hop, RFC 5737 documentation test range: 198.51.100.42)
    assert hops[1].hop_number == 2
    assert hops[1].ip == "198.51.100.42"
    assert hops[1].ip_type == "documentation"
    assert hops[1].is_private_ip is False
    assert "RFC 5737" in hops[1].forensic_notes

    # Hop 3 (final border hop, public routable IP: 93.184.216.34)
    assert hops[2].hop_number == 3
    assert hops[2].ip == "93.184.216.34"
    assert hops[2].ip_type == "public"
    assert hops[2].is_private_ip is False
    assert "Publicly routable" in hops[2].forensic_notes

    # Check delays
    assert hops[1].delay_seconds == 60.0
    assert hops[2].delay_seconds == 60.0
