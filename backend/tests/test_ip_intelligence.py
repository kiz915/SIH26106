"""
Unit Tests for IP Intelligence and Network Infrastructure Geolocation.
Tests RFC1918 bypass, loopback bypass, documentation bypass, mock provider, synthetic indicators, caching, and error resilience.
"""

import pytest
from backend.ip_intelligence.models import IPIntelligenceResult
from backend.ip_intelligence.provider import BaseIPProvider, UnavailableIPProvider, get_ip_provider
from backend.ip_intelligence.mock_provider import MockIPIntelligenceProvider
from backend.ip_intelligence.service import IPIntelligenceService


class ErrorThrowingIPProvider(BaseIPProvider):
    """Test stub simulating network timeout or provider crash."""
    def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        raise TimeoutError("External API timed out after 3.0s")


def test_public_ip_lookup_mock_provider():
    service = IPIntelligenceService(MockIPIntelligenceProvider())
    res = service.lookup_ip("8.8.8.8")

    assert res.ip == "8.8.8.8"
    assert res.status == "available"
    assert res.ip_type == "public"
    assert res.country == "United States"
    assert res.country_code == "US"
    assert res.asn == "AS15169"
    assert res.organization == "Google LLC"
    assert res.is_datacenter is True
    # Explicit synthetic indicators
    assert res.source == "synthetic_demo"
    assert res.confidence == "simulated"
    assert res.is_synthetic is True
    assert "attacker" not in res.disclaimer.lower() or "does not establish" in res.disclaimer.lower()


def test_generic_mock_ip_lookup_has_synthetic_flag():
    service = IPIntelligenceService(MockIPIntelligenceProvider())
    res = service.lookup_ip("198.51.100.1")  # Treated as public if passed directly to provider
    prov_res = MockIPIntelligenceProvider().lookup_ip("198.51.100.1")
    assert prov_res.is_synthetic is True
    assert prov_res.source == "synthetic_demo"
    assert prov_res.confidence == "simulated"


def test_rfc1918_private_ip_bypasses_external_lookup():
    """RFC1918 private IPs must be classified internally without calling external provider."""
    service = IPIntelligenceService(ErrorThrowingIPProvider())
    
    for ip in ["10.0.1.25", "172.16.5.1", "192.168.1.1"]:
        res = service.lookup_ip(ip)
        assert res.ip == ip
        assert res.status == "skipped_private"
        assert res.ip_type == "rfc1918"
        assert res.country is None
        assert res.is_synthetic is False
        assert "rfc1918" in res.source.lower()


def test_loopback_ip_bypasses_external_lookup():
    service = IPIntelligenceService(ErrorThrowingIPProvider())
    for ip in ["127.0.0.1", "::1"]:
        res = service.lookup_ip(ip)
        assert res.status == "skipped_loopback"
        assert res.ip_type == "loopback"
        assert res.country is None
        assert res.is_synthetic is False


def test_documentation_test_ip_bypasses_external_lookup():
    """RFC 5737 / RFC 3849 testbed IPs must be recognized as documentation."""
    service = IPIntelligenceService(ErrorThrowingIPProvider())
    for ip in ["192.0.2.10", "198.51.100.42", "203.0.113.88", "2001:db8::1"]:
        res = service.lookup_ip(ip)
        assert res.status == "skipped_documentation"
        assert res.ip_type == "documentation"
        assert res.country is None
        assert res.is_synthetic is False


def test_invalid_ip_format():
    service = IPIntelligenceService(MockIPIntelligenceProvider())
    res = service.lookup_ip("999.999.999.999")
    assert res.status == "error"
    assert res.ip_type == "invalid"
    assert res.is_synthetic is False


def test_unavailable_provider():
    service = IPIntelligenceService(UnavailableIPProvider())
    res = service.lookup_ip("93.184.216.34")
    assert res.status == "unavailable"
    assert res.source == "none"
    assert res.is_synthetic is False


def test_provider_error_and_timeout_resilience():
    """If provider throws timeout/HTTP error, service must return structured error result gracefully."""
    service = IPIntelligenceService(ErrorThrowingIPProvider())
    res = service.lookup_ip("93.184.216.34")
    assert res.status == "error"
    assert res.ip_type == "public"
    assert res.source == "provider_error"
    assert res.is_synthetic is False


def test_in_memory_caching():
    mock_prov = MockIPIntelligenceProvider()
    service = IPIntelligenceService(mock_prov)

    # First lookup
    res1 = service.lookup_ip("1.1.1.1")
    # Second lookup should return cached object
    res2 = service.lookup_ip("1.1.1.1")
    assert res1 is res2
    assert "1.1.1.1" in service._cache


def test_batch_lookup_ips():
    service = IPIntelligenceService(MockIPIntelligenceProvider())
    ips = ["8.8.8.8", "10.0.0.1", "198.51.100.42", "8.8.8.8"]
    results = service.lookup_ips(ips)

    # Should deduplicate preserving order
    assert len(results) == 3
    assert results[0].ip == "8.8.8.8"
    assert results[0].status == "available"
    assert results[0].is_synthetic is True
    assert results[1].ip == "10.0.0.1"
    assert results[1].status == "skipped_private"
    assert results[2].ip == "198.51.100.42"
    assert results[2].status == "skipped_documentation"
