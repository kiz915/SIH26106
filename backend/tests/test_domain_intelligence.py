"""
Unit Tests for Domain Intelligence and DNS Forensic Lookup.
"""

import pytest
from backend.domain_intelligence import (
    DomainIntelligenceResult,
    DomainIntelligenceService,
)


def test_demo_domain_profile_lookup():
    service = DomainIntelligenceService()
    res = service.lookup_domain("example.com")

    assert res.domain == "example.com"
    assert res.status == "resolved"
    assert len(res.a_records) > 0
    assert "93.184.216.34" in res.a_records
    assert res.rdap_status == "synthetic_demo"
    assert res.is_synthetic is True
    assert res.source == "synthetic_demo"
    assert "Demo Profile" in res.registrar


def test_malformed_domain_syntax():
    service = DomainIntelligenceService()
    for bad in ["not-a-domain", "http://bad.com", "space domain.com", ""]:
        res = service.lookup_domain(bad)
        assert res.status == "skipped_invalid"
        assert res.is_synthetic is False
        assert res.rdap_status == "not_queried"
        assert res.error is not None


def test_custom_mock_resolver_success_and_failure():
    def mock_resolver(domain: str) -> DomainIntelligenceResult:
        if domain == "clean-company.org":
            return DomainIntelligenceResult(
                domain=domain,
                status="resolved",
                a_records=["192.0.2.1"],
                aaaa_records=[],
                mx_records=["10 mail.clean-company.org"],
                rdap_status="not_queried",
                source="mock_resolver",
                is_synthetic=False
            )
        else:
            return DomainIntelligenceResult(
                domain=domain,
                status="unresolved",
                rdap_status="not_queried",
                source="mock_resolver",
                is_synthetic=False,
                error="NXDOMAIN"
            )

    service = DomainIntelligenceService(dns_resolver=mock_resolver)

    # Success case
    res1 = service.lookup_domain("clean-company.org")
    assert res1.status == "resolved"
    assert res1.a_records == ["192.0.2.1"]
    assert res1.rdap_status == "not_queried"
    assert res1.is_synthetic is False

    # Failure case
    res2 = service.lookup_domain("nonexistent-test-123456.org")
    assert res2.status == "unresolved"
    assert res2.error == "NXDOMAIN"
    assert res2.rdap_status == "not_queried"


def test_domain_caching():
    service = DomainIntelligenceService()
    res1 = service.lookup_domain("external-secure-portal.xyz")
    res2 = service.lookup_domain("external-secure-portal.xyz")

    assert res1 is res2
    assert "external-secure-portal.xyz" in service._cache


def test_batch_lookup_domains():
    service = DomainIntelligenceService()
    domains = ["example.com", "secure-invoice-verification.xyz", "example.com"]
    results = service.lookup_domains(domains)

    assert len(results) == 2
    assert results[0].domain == "example.com"
    assert results[0].is_synthetic is True
    assert results[1].domain == "secure-invoice-verification.xyz"
    assert results[1].is_synthetic is True
