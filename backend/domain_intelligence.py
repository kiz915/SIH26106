"""
Domain Intelligence & DNS Forensic Investigation Service.
Performs safe DNS resolution (A, AAAA, MX, NS, TXT) and RDAP metadata abstraction.
Strictly avoids scraping WHOIS web pages and never follows URLs or downloads webpage content.
"""

import socket
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Explicitly labeled demo profiles for simulated testbeds
DEMO_DOMAIN_PROFILES = {
    "example.com": {
        "status": "resolved",
        "a_records": ["93.184.216.34"],
        "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
        "mx_records": ["0 ."],
        "ns_records": ["a.iana-servers.net", "b.iana-servers.net"],
        "txt_records": ["v=spf1 -all"],
        "rdap_status": "synthetic_demo",
        "registrar": "Internet Assigned Numbers Authority (Demo Profile)",
        "registration_date": "1995-08-14T04:00:00Z",
        "expiration_date": None,
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        "source": "synthetic_demo",
        "is_synthetic": True,
    },
    "external-secure-portal.xyz": {
        "status": "resolved",
        "a_records": ["198.51.100.42"],
        "aaaa_records": [],
        "mx_records": ["10 mail.external-secure-portal.xyz"],
        "ns_records": ["ns1.external-secure-portal.xyz"],
        "txt_records": ["v=spf1 ip4:198.51.100.42 ~all"],
        "rdap_status": "synthetic_demo",
        "registrar": "Suspicious TLD Registrar LLC (Demo Profile)",
        "registration_date": "2026-09-01T10:00:00Z",
        "expiration_date": "2027-09-01T10:00:00Z",
        "nameservers": ["ns1.external-secure-portal.xyz"],
        "source": "synthetic_demo",
        "is_synthetic": True,
    },
    "secure-invoice-verification.xyz": {
        "status": "resolved",
        "a_records": ["198.51.100.42"],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": ["ns1.external-secure-portal.xyz"],
        "txt_records": [],
        "rdap_status": "synthetic_demo",
        "registrar": "Suspicious TLD Registrar LLC (Demo Profile)",
        "registration_date": "2026-09-05T08:00:00Z",
        "expiration_date": "2027-09-05T08:00:00Z",
        "nameservers": ["ns1.external-secure-portal.xyz"],
        "source": "synthetic_demo",
        "is_synthetic": True,
    }
}


class DomainIntelligenceResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    domain: str = Field(..., description="Target domain evaluated")
    status: str = Field(
        ...,
        description="Lookup status: resolved | unresolved | error | skipped_invalid"
    )
    a_records: List[str] = Field(default_factory=list, description="Resolved IPv4 (A) addresses")
    aaaa_records: List[str] = Field(default_factory=list, description="Resolved IPv6 (AAAA) addresses")
    mx_records: List[str] = Field(default_factory=list, description="Mail Exchanger (MX) records")
    ns_records: List[str] = Field(default_factory=list, description="Authoritative Name Server (NS) records")
    txt_records: List[str] = Field(default_factory=list, description="TXT / SPF verification records")
    rdap_status: str = Field(
        default="not_queried",
        description="RDAP registration query status: not_queried | synthetic_demo | unavailable | available"
    )
    registrar: Optional[str] = Field(default=None, description="Domain registrar name")
    registration_date: Optional[str] = Field(default=None, description="ISO timestamp of domain registration")
    expiration_date: Optional[str] = Field(default=None, description="ISO timestamp of domain expiration")
    nameservers: List[str] = Field(default_factory=list, description="Identified nameservers")
    source: Optional[str] = Field(default=None, description="Intelligence source or protocol")
    is_synthetic: bool = Field(default=False, description="True if domain intelligence is generated demo/synthetic data")
    error: Optional[str] = Field(default=None, description="Error message if resolution failed")


class DomainIntelligenceService:
    """
    Forensic domain intelligence service.
    Performs safe DNS resolution and caches responses in memory.
    """

    def __init__(self, dns_resolver=None):
        self._cache: Dict[str, DomainIntelligenceResult] = {}
        self._custom_resolver = dns_resolver

    def is_valid_domain(self, domain: str) -> bool:
        """Validates if candidate string matches standard domain syntax."""
        if not domain or len(domain) > 253:
            return False
        clean = domain.strip().lower()
        return bool(DOMAIN_REGEX.match(clean))

    def _resolve_standard_dns(self, domain: str) -> DomainIntelligenceResult:
        """Resolves DNS using standard socket library with timeout bounds."""
        a_records: List[str] = []
        aaaa_records: List[str] = []

        try:
            # Set default timeout for socket operations
            orig_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3.0)
            try:
                # 1. Resolve IPv4 (A records)
                for res in socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM):
                    ip = res[4][0]
                    if ip not in a_records:
                        a_records.append(ip)
            except (socket.gaierror, socket.herror, TimeoutError):
                pass

            try:
                # 2. Resolve IPv6 (AAAA records)
                for res in socket.getaddrinfo(domain, 80, socket.AF_INET6, socket.SOCK_STREAM):
                    ip = res[4][0]
                    if ip not in aaaa_records:
                        aaaa_records.append(ip)
            except (socket.gaierror, socket.herror, TimeoutError):
                pass
            finally:
                socket.setdefaulttimeout(orig_timeout)

            if a_records or aaaa_records:
                return DomainIntelligenceResult(
                    domain=domain,
                    status="resolved",
                    a_records=a_records,
                    aaaa_records=aaaa_records,
                    rdap_status="not_queried",
                    source="dns_standard_socket",
                    is_synthetic=False
                )
            else:
                return DomainIntelligenceResult(
                    domain=domain,
                    status="unresolved",
                    rdap_status="not_queried",
                    source="dns_standard_socket",
                    is_synthetic=False,
                    error="Domain could not be resolved to any IP address."
                )
        except Exception as exc:
            return DomainIntelligenceResult(
                domain=domain,
                status="error",
                rdap_status="not_queried",
                source="dns_standard_socket",
                is_synthetic=False,
                error=f"DNS resolution failure: {str(exc)}"
            )

    def lookup_domain(self, domain_str: str) -> DomainIntelligenceResult:
        """
        Retrieves DNS and infrastructure intelligence for a single domain.
        Uses in-memory caching to avoid redundant queries.
        """
        clean_domain = domain_str.strip().lower()

        if not clean_domain or not self.is_valid_domain(clean_domain):
            return DomainIntelligenceResult(
                domain=domain_str,
                status="skipped_invalid",
                rdap_status="not_queried",
                is_synthetic=False,
                error="Invalid domain syntax or format."
            )

        # Check in-memory cache
        if clean_domain in self._cache:
            return self._cache[clean_domain]

        # Check demo / testbed profile
        if clean_domain in DEMO_DOMAIN_PROFILES:
            prof = DEMO_DOMAIN_PROFILES[clean_domain]
            result = DomainIntelligenceResult(
                domain=clean_domain,
                status=prof["status"],
                a_records=prof.get("a_records", []),
                aaaa_records=prof.get("aaaa_records", []),
                mx_records=prof.get("mx_records", []),
                ns_records=prof.get("ns_records", []),
                txt_records=prof.get("txt_records", []),
                rdap_status=prof.get("rdap_status", "synthetic_demo"),
                registrar=prof.get("registrar"),
                registration_date=prof.get("registration_date"),
                expiration_date=prof.get("expiration_date"),
                nameservers=prof.get("nameservers", []),
                source=prof.get("source", "synthetic_demo"),
                is_synthetic=prof.get("is_synthetic", True)
            )
            self._cache[clean_domain] = result
            return result

        # Use custom injected resolver (for unit tests) or standard DNS
        if self._custom_resolver:
            result = self._custom_resolver(clean_domain)
        else:
            result = self._resolve_standard_dns(clean_domain)

        self._cache[clean_domain] = result
        return result

    def lookup_domains(self, domains: List[str]) -> List[DomainIntelligenceResult]:
        """Batch lookup for a list of domains, preserving unique order."""
        seen = set()
        results = []
        for d in domains:
            clean = d.strip().lower()
            if clean and clean not in seen:
                seen.add(clean)
                results.append(self.lookup_domain(clean))
        return results

    def clear_cache(self) -> None:
        """Clears the domain resolution cache."""
        self._cache.clear()
