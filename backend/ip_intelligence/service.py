"""
IP Intelligence Service Layer.
Coordinates caching, special address bypass (RFC1918/Loopback/Documentation), and provider lookups.
"""

from typing import List, Dict, Optional
import ipaddress

from backend.ip_intelligence.models import IPIntelligenceResult
from backend.ip_intelligence.provider import BaseIPProvider, get_ip_provider
from backend.relay_parser import classify_ip_address


class IPIntelligenceService:
    """
    Enriches IP addresses with network infrastructure intelligence and geolocation context.
    Features in-memory caching and automatic non-routable IP classification bypass.
    """

    def __init__(self, provider: Optional[BaseIPProvider] = None):
        self.provider = provider or get_ip_provider()
        self._cache: Dict[str, IPIntelligenceResult] = {}

    def lookup_ip(self, ip_str: str) -> IPIntelligenceResult:
        """
        Looks up intelligence for an IP address.
        Non-public/private/documentation ranges are classified internally without calling external providers.
        """
        clean_ip = ip_str.strip("[]() \t\r\n")
        if not clean_ip:
            return IPIntelligenceResult(
                ip=ip_str,
                status="error",
                ip_type="invalid",
                source="validation_error"
            )

        # Check cache
        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Classify IP using standard address rules
        ip_type, is_private, note = classify_ip_address(clean_ip)

        # Handle non-routable IP classes locally without external calls
        if ip_type in ("rfc1918", "loopback", "link-local", "documentation", "reserved", "invalid"):
            status_map = {
                "rfc1918": "skipped_private",
                "loopback": "skipped_loopback",
                "link-local": "skipped_link_local",
                "documentation": "skipped_documentation",
                "reserved": "skipped_reserved",
                "invalid": "error",
            }
            result = IPIntelligenceResult(
                ip=clean_ip,
                status=status_map.get(ip_type, "unavailable"),
                ip_type=ip_type,
                source=f"internal_classification_{ip_type}",
                confidence="high" if ip_type != "invalid" else "none"
            )
            self._cache[clean_ip] = result
            return result

        # For public / globally routable IPs, delegate to configured provider
        try:
            result = self.provider.lookup_ip(clean_ip)
        except Exception as exc:
            result = IPIntelligenceResult(
                ip=clean_ip,
                status="error",
                ip_type="public",
                source="provider_error",
                confidence="none"
            )

        self._cache[clean_ip] = result
        return result

    def lookup_ips(self, ips: List[str]) -> List[IPIntelligenceResult]:
        """Batch lookup for a list of IP addresses, returning unique results in order."""
        seen = set()
        results = []
        for ip in ips:
            clean = ip.strip("[]() \t\r\n")
            if clean and clean not in seen:
                seen.add(clean)
                results.append(self.lookup_ip(clean))
        return results

    def clear_cache(self) -> None:
        """Clears the in-memory lookup cache."""
        self._cache.clear()
