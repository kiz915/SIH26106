"""
Abstract Provider Interface and Factory for IP Intelligence.
Ensures provider-agnostic extensibility without hardcoding vendors.
"""

from abc import ABC, abstractmethod
import os
import httpx
import logging
from typing import Optional
from .models import IPIntelligenceResult

logger = logging.getLogger("backend.ip_intelligence")

class BaseIPProvider(ABC):
    """Abstract Base Class for IP threat intelligence and network geolocation providers."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        """
        Queries intelligence for a single publicly routable IP address.
        Returns a structured IPIntelligenceResult.
        """
        pass


class UnavailableIPProvider(BaseIPProvider):
    """Fallback provider when no external provider is configured or available."""

    def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        return IPIntelligenceResult(
            ip=ip,
            status="unavailable",
            ip_type="public",
            source="none",
            confidence="none"
        )


class IpApiProvider(BaseIPProvider):
    """
    Real-world IP Intelligence provider using ip-api.com (Free Tier).
    Provides geolocation, ASN, and organization data.
    """

    def __init__(self):
        self.api_url = "http://ip-api.com/json"

    def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.api_url}/{ip}")
                response.raise_for_status()
                data = response.json()

            if data.get("status") == "fail":
                return IPIntelligenceResult(
                    ip=ip,
                    status="error",
                    ip_type="public",
                    source="ip-api-fail",
                    confidence="none",
                    error=data.get("message", "API lookup failed")
                )

            # Heuristic for confidence: LOW if org contains hosting/cloud/vps/vpn/tor/datacenter
            isp = data.get("isp", "").lower()
            org = data.get("org", "").lower()
            datacenter_keywords = ["hosting", "cloud", "vps", "vpn", "tor", "datacenter", "aws", "azure", "google", "digitalocean", "ovh"]
            
            confidence = "HIGH"
            if any(kw in isp or kw in org for kw in datacenter_keywords):
                confidence = "LOW"

            return IPIntelligenceResult(
                ip=ip,
                status="available",
                provider="ip-api.com",
                country=data.get("country"),
                region=data.get("regionName"),
                city=data.get("city"),
                asn=data.get("as"),
                isp=data.get("isp"),
                is_hosting=confidence == "LOW",
                is_vpn_tor=confidence == "LOW",
                source="ip-api.com",
                confidence=confidence
            )
        except Exception as exc:
            logger.error(f"ip-api.com lookup failed for {ip}: {exc}")
            return IPIntelligenceResult(
                ip=ip,
                status="error",
                ip_type="public",
                source="ip-api-error",
                confidence="none"
            )


def get_ip_provider(provider_name: Optional[str] = None) -> BaseIPProvider:
    """
    Factory creating configured IP intelligence provider based on environment or argument.
    Defaults to 'real' provider for production/integration, 'mock' for dev.
    """
    selected = (provider_name or os.environ.get("IP_INTELLIGENCE_PROVIDER", "real")).lower().strip()

    if selected == "mock":
        from .mock_provider import MockIPIntelligenceProvider
        return MockIPIntelligenceProvider()
    elif selected == "real":
        return IpApiProvider()
    elif selected in ("none", "unavailable"):
        return UnavailableIPProvider()
    else:
        # Default to real for integration sprint
        return IpApiProvider()
