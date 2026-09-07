"""
Abstract Provider Interface and Factory for IP Intelligence.
Ensures provider-agnostic extensibility without hardcoding vendors.
"""

from abc import ABC, abstractmethod
import os
from typing import Optional

from backend.ip_intelligence.models import IPIntelligenceResult


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


def get_ip_provider(provider_name: Optional[str] = None) -> BaseIPProvider:
    """
    Factory creating configured IP intelligence provider based on environment or argument.
    Defaults to 'mock' provider for safe development/testing.
    """
    selected = (provider_name or os.environ.get("IP_INTELLIGENCE_PROVIDER", "mock")).lower().strip()

    if selected == "mock":
        from backend.ip_intelligence.mock_provider import MockIPIntelligenceProvider
        return MockIPIntelligenceProvider()
    elif selected in ("none", "unavailable"):
        return UnavailableIPProvider()
    else:
        # Future real providers (e.g. MaxMind, IPinfo, VirusTotal) can register here
        from backend.ip_intelligence.mock_provider import MockIPIntelligenceProvider
        return MockIPIntelligenceProvider()
