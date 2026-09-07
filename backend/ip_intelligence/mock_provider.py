"""
Mock IP Intelligence Provider for Local Testing and Development.
Returns clearly labeled synthetic/simulated infrastructure data.
"""

from backend.ip_intelligence.provider import BaseIPProvider
from backend.ip_intelligence.models import IPIntelligenceResult

# Synthetic demo catalog for well-known test IPs
KNOWN_MOCK_PROFILES = {
    "8.8.8.8": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": "AS15169",
        "organization": "Google LLC",
        "isp": "Google LLC",
        "is_hosting": False,
        "is_datacenter": True,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
    },
    "1.1.1.1": {
        "country": "Australia",
        "country_code": "AU",
        "region": "Queensland",
        "city": "Brisbane",
        "latitude": -27.4698,
        "longitude": 153.0251,
        "asn": "AS13335",
        "organization": "Cloudflare, Inc.",
        "isp": "Cloudflare, Inc.",
        "is_hosting": True,
        "is_datacenter": True,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
    },
    "93.184.216.34": {
        "country": "United States",
        "country_code": "US",
        "region": "Massachusetts",
        "city": "Norwell",
        "latitude": 42.1596,
        "longitude": -70.8217,
        "asn": "AS15133",
        "organization": "Edgecast Inc.",
        "isp": "MCI Communications Services, Inc. d/b/a Verizon Business",
        "is_hosting": True,
        "is_datacenter": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
    },
    "142.250.190.46": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": "AS15169",
        "organization": "Google LLC",
        "isp": "Google LLC",
        "is_hosting": True,
        "is_datacenter": True,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
    }
}


class MockIPIntelligenceProvider(BaseIPProvider):
    """
    Mock provider providing deterministic synthetic metadata.
    Explicitly labeled as simulated/demo data.
    """

    def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        clean_ip = ip.strip()
        profile = KNOWN_MOCK_PROFILES.get(clean_ip)

        if profile:
            return IPIntelligenceResult(
                ip=clean_ip,
                status="available",
                ip_type="public",
                country=profile["country"],
                country_code=profile["country_code"],
                region=profile["region"],
                city=profile["city"],
                latitude=profile["latitude"],
                longitude=profile["longitude"],
                asn=profile["asn"],
                organization=profile["organization"],
                isp=profile["isp"],
                is_hosting=profile["is_hosting"],
                is_datacenter=profile["is_datacenter"],
                is_vpn=profile["is_vpn"],
                is_proxy=profile["is_proxy"],
                is_tor=profile["is_tor"],
                source="synthetic_demo",
                confidence="simulated",
                is_synthetic=True
            )

        # Generic simulated public IP response for other public addresses
        return IPIntelligenceResult(
            ip=clean_ip,
            status="available",
            ip_type="public",
            country="Simulated Origin",
            country_code="XX",
            region="Simulated Region",
            city="Simulated City",
            latitude=0.0,
            longitude=0.0,
            asn="AS65000",
            organization="Simulated Autonomous System",
            isp="Simulated Network Provider",
            is_hosting=False,
            is_datacenter=False,
            is_vpn=False,
            is_proxy=False,
            is_tor=False,
            source="synthetic_demo",
            confidence="simulated",
            is_synthetic=True
        )
