"""
Pydantic schemas and data models for Network IP Intelligence & Geolocation.
"""

from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

DISCLAIMER_TEXT = (
    "IP geolocation reflects network infrastructure routing or registration data "
    "and does not establish the physical identity or location of the attacker."
)


class IPIntelligenceResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ip: str = Field(..., description="Target IP address evaluated")
    status: str = Field(
        ...,
        description="Lookup status: available | unavailable | skipped_private | skipped_documentation | skipped_loopback | skipped_reserved | error"
    )
    ip_type: Optional[str] = Field(
        default=None,
        description="IP classification: public | rfc1918 | loopback | link-local | documentation | reserved"
    )
    country: Optional[str] = Field(default=None, description="Country name or code")
    country_code: Optional[str] = Field(default=None, description="ISO 3166-1 alpha-2 country code")
    region: Optional[str] = Field(default=None, description="Region or state")
    city: Optional[str] = Field(default=None, description="City")
    latitude: Optional[float] = Field(default=None, description="Approximate latitude of network infrastructure")
    longitude: Optional[float] = Field(default=None, description="Approximate longitude of network infrastructure")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number (e.g. AS15169)")
    organization: Optional[str] = Field(default=None, description="AS or Network Organization")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider name")
    is_hosting: Optional[bool] = Field(default=None, description="True if identified as hosting/datacenter IP")
    is_datacenter: Optional[bool] = Field(default=None, description="True if identified as cloud/datacenter range")
    is_vpn: Optional[bool] = Field(default=None, description="True if known VPN exit node")
    is_proxy: Optional[bool] = Field(default=None, description="True if open/anonymous proxy")
    is_tor: Optional[bool] = Field(default=None, description="True if known TOR exit node")
    source: Optional[str] = Field(default=None, description="Provider or mechanism supplying intelligence")
    confidence: Optional[str] = Field(default=None, description="Confidence level: low | medium | high | simulated")
    is_synthetic: bool = Field(default=False, description="True if intelligence is generated mock/synthetic data")
    disclaimer: str = Field(
        default=DISCLAIMER_TEXT,
        description="Evidentiary disclaimer on infrastructure location vs attacker identity"
    )
