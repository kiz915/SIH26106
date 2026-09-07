"""
Relay Path Parser and Received Header Forensic Analyzer.
Parses Received headers into chronologically ordered hops with granular IP classification:
RFC1918 private, loopback, link-local, documentation/test, reserved, and public.
"""

import email.message
import re
import ipaddress
from email.utils import parsedate_to_datetime
from datetime import datetime
from typing import List, Optional, Tuple

from backend.models import RelayHop


# Regex patterns for parsing components of Received headers
IP_PATTERN = re.compile(
    r"\[?(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7})\]?"
)

FROM_SERVER_PATTERN = re.compile(r"from\s+([^\s;()]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
BY_SERVER_PATTERN = re.compile(r"by\s+([^\s;()]+)", re.IGNORECASE)

# Network definitions for granular IP categorization
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("2001:db8::/32"),   # RFC 3849 (IPv6 Documentation)
]

CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")
BENCHMARK_NETWORKS = ipaddress.ip_network("198.18.0.0/15")


def validate_ip(candidate: str) -> Optional[str]:
    """Validates an IP address using Python's standard ipaddress module."""
    if not candidate:
        return None
    cleaned = candidate.strip("[]() \t\r\n")
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None


def extract_ip_from_header(raw_header: str) -> Optional[str]:
    """Finds and strictly validates the first IP address within a Received header."""
    matches = IP_PATTERN.findall(raw_header)
    for candidate in matches:
        valid = validate_ip(candidate)
        if valid:
            return valid
    return None


def classify_ip_address(ip_candidate: Optional[str]) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Classifies an IP address into forensic categories:
    - 'rfc1918' (Private enterprise network)
    - 'loopback' (Localhost)
    - 'link-local' (Autoconfigured non-routable link)
    - 'documentation' (RFC 5737 / RFC 3849 testbeds & documentation ranges)
    - 'reserved' (Special purpose, CGNAT, benchmark, multicast)
    - 'public' (Globally routable Internet IP)
    
    Returns: (ip_type, is_private_ip, forensic_description)
    """
    if not ip_candidate:
        return None, False, None

    try:
        ip = ipaddress.ip_address(ip_candidate.strip("[]() \t\r\n"))
    except ValueError:
        return "invalid", False, "Invalid IP address syntax."

    # 1. Loopback
    if ip.is_loopback:
        return "loopback", False, "Loopback address (localhost internal transmission)."

    # 2. Link-Local
    if ip.is_link_local:
        return "link-local", False, "Link-local address (non-routable autoconfigured segment)."

    # 3. Documentation / Test ranges (RFC 5737 / RFC 3849)
    if any(ip in net for net in DOCUMENTATION_NETWORKS):
        return "documentation", False, "RFC 5737 / RFC 3849 documentation/test range IP (used in testbeds and test samples)."

    # 4. RFC 1918 Private IPv4 & IPv6 ULA
    if ip.version == 4 and any(ip in net for net in RFC1918_NETWORKS):
        return "rfc1918", True, "Traversed RFC 1918 private internal network space."
    if ip.version == 6 and ip in IPV6_ULA_NETWORK:
        return "rfc1918", True, "Traversed IPv6 Unique Local Address (ULA) private address space."

    # 5. Reserved / Special-use (CGNAT, Benchmarking, Multicast, Reserved)
    if ip in CARRIER_GRADE_NAT or ip in BENCHMARK_NETWORKS or ip.is_reserved or ip.is_multicast:
        return "reserved", False, "Reserved / special-use non-routable IP address."

    # 6. Public / Globally Routable
    if ip.is_global:
        return "public", False, "Publicly routable IP address."

    return "reserved", False, "Special-use non-global IP address."


def extract_servers(raw_header: str) -> Tuple[Optional[str], Optional[str]]:
    """Extracts transmitting server ('from ...') and receiving server ('by ...')."""
    sending = None
    receiving = None

    from_match = FROM_SERVER_PATTERN.search(raw_header)
    if from_match:
        sending = from_match.group(1).strip()

    by_match = BY_SERVER_PATTERN.search(raw_header)
    if by_match:
        receiving = by_match.group(1).strip()

    return sending, receiving


def extract_timestamp(raw_header: str) -> Tuple[Optional[str], Optional[datetime]]:
    """Extracts and parses timestamp from the trailing section of a Received header."""
    if ";" not in raw_header:
        return None, None

    date_str = raw_header.rsplit(";", 1)[-1].strip()
    # Normalize excessive whitespaces or newlines in date string
    date_str = re.sub(r"\s+", " ", date_str)

    try:
        dt = parsedate_to_datetime(date_str)
        return dt.isoformat(), dt
    except Exception:
        return date_str if date_str else None, None


def parse_relay_path(msg: email.message.EmailMessage) -> List[RelayHop]:
    """
    Parses 'Received' headers into an ordered list of RelayHops with forensic IP classification.
    
    Order explanation:
    - MTAs prepend Received headers to the top of the message.
    - Topmost header = Final receiving hop (recipient boundary MTA).
    - Bottommost header = Initial sending hop (originator / first relay).
    - We reverse the raw list so Hop 1 = Originator -> Hop N = Recipient.
    
    Forensic integrity:
    - Headers added prior to the recipient's trusted border MTA can be forged by the sender.
    - Accurately classifies RFC1918, loopback, link-local, documentation, and public addresses.
    """
    raw_received_headers = msg.get_all("Received", [])
    if not raw_received_headers:
        return []

    # Chronological ordering: reverse the list so index 0 is the earliest (bottom) hop
    chronological_headers = list(reversed(raw_received_headers))
    hops: List[RelayHop] = []
    prev_dt: Optional[datetime] = None

    total_hops = len(chronological_headers)

    for idx, raw_hdr in enumerate(chronological_headers, start=1):
        clean_raw = " ".join(raw_hdr.split())
        sending_server, receiving_server = extract_servers(clean_raw)
        ip = extract_ip_from_header(clean_raw)
        iso_ts, dt_obj = extract_timestamp(clean_raw)

        # Granular IP Classification
        ip_type, is_private, ip_forensic_note = classify_ip_address(ip)

        # Calculate delay relative to previous hop if timestamps are valid
        delay_sec = None
        if dt_obj and prev_dt:
            delta = (dt_obj - prev_dt).total_seconds()
            delay_sec = max(0.0, delta)
        if dt_obj:
            prev_dt = dt_obj

        # Forensic commentary
        notes = []
        if idx == 1:
            notes.append("Initial entry hop (closest to original sender). Note: Origin headers may be forged if unauthenticated.")
        elif idx == total_hops:
            notes.append("Final destination hop (recipient border mail gateway).")

        if ip_forensic_note:
            notes.append(ip_forensic_note)

        hop = RelayHop(
            hop_number=idx,
            receiving_server=receiving_server,
            sending_server=sending_server,
            ip=ip,
            ip_type=ip_type,
            timestamp=iso_ts,
            raw_header=clean_raw,
            is_private_ip=is_private,
            delay_seconds=delay_sec,
            forensic_notes=" | ".join(notes) if notes else None
        )
        hops.append(hop)

    return hops
