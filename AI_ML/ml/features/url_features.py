"""URL-based feature extraction using rule-based analysis."""

import math
import re
from typing import TypedDict

from ml.config import CONFIG


class UrlFeatureFlags(TypedDict):
    malicious_prob: float
    flags: list[str]


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


class UrlFeatures:
    """Extract features from URLs for threat detection."""

    def __init__(self):
        cfg = CONFIG.get("features", {}).get("url", {})
        self.suspicious_tlds = cfg.get("suspicious_tlds", [
            ".xyz", ".tk", ".buzz", ".top", ".work", ".click"
        ])
        self.max_subdomains = cfg.get("max_subdomains", 4)
        self.max_length = cfg.get("max_length", 200)

    def analyze_url(self, url: str) -> UrlFeatureFlags:
        """Analyze a single URL and return threat probability + flags."""
        url_lower = url.lower()
        flags = []
        score = 0.0

        if len(url) > self.max_length:
            flags.append("excessive_length")
            score += 25.0

        entropy = calculate_entropy(url)
        if entropy > 4.0:
            flags.append("high_entropy")
            score += 30.0

        ip_pattern = re.compile(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}"
        )
        if ip_pattern.search(url_lower):
            flags.append("ip_address_host")
            score += 40.0

        if url_lower.startswith("http://"):
            flags.append("http_not_https")
            score += 15.0

        if "xn--" in url_lower:
            flags.append("punycode_detected")
            score += 35.0

        if "@" in url and "://" in url:
            flags.append("at_symbol_obfuscation")
            score += 40.0

        for tld in self.suspicious_tlds:
            if url_lower.endswith(tld) or f"{tld}/" in url_lower:
                flags.append(f"suspicious_tld_{tld}")
                score += 25.0
                break

        subdomain_count = url_lower.count(".")
        if subdomain_count > self.max_subdomains:
            flags.append("excessive_subdomains")
            score += 15.0

        suspicious_keywords = ["login", "verify", "account", "payment", "secure", "update", "confirm", "signin", "bank"]
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                flags.append(f"suspicious_keyword_{keyword}")
                score += 10.0
                break

        digit_count = sum(c.isdigit() for c in url)
        digit_ratio = digit_count / len(url) if url else 0
        if digit_ratio > 0.4:
            flags.append("high_digit_density")
            score += 20.0

        hex_pattern = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)
        if hex_pattern.search(url):
            flags.append("hex_encoding_detected")
            score += 15.0

        malicious_prob = min(100.0, score)
        return UrlFeatureFlags(malicious_prob=malicious_prob, flags=flags)

    def analyze_urls(self, urls: list[str]) -> list[UrlFeatureFlags]:
        """Analyze multiple URLs."""
        return [self.analyze_url(url) for url in urls]

    def aggregate_score(self, url_results: list[UrlFeatureFlags]) -> float:
        """Aggregate URL threat scores."""
        if not url_results:
            return 0.0
        max_prob = max(r["malicious_prob"] for r in url_results)
        avg_prob = sum(r["malicious_prob"] for r in url_results) / len(url_results)
        return min(100.0, max_prob * 0.6 + avg_prob * 0.4)
