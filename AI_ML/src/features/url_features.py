import re
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from config.config import URL_FEATURE_WEIGHTS

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click', 
    '.link', '.work', '.date', '.racing', '.review', '.country', '.stream', 
    '.download', '.win', '.bid', '.party', '.science', '.cricket', '.faith'
}

LOGIN_KEYWORDS = {
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 
    'confirm', 'account', 'secure', 'update', 'banking', 'password', 
    'credential', 'authenticate', 'webscr', 'payment', 'wallet'
}

URL_REGEX = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*')
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


@dataclass
class UrlFeatureResult:
    url_count: int
    ip_address_urls: int
    suspicious_tld_count: int
    obfuscated_count: int
    login_keyword_count: int
    excessive_subdomain_count: int
    long_url_count: int
    suspicious_urls: List[Dict[str, Any]]
    score: float
    flags: Dict[str, bool]
    extracted_domains: List[str]
    extracted_ips: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_url_features(urls: List[str], body: str = '') -> UrlFeatureResult:
    """
    Extracts URL-based risk signals from a list of URLs and email body text.
    """
    if not urls and body:
        urls = URL_REGEX.findall(body)
        
    if not urls:
        return UrlFeatureResult(0, 0, 0, 0, 0, 0, 0, [], 0.0, {
            'ip_address_url': False, 'suspicious_tld': False, 'excessive_subdomains': False,
            'url_obfuscation': False, 'login_keywords': False, 'long_url': False, 'has_urls': False
        }, [], [])

    ip_address_urls = 0
    suspicious_tld_count = 0
    obfuscated_count = 0
    login_keyword_count = 0
    excessive_subdomain_count = 0
    long_url_count = 0
    
    suspicious_urls = []
    extracted_domains = set()
    extracted_ips = set()
    
    for url in urls:
        reasons = []
        is_suspicious = False
        
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            path_query = (parsed.path + ' ' + parsed.query).lower()
        except Exception:
            continue
            
        if host:
            extracted_domains.add(host)
            
        # Check IP address
        if IP_REGEX.search(host):
            ip_address_urls += 1
            extracted_ips.add(host)
            reasons.append("IP address in URL")
            is_suspicious = True
            
        # Check suspicious TLD
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_tld_count += 1
            reasons.append("Suspicious TLD")
            is_suspicious = True
            
        # Check excessive subdomains (excluding www)
        host_parts = [p for p in host.split('.') if p != 'www']
        if len(host_parts) > 3:
            excessive_subdomain_count += 1
            reasons.append("Excessive subdomains")
            is_suspicious = True
            
        # Check obfuscation
        if '@' in url or '%' in url or 'xn--' in host:
            obfuscated_count += 1
            reasons.append("URL obfuscation")
            is_suspicious = True
            
        # Check login keywords
        if any(kw in path_query for kw in LOGIN_KEYWORDS):
            login_keyword_count += 1
            reasons.append("Login/verification keywords")
            is_suspicious = True
            
        # Check long URL
        if len(url) > 75:
            long_url_count += 1
            reasons.append("Long URL")
            is_suspicious = True
            
        if is_suspicious:
            suspicious_urls.append({"url": url, "reasons": reasons})

    flags = {
        'ip_address_url': ip_address_urls > 0,
        'suspicious_tld': suspicious_tld_count > 0,
        'excessive_subdomains': excessive_subdomain_count > 0,
        'url_obfuscation': obfuscated_count > 0,
        'login_keywords': login_keyword_count > 0,
        'long_url': long_url_count > 0,
        'has_urls': len(urls) > 0
    }

    score = 0.0
    total_weight = sum(URL_FEATURE_WEIGHTS.values()) if URL_FEATURE_WEIGHTS else 1.0
    if total_weight > 0:
        weighted_sum = sum(URL_FEATURE_WEIGHTS.get(f, 0.0) for f, val in flags.items() if val)
        score = (weighted_sum / total_weight) * 100.0
        score = max(0.0, min(100.0, score))

    return UrlFeatureResult(
        url_count=len(urls),
        ip_address_urls=ip_address_urls,
        suspicious_tld_count=suspicious_tld_count,
        obfuscated_count=obfuscated_count,
        login_keyword_count=login_keyword_count,
        excessive_subdomain_count=excessive_subdomain_count,
        long_url_count=long_url_count,
        suspicious_urls=suspicious_urls,
        score=score,
        flags=flags,
        extracted_domains=list(extracted_domains),
        extracted_ips=list(extracted_ips)
    )
