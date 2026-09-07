from dataclasses import dataclass
from typing import Dict, Any, List

from src.nlp.classifier import NLPResult
from src.scoring.risk_scorer import ScoringResult

@dataclass
class Evidence:
    severity: str
    message: str
    category: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "message": self.message,
            "category": self.category
        }

@dataclass
class ExplanationResult:
    reasons: List[Dict[str, Any]]
    text_analysis: Dict[str, Any]
    url_analysis: Dict[str, Any]
    header_analysis: Dict[str, Any]
    iocs: Dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "reasons": self.reasons,
            "text_analysis": self.text_analysis,
            "url_analysis": self.url_analysis,
            "header_analysis": self.header_analysis,
            "iocs": self.iocs
        }

class Explainer:
    def explain(self, nlp_result: NLPResult, text_features: Any, url_features: Any, header_features: Any, scoring_result: ScoringResult, email_data: Dict[str, Any] = None) -> ExplanationResult:
        if email_data is None:
            email_data = {}
            
        evidence_list: List[Evidence] = []
        
        # 1. Collect reasons from text features
        text_attrs = ['urgency', 'fear_threat', 'credential_request', 'financial_request', 'impersonation', 'suspicious_cta', 'social_engineering', 'suspicious_grammar']
        for attr in text_attrs:
            val = getattr(text_features, attr, 0.0)
            if val > 0.3:
                severity = 'HIGH' if val > 0.7 else 'MEDIUM'
                patterns = getattr(text_features, 'matched_patterns', {}).get(attr, [])
                msg = f"High text feature score for {attr}: {val:.2f}."
                if patterns:
                    msg += f" Matched patterns: {', '.join(patterns)}"
                evidence_list.append(Evidence(severity=severity, message=msg, category='text'))
                
        # 2. Collect reasons from URL features
        if getattr(url_features, 'ip_address_urls', 0) > 0:
            evidence_list.append(Evidence(severity='HIGH', message='URL contains raw IP address', category='url'))
        if getattr(url_features, 'suspicious_tld_count', 0) > 0:
            evidence_list.append(Evidence(severity='MEDIUM', message='Suspicious TLD detected', category='url'))
        if getattr(url_features, 'obfuscated_count', 0) > 0:
            evidence_list.append(Evidence(severity='HIGH', message='URL obfuscation detected', category='url'))
        if getattr(url_features, 'login_keyword_count', 0) > 0:
            evidence_list.append(Evidence(severity='HIGH', message='Suspicious login/verify URL detected', category='url'))
        if getattr(url_features, 'excessive_subdomain_count', 0) > 0:
            evidence_list.append(Evidence(severity='MEDIUM', message='Excessive subdomains in URL', category='url'))
        if getattr(url_features, 'long_url_count', 0) > 0:
            evidence_list.append(Evidence(severity='LOW', message='Unusually long URL detected', category='url'))
            
        # 3. Collect reasons from header features
        if getattr(header_features, 'spf_fail', False):
            evidence_list.append(Evidence(severity='HIGH', message='SPF authentication failed', category='header'))
        if getattr(header_features, 'dkim_fail', False):
            evidence_list.append(Evidence(severity='HIGH', message='DKIM authentication failed', category='header'))
        if getattr(header_features, 'dmarc_fail', False):
            evidence_list.append(Evidence(severity='HIGH', message='DMARC authentication failed', category='header'))
        if getattr(header_features, 'sender_reply_to_mismatch', False):
            evidence_list.append(Evidence(severity='HIGH', message='Sender and Reply-To address mismatch', category='header'))
        if getattr(header_features, 'sender_domain_mismatch', False):
            evidence_list.append(Evidence(severity='MEDIUM', message='Sender domain mismatch detected', category='header'))
        if getattr(header_features, 'suspicious_received_chain', False):
            evidence_list.append(Evidence(severity='MEDIUM', message='Suspicious email routing detected', category='header'))
            
        # 4. Add NLP model evidence
        label_val = nlp_result.label.value if hasattr(nlp_result.label, 'value') else nlp_result.label
        evidence_list.append(Evidence(
            severity='MEDIUM', 
            message=f'NLP model classified as {label_val} with {nlp_result.confidence:.0%} confidence', 
            category='nlp'
        ))
        if scoring_result.fp_capped:
            evidence_list.append(Evidence(severity='LOW', message='False-positive cap applied — signals appear benign', category='nlp'))
            
        # 5. Sort by severity (HIGH > MEDIUM > LOW)
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        evidence_list.sort(key=lambda x: severity_order.get(x.severity, 3))
        
        reasons = [e.to_dict() for e in evidence_list]
        
        # 6. Build IOCs block
        headers = email_data.get('headers', {})
        sender = email_data.get('sender', '')
        reply_to = headers.get('Reply-To', '')
        email_addresses = [a for a in [sender, reply_to] if a]
        
        iocs = {
            'urls': getattr(url_features, 'suspicious_urls', []),
            'domains': getattr(url_features, 'extracted_domains', []),
            'ip_addresses': getattr(url_features, 'extracted_ips', []),
            'email_addresses': list(set(email_addresses)),
            'file_hashes': [att.get('hash', '') for att in email_data.get('attachments', []) if att.get('hash')]
        }
        
        # 7. Return ExplanationResult
        return ExplanationResult(
            reasons=reasons,
            text_analysis=text_features.to_dict(),
            url_analysis=url_features.to_dict(),
            header_analysis=header_features.to_dict(),
            iocs=iocs
        )
