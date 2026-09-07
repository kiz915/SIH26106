#!/usr/bin/env python3
"""
Generate sample analysis result for handoff to Team 1 (Frontend)
"""

import json
import time
from pathlib import Path

# Simple sample output for UI development
sample_result = {
    "risk_score": 85.5,
    "classification": "PHISHING",
    "confidence": 0.92,
    "risk_level": "HIGH",
    "threat_category": "phishing",
    "reasons": [
        {
            "severity": "HIGH",
            "message": "High text feature score for credential_request: 0.85. Matched patterns: password, verify, credentials",
            "category": "text"
        },
        {
            "severity": "HIGH",
            "message": "Suspicious login/verify URL detected",
            "category": "url"
        },
        {
            "severity": "HIGH",
            "message": "SPF authentication failed",
            "category": "header"
        },
        {
            "severity": "MEDIUM",
            "message": "NLP model classified as PHISHING with 92% confidence",
            "category": "nlp"
        }
    ],
    "text_analysis": {
        "urgency": 0.75,
        "fear_threat": 0.60,
        "credential_request": 0.85,
        "financial_request": 0.30,
        "impersonation": 0.45,
        "suspicious_cta": 0.80,
        "social_engineering": 0.70,
        "suspicious_grammar": 0.25,
        "flagged_spans": [
            {
                "text": "verify your account immediately",
                "reason": "credential_request",
                "severity": "HIGH"
            },
            {
                "text": "click here to verify",
                "reason": "suspicious_cta", 
                "severity": "HIGH"
            },
            {
                "text": "password will be suspended",
                "reason": "fear_threat",
                "severity": "MEDIUM"
            }
        ]
    },
    "url_analysis": {
        "suspicious_urls": [
            "http://suspicious-site.com/verify",
            "http://evil.com/login"
        ],
        "extracted_domains": [
            "suspicious-site.com",
            "evil.com"
        ],
        "extracted_ips": [],
        "ip_address_urls": 0,
        "suspicious_tld_count": 0,
        "obfuscated_count": 0,
        "login_keyword_count": 2,
        "excessive_subdomain_count": 0,
        "long_url_count": 0
    },
    "header_analysis": {
        "spf_fail": True,
        "dkim_fail": True,
        "dmarc_fail": True,
        "sender_reply_to_mismatch": True,
        "sender_domain_mismatch": False,
        "suspicious_received_chain": True,
        "anomalies": [
            "SPF authentication failed",
            "DKIM authentication failed", 
            "DMARC authentication failed",
            "Sender and Reply-To address mismatch"
        ]
    },
    "iocs": {
        "urls": [
            "http://suspicious-site.com/verify",
            "http://evil.com/login"
        ],
        "domains": [
            "suspicious-site.com",
            "evil.com"
        ],
        "ip_addresses": [],
        "email_addresses": [
            "phisher@evil.com",
            "hacker@fake-corp.com"
        ],
        "file_hashes": []
    },
    "component_scores": {
        "nlp_score": 92.0,
        "text_score": 85.5,
        "url_score": 75.0,
        "header_score": 90.0,
        "fusion_score": 85.5
    },
    "fp_capped": False,
    "hash_payload": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
    "model_metadata": {
        "model_name": "distilbert-phishing-v1",
        "model_version": "1.0",
        "model_type": "fine_tuned",
        "inference_framework": "onnxruntime",
        "macro_f1": 0.9819,
        "latency_ms": 512.3
    },
    "generated_at": "2026-09-07T10:30:00Z"
}

# Save to handoff directory
handoff_dir = Path(__file__).parent.parent / "handoff"
output_file = handoff_dir / "sample_analysis_result.json"

with open(output_file, 'w') as f:
    json.dump(sample_result, f, indent=2)

print(f"Sample analysis result saved to: {output_file}")
print(f"File size: {output_file.stat().st_size} bytes")