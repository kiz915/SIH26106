import os
from enum import Enum
from pathlib import Path

class TextModelMode(str, Enum):
    ZERO_SHOT = 'zero_shot'
    FINE_TUNED = 'fine_tuned'
    RULES_ONLY = 'rules_only'

class ThreatLabel(str, Enum):
    LEGITIMATE = 'LEGITIMATE'
    SUSPICIOUS = 'SUSPICIOUS'
    PHISHING = 'PHISHING'
    IMPERSONATION = 'IMPERSONATION'
    BEC_PAYMENT_DIVERSION = 'BEC_PAYMENT_DIVERSION'
    CREDENTIAL_HARVESTING = 'CREDENTIAL_HARVESTING'
    MALWARE_DELIVERY = 'MALWARE_DELIVERY'

class RiskLevel(str, Enum):
    LOW = 'Low Risk'
    SUSPICIOUS = 'Suspicious'
    HIGH = 'High Risk'
    CRITICAL = 'Critical'

try:
    import torch
    DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'
except ImportError:
    DEVICE = 'cpu'

TEXT_MODEL_MODE = TextModelMode(os.environ.get('TEXT_MODEL_MODE', TextModelMode.ZERO_SHOT.value))

ZERO_SHOT_MODEL_NAME = 'typeform/distilbert-base-uncased-mnli'

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / 'models'
DATA_DIR = PROJECT_ROOT / 'data'

FINE_TUNED_MODEL_DIR = MODELS_DIR / 'distilbert-phishing-v1' / 'onnx'
FINE_TUNED_MIN_F1 = 0.90

ZERO_SHOT_LABELS = [
    'legitimate email',
    'suspicious email',
    'phishing attempt',
    'impersonation attempt',
    'business email compromise payment diversion',
    'credential harvesting attack',
    'malware delivery'
]

ZERO_SHOT_LABEL_MAP = {
    'legitimate email': ThreatLabel.LEGITIMATE,
    'suspicious email': ThreatLabel.SUSPICIOUS,
    'phishing attempt': ThreatLabel.PHISHING,
    'impersonation attempt': ThreatLabel.IMPERSONATION,
    'business email compromise payment diversion': ThreatLabel.BEC_PAYMENT_DIVERSION,
    'credential harvesting attack': ThreatLabel.CREDENTIAL_HARVESTING,
    'malware delivery': ThreatLabel.MALWARE_DELIVERY
}

FUSION_STRATEGY = os.environ.get('FUSION_STRATEGY', 'weighted')

FUSION_WEIGHTS = {'nlp': 0.40, 'url': 0.30, 'header': 0.30}

RISK_THRESHOLDS = {
    RiskLevel.LOW: (0, 29),
    RiskLevel.SUSPICIOUS: (30, 59),
    RiskLevel.HIGH: (60, 79),
    RiskLevel.CRITICAL: (80, 100)
}

FP_CAP_CONFIDENCE = 0.70
FP_CAP_MAX_SCORE = 25

TEXT_FEATURE_WEIGHTS = {
    'urgency': 8,
    'fear_threat': 10,
    'credential_request': 15,
    'financial_request': 12,
    'impersonation': 10,
    'suspicious_cta': 8,
    'social_engineering': 10,
    'suspicious_grammar': 5
}

URL_FEATURE_WEIGHTS = {
    'ip_address_url': 15,
    'suspicious_tld': 10,
    'excessive_subdomains': 8,
    'url_obfuscation': 12,
    'login_keywords': 10,
    'long_url': 5,
    'has_urls': 3
}

HEADER_FEATURE_WEIGHTS = {
    'spf_fail': 15,
    'dkim_fail': 15,
    'dmarc_fail': 20,
    'sender_reply_to_mismatch': 12,
    'sender_domain_mismatch': 10,
    'suspicious_received_chain': 8
}

MODEL_VERSION = '0.1.0'
