import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from config.config import TEXT_FEATURE_WEIGHTS

URGENCY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"immediately", r"urgent", r"asap", r"action required", r"expir(e|es|ed|ing)", 
    r"suspend(ed)?", r"deactivat(e|ed)", r"within \d+ (hour|day|minute)", r"last chance", 
    r"final warning", r"time.?sensitive", r"respond now", r"act now", r"limited time", 
    r"don't delay", r"right away"
]]

FEAR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"unauthorized", r"suspicious activity", r"security alert", r"account.{0,20}(locked|suspended|compromised)", 
    r"fraudulent", r"identity theft", r"illegal", r"law enforcement", r"legal action", 
    r"criminal", r"data breach", r"hacked", r"stolen", r"threat", r"penalty"
]]

CREDENTIAL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(verify|confirm|update|validate).{0,30}(account|password|identity|credentials)", 
    r"(enter|provide|submit).{0,30}(password|ssn|social security|credit card)", 
    r"log.?in.{0,20}(verify|confirm|secure)", r"reset.{0,20}password", 
    r"(username|password|pin|otp).*(required|needed|enter)", r"sign.?in to (confirm|verify)"
]]

FINANCIAL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"wire transfer", r"bank account", r"routing number", r"payment (required|due|overdue)", 
    r"invoice.{0,20}(attached|enclosed|overdue)", r"western union", r"bitcoin", r"cryptocurrency", 
    r"money gram", r"gift card", r"(send|transfer).{0,30}(money|funds|payment)", r"refund.{0,20}(process|claim|pending)"
]]

IMPERSONATION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(this is|i am).{0,20}(ceo|cfo|director|manager|president|admin)", 
    r"on behalf of.{0,20}(management|hr|it department|helpdesk)", r"official notice from", 
    r"authorized representative", r"(microsoft|apple|google|amazon|paypal|netflix|bank).{0,20}(support|team|security|service)", 
    r"helpdesk", r"it department notice", r"system administrator"
]]

SUSPICIOUS_CTA_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"click (here|below|this link|the link|immediately)", r"open.{0,10}(attachment|document|file)", 
    r"download.{0,10}(attachment|file|document)", r"(enable|disable).{0,10}(macro|content|editing)", 
    r"review.{0,10}(document|attachment|invoice)"
]]

SOCIAL_ENGINEERING_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(don't|do not) (tell|share|inform|mention).{0,20}(anyone|anybody|colleagues)", 
    r"keep this (confidential|private|secret|between us)", r"(only you|you alone|personally selected|specially chosen)", 
    r"(winner|won|selected|chosen).{0,20}(prize|lottery|award|reward)", r"congratulations.{0,20}(won|selected|winner)", 
    r"inheritance.{0,10}(fund|claim|beneficiary)", r"kindly (do not|don't) (ignore|disregard)"
]]

SUSPICIOUS_GRAMMAR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"dear (customer|user|account holder|valued|sir\/madam|beneficiary)", r"(greetings|hello) dear", 
    r"kindly (revert|do the needful|furnish|oblige)", r"we have detected.{0,20}unusual", 
    r"your account (has been|will be|is being)", r"click.{0,20}(within|before).{0,10}(24|48|72).{0,5}hour"
]]


@dataclass
class TextFeatureResult:
    urgency: float
    fear_threat: float
    credential_request: float
    financial_request: float
    impersonation: float
    suspicious_cta: float
    social_engineering: float
    suspicious_grammar: float
    matched_patterns: Dict[str, List[str]]
    score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_text_features(text: str) -> TextFeatureResult:
    """
    Extracts text-based risk features from email content using regex and keyword matching.
    """
    if not text:
        return TextFeatureResult(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, {}, 0.0)

    text_lower = text.lower()
    
    categories = {
        'urgency': URGENCY_PATTERNS,
        'fear_threat': FEAR_PATTERNS,
        'credential_request': CREDENTIAL_PATTERNS,
        'financial_request': FINANCIAL_PATTERNS,
        'impersonation': IMPERSONATION_PATTERNS,
        'suspicious_cta': SUSPICIOUS_CTA_PATTERNS,
        'social_engineering': SOCIAL_ENGINEERING_PATTERNS,
        'suspicious_grammar': SUSPICIOUS_GRAMMAR_PATTERNS
    }

    feature_values = {}
    matched_patterns = {}

    for cat_name, patterns in categories.items():
        matches = []
        for pat in patterns:
            found = pat.findall(text_lower)
            if found:
                matches.append(pat.pattern)
        
        count = len(matches)
        feature_values[cat_name] = min(1.0, count * 0.3)
        if matches:
            matched_patterns[cat_name] = matches

    total_weight = sum(TEXT_FEATURE_WEIGHTS.values()) if TEXT_FEATURE_WEIGHTS else 1.0
    weighted_sum = sum(feature_values.get(f, 0.0) * w for f, w in TEXT_FEATURE_WEIGHTS.items())
    
    score = (weighted_sum / total_weight) * 100 if total_weight > 0 else 0.0
    score = max(0.0, min(100.0, score))

    return TextFeatureResult(
        urgency=feature_values['urgency'],
        fear_threat=feature_values['fear_threat'],
        credential_request=feature_values['credential_request'],
        financial_request=feature_values['financial_request'],
        impersonation=feature_values['impersonation'],
        suspicious_cta=feature_values['suspicious_cta'],
        social_engineering=feature_values['social_engineering'],
        suspicious_grammar=feature_values['suspicious_grammar'],
        matched_patterns=matched_patterns,
        score=score
    )
