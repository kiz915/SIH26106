"""Explainer module for generating human-readable threat reasons."""

import logging
from typing import Any

from ml.config import CONFIG

logger = logging.getLogger(__name__)


class Explainer:
    """Generate explanations and reasons from analysis results."""

    def __init__(self):
        cfg = CONFIG.get("explainability", {})
        self.max_flagged_spans = cfg.get("max_flagged_spans", 5)
        self.max_anomalies = cfg.get("max_anomalies", 5)
        self.span_highlight_method = cfg.get("span_highlight_method", "lexicon")
        self._captum_explainer = None

    def generate_reasons(
        self,
        text_flags: dict,
        header_result: dict,
        url_results: list[dict],
        classification_label: str
    ) -> list[dict]:
        """Generate sorted list of reasons from all towers."""
        reasons = []

        if text_flags.get("urgency_detected"):
            reasons.append({"severity": "MEDIUM", "text": "Urgency language detected in email body"})
        if text_flags.get("fear_detected"):
            reasons.append({"severity": "MEDIUM", "text": "Fear-inducing language detected"})
        if text_flags.get("credential_request"):
            reasons.append({"severity": "HIGH", "text": "Credential or login request detected"})
        if text_flags.get("financial_request"):
            reasons.append({"severity": "MEDIUM", "text": "Financial transaction language detected"})
        if text_flags.get("impersonation_detected"):
            reasons.append({"severity": "HIGH", "text": "Potential impersonation of known entity or role"})
        if text_flags.get("suspicious_cta"):
            reasons.append({"severity": "MEDIUM", "text": "Suspicious call-to-action detected"})

        for anomaly in header_result.get("anomalies", [])[:self.max_anomalies]:
            severity = "HIGH" if anomaly.get("contribution", 0) >= 25 else "MEDIUM" if anomaly.get("contribution", 0) >= 15 else "LOW"
            reasons.append({
                "severity": severity,
                "text": f"Header anomaly: {anomaly.get('feature', 'unknown')} - {anomaly.get('value', '')}"
            })

        for url_result in url_results:
            for flag in url_result.get("flags", [])[:3]:
                reasons.append({
                    "severity": "HIGH" if "suspicious" in flag or "obfuscation" in flag or "ip_address" in flag else "MEDIUM",
                    "text": f"URL threat flag: {flag}"
                })

        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        reasons.sort(key=lambda r: severity_order.get(r["severity"], 2))
        return reasons[:10]

    def derive_threat_category(self, label: str, text_flags: dict, url_results: list[dict]) -> str:
        """Derive threat category from classification label and flags."""
        if label == "LEGITIMATE":
            return "LEGITIMATE"
        if label == "SUSPICIOUS":
            return "SUSPICIOUS"

        if text_flags.get("financial_request") and text_flags.get("impersonation_detected"):
            return "BEC_PAYMENT_DIVERSION"
        if text_flags.get("credential_request"):
            return "CREDENTIAL_HARVESTING"
        if any("malicious" in r.get("flags", []) or "malware" in str(r.get("flags", [])).lower() for r in url_results):
            return "MALWARE_DELIVERY"
        if text_flags.get("impersonation_detected"):
            return "IMPERSONATION"
        if label == "PHISHING":
            return "PHISHING"

        return label

    def get_captum_spans(self, text: str, subject: str = "", model=None, tokenizer=None, top_k: int = 5) -> list[dict]:
        """
        Generate flagged spans using Captum Integrated Gradients.
        
        Args:
            text: Email body text
            subject: Email subject
            model: PyTorch model (zero-shot or fine-tuned)
            tokenizer: Corresponding tokenizer
            top_k: Number of top spans to return
            
        Returns:
            List of flagged spans with text, start, end, reason, weight
        """
        if model is None or tokenizer is None:
            return []
        
        try:
            import torch
            from captum.attr import LayerIntegratedGradients
            
            # Combine subject and body for model input
            full_text = f"{subject} [SEP] {text}" if subject else text
            
            # Tokenize
            inputs = tokenizer(full_text, return_tensors="pt", truncation=True, max_length=512)
            input_ids = inputs["input_ids"]
            attention_mask = inputs["attention_mask"]
            
            # Wrap model to return logits only
            class LogitsModel(torch.nn.Module):
                def __init__(self, model):
                    super().__init__()
                    self.model = model
                def forward(self, input_ids, attention_mask):
                    return self.model(input_ids=input_ids, attention_mask=attention_mask).logits
            
            logits_model = LogitsModel(model)
            
            # Use LayerIntegratedGradients on embedding layer
            lig = LayerIntegratedGradients(
                logits_model, 
                logits_model.model.distilbert.embeddings.word_embeddings
            )
            
            # Baseline (zeros)
            baseline_input_ids = torch.zeros_like(input_ids)
            baseline_attention_mask = torch.zeros_like(attention_mask)
            
            # Target class: contradiction (index 0) for phishing detection
            target = 0
            
            # Compute attributions
            attributions = lig.attribute(
                inputs=(input_ids, attention_mask),
                baselines=(baseline_input_ids, baseline_attention_mask),
                target=target,
                return_convergence_delta=False,
                additional_forward_args=()
            )
            
            # Sum over embedding dimension and get per-token importance
            token_importance = attributions[0].sum(dim=-1).squeeze().detach().numpy()
            
            # Get tokens
            tokens = tokenizer.convert_ids_to_tokens(input_ids[0])
            
            # Map tokens to character offsets in original body text
            spans = self._tokens_to_body_spans(text, subject, tokens, token_importance, top_k)
            
            return spans
            
        except Exception as e:
            logger.warning(f"Captum attribution failed: {e}, falling back to lexicon")
            return []

    def _tokens_to_body_spans(self, body_text: str, subject: str, tokens: list[str], importance: list[float], top_k: int) -> list[dict]:
        """Map token-level importance to character spans in original body text."""
        spans = []
        
        # Reconstruct the full text used for tokenization
        full_text = f"{subject} [SEP] {body_text}" if subject else body_text
        
        # Track character position in full_text
        char_pos = 0
        token_spans = []
        
        for i, token in enumerate(tokens):
            if token in ("[CLS]", "[SEP]", "[PAD]"):
                continue
            # Clean token (remove ## for subwords)
            clean_token = token.replace("##", "")
            if not clean_token:
                continue
            
            # Find in full_text starting from char_pos
            idx = full_text.lower().find(clean_token.lower(), char_pos)
            if idx >= 0:
                token_spans.append((idx, idx + len(clean_token), clean_token, float(importance[i])))
                char_pos = idx + len(clean_token)
            else:
                # Approximate
                token_spans.append((char_pos, char_pos + len(clean_token), clean_token, float(importance[i])))
                char_pos += len(clean_token)
        
        # Sort by importance (absolute value) and take top_k
        token_spans.sort(key=lambda x: abs(x[3]), reverse=True)
        
        # Subject offset in full_text
        subject_len = len(subject) + len(" [SEP] ") if subject else 0
        
        for full_start, full_end, token_text, imp in token_spans[:top_k]:
            # Only keep spans that are in the body text (after subject + [SEP])
            if full_start >= subject_len:
                # Map to body_text coordinates
                body_start = full_start - subject_len
                body_end = full_end - subject_len
                
                # Ensure the span is within body_text bounds
                if 0 <= body_start < len(body_text) and 0 < body_end <= len(body_text):
                    span_text = body_text[body_start:body_end]
                    # Verify it's an actual substring
                    if span_text and span_text in body_text:
                        reason = self._infer_reason(token_text)
                        spans.append({
                            "text": span_text,
                            "start": body_start,
                            "end": body_end,
                            "reason": reason,
                            "weight": float(abs(imp))
                        })
        
        return spans

    def _infer_reason(self, token_text: str) -> str:
        """Infer threat reason from token text."""
        token_lower = token_text.lower()
        urgency_words = {"urgent", "immediately", "asap", "suspend", "expire", "within", "24", "hours", "right", "now"}
        fear_words = {"compromised", "unauthorized", "suspended", "blocked", "breach", "security", "threat"}
        credential_words = {"password", "login", "verify", "confirm", "credentials", "identity", "account"}
        financial_words = {"payment", "wire", "transfer", "bank", "invoice", "fee", "processing", "due"}
        impersonation_words = {"ceo", "cfo", "director", "manager", "employee", "customer", "security", "team"}
        cta_words = {"click", "here", "below", "now", "verify", "confirm", "link"}
        
        if token_lower in credential_words:
            return "credential"
        elif token_lower in urgency_words:
            return "urgency"
        elif token_lower in fear_words:
            return "fear"
        elif token_lower in financial_words:
            return "financial"
        elif token_lower in impersonation_words:
            return "impersonation"
        elif token_lower in cta_words:
            return "suspicious_cta"
        return "suspicious"


def get_captum_explainer():
    """Get or create CaptumExplainer instance."""
    global _captum_explainer
    if _captum_explainer is None:
        _captum_explainer = Explainer()
    return _captum_explainer