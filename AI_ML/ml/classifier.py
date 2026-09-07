"""Email text classifier with 4 operating modes."""

import logging
import os
from typing import Any

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from ml.config import CONFIG, DEVICE
from ml.features.text_features import TextFeatures

logger = logging.getLogger(__name__)

NLI_LABELS = ["contradiction", "neutral", "entailment"]

NLI_TO_THREAT = {
    "contradiction": "PHISHING",
    "neutral": "SUSPICIOUS",
    "entailment": "LEGITIMATE",
}

CANDIDATE_LABEL_TO_CLASS = {
    "phishing": "PHISHING",
    "legitimate email": "LEGITIMATE",
    "credential theft": "CREDENTIAL_HARVESTING",
    "business email compromise": "BEC_PAYMENT_DIVERSION",
    "invoice fraud": "BEC_PAYMENT_DIVERSION",
    "malware delivery": "MALWARE_DELIVERY",
    "impersonation": "IMPERSONATION",
}


class Classifier:
    """
    Text classifier with rules_only, zero_shot, hybrid_zero_shot, and fine_tuned modes.
    
    Mode selection (via configs/ml.yaml):
    - rules_only: Lexical/rule-based only (always works, no model needed)
    - zero_shot: Pure NLI zero-shot classification
    - hybrid_zero_shot: Weighted blend of lexical (65%) + zero-shot (35%)
    - fine_tuned: Fine-tuned email classifier (future)
    """

    def __init__(self):
        self.cfg = CONFIG.get("text_model", {})
        self.mode = self.cfg.get("mode", "hybrid_zero_shot")
        self.local_files_only = self.cfg.get("local_files_only", True)
        self.max_length = self.cfg.get("max_length", 512)
        self.hybrid_weights = self.cfg.get("hybrid_weights", {"lexical": 0.65, "zero_shot": 0.35})
        
        self.text_features = TextFeatures()
        self.model = None
        self.tokenizer = None
        self._loaded = False
        self._load_failed = False
        self._model_version = "none"

    def load(self) -> bool:
        """Load the appropriate model based on configured mode."""
        if self._loaded or self._load_failed:
            return not self._load_failed

        if self.mode == "rules_only":
            self._loaded = True
            return True

        if self.mode in ("zero_shot", "hybrid_zero_shot"):
            return self._load_zero_shot_model()

        if self.mode == "fine_tuned":
            return self._load_fine_tuned_model()

        self._loaded = True
        return True

    def _load_zero_shot_model(self) -> bool:
        """Load zero-shot NLI model with safe/offline configuration."""
        model_name = self.cfg.get("zero_shot_model", "typeform/distilbert-base-uncased-mnli")

        load_kwargs = {"pretrained_model_name_or_path": model_name}
        
        if self.local_files_only:
            load_kwargs["local_files_only"] = True
            os.environ["TRANSFORMERS_OFFLINE"] = "1"
            os.environ["HF_HUB_OFFLINE"] = "1"

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(**load_kwargs)
            self.model = AutoModelForSequenceClassification.from_pretrained(**load_kwargs)
            self.model.to(DEVICE)
            self.model.eval()
            self._loaded = True
            self._model_version = model_name
            logger.info(f"Loaded zero-shot model: {model_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load zero-shot model (local_files_only={self.local_files_only}): {e}")
            self._load_failed = True
            self._loaded = True
            self.mode = "rules_only"
            return False

    def _load_fine_tuned_model(self) -> bool:
        """Load fine-tuned ONNX model (stub - falls back to hybrid_zero_shot)."""
        logger.info("Fine-tuned model not yet available, falling back to hybrid_zero_shot")
        self.mode = "hybrid_zero_shot"
        return self._load_zero_shot_model()

    def classify(self, text: str, subject: str = "") -> dict[str, Any]:
        """
        Classify email text and return label + confidence + all scores.
        
        Returns dict with:
        - label: str (one of LABELS)
        - confidence: float (0-1)
        - all_scores: dict[str, float] (all label scores 0-100)
        """
        if self.mode == "rules_only" or not self._loaded or self._load_failed:
            return self._classify_rules(text, subject)

        if self.mode == "zero_shot":
            return self._classify_zero_shot(text, subject)

        if self.mode == "hybrid_zero_shot":
            return self._classify_hybrid(text, subject)

        return self._classify_rules(text, subject)

    def _classify_rules(self, text: str, subject: str = "") -> dict[str, Any]:
        """Rule-based classification using text features."""
        flags = self.text_features.extract(text, subject)
        all_scores = self._flags_to_all_scores(flags)
        
        best_label = max(all_scores, key=all_scores.get)
        confidence = all_scores[best_label] / 100.0 if all_scores[best_label] > 0 else 0.5

        return {
            "label": best_label,
            "confidence": confidence,
            "all_scores": all_scores
        }

    def _flags_to_all_scores(self, flags: dict) -> dict[str, float]:
        """Convert text feature flags to all_scores dict."""
        all_scores = {
            "LEGITIMATE": 100.0 - flags["overall_score"],
            "SUSPICIOUS": flags["overall_score"] * 0.5,
            "PHISHING": flags["overall_score"] * 0.7,
            "IMPERSONATION": flags["impersonation_score"],
            "BEC_PAYMENT_DIVERSION": flags["financial_score"] + flags["impersonation_score"] * 0.5,
            "CREDENTIAL_HARVESTING": flags["credential_score"],
            "MALWARE_DELIVERY": 0.0,
        }

        for key in all_scores:
            all_scores[key] = min(100.0, max(0.0, all_scores[key]))

        return all_scores

    def _classify_zero_shot(self, text: str, subject: str = "") -> dict[str, Any]:
        """Pure zero-shot classification using NLI model."""
        if self.model is None or self.tokenizer is None:
            return self._classify_rules(text, subject)

        combined = f"{subject} [SEP] {text}" if subject else text
        words = combined.split()
        if len(words) > self.max_length:
            combined = " ".join(words[:self.max_length])

        try:
            inputs = self.tokenizer(combined, return_tensors="pt", truncation=True, max_length=self.max_length)
            inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1)[0]

            best_idx = torch.argmax(probs).item()
            best_nli = NLI_LABELS[best_idx] if best_idx < len(NLI_LABELS) else "neutral"
            
            mapped_label = NLI_TO_THREAT.get(best_nli, "SUSPICIOUS")
            confidence = probs[best_idx].item()

            all_scores = self._nli_probs_to_all_scores(probs)
            all_scores[mapped_label] = confidence * 100

            return {
                "label": mapped_label,
                "confidence": confidence,
                "all_scores": all_scores
            }
        except Exception as e:
            logger.warning(f"Zero-shot classification failed: {e}, falling back to rules")
            return self._classify_rules(text, subject)

    def _classify_hybrid(self, text: str, subject: str = "") -> dict[str, Any]:
        """Hybrid classification: weighted blend of lexical + zero-shot."""
        if self.model is None or self.tokenizer is None:
            return self._classify_rules(text, subject)

        lexical_result = self._classify_rules(text, subject)
        
        try:
            combined = f"{subject} [SEP] {text}" if subject else text
            words = combined.split()
            if len(words) > self.max_length:
                combined = " ".join(words[:self.max_length])

            inputs = self.tokenizer(combined, return_tensors="pt", truncation=True, max_length=self.max_length)
            inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1)[0]

            zero_shot_scores = self._nli_probs_to_all_scores(probs)

            all_scores = {}
            lexical_weight = self.hybrid_weights.get("lexical", 0.65)
            zero_shot_weight = self.hybrid_weights.get("zero_shot", 0.35)

            for label in set(list(lexical_result["all_scores"].keys()) + list(zero_shot_scores.keys())):
                lex_score = lexical_result["all_scores"].get(label, 0.0)
                zs_score = zero_shot_scores.get(label, 0.0)
                all_scores[label] = min(100.0, lex_score * lexical_weight + zs_score * zero_shot_weight)

            best_label = max(all_scores, key=all_scores.get)
            confidence = all_scores[best_label] / 100.0 if all_scores[best_label] > 0 else 0.5

            return {
                "label": best_label,
                "confidence": confidence,
                "all_scores": all_scores
            }
        except Exception as e:
            logger.warning(f"Hybrid zero-shot failed: {e}, falling back to lexical")
            return lexical_result

    def _nli_probs_to_all_scores(self, probs: torch.Tensor) -> dict[str, float]:
        """Convert NLI model probabilities to all_scores dict."""
        all_scores = {label: 0.0 for label in [
            "LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION",
            "BEC_PAYMENT_DIVERSION", "CREDENTIAL_HARVESTING", "MALWARE_DELIVERY"
        ]}

        for i, nli_label in enumerate(NLI_LABELS):
            if i < len(probs):
                prob_val = probs[i].item()
                mapped = NLI_TO_THREAT.get(nli_label)
                if mapped:
                    all_scores[mapped] = max(all_scores.get(mapped, 0.0), prob_val * 100)

        for key in all_scores:
            all_scores[key] = min(100.0, max(0.0, all_scores[key]))

        return all_scores

    def get_text_score(self, text: str, subject: str = "") -> float:
        """Get a 0-100 threat score for text tower (uses lexical rules only)."""
        flags = self.text_features.extract(text, subject)
        return flags["overall_score"]

    def get_mode(self) -> str:
        """Return current operating mode."""
        return self.mode

    def is_model_loaded(self) -> bool:
        """Return whether transformer model is loaded."""
        return self._loaded and not self._load_failed and self.model is not None
