import logging
from dataclasses import dataclass
from typing import Dict, Any
import torch

from config.config import (
    TextModelMode, ThreatLabel, DEVICE, TEXT_MODEL_MODE,
    ZERO_SHOT_MODEL_NAME, ZERO_SHOT_LABELS, ZERO_SHOT_LABEL_MAP,
    FINE_TUNED_MODEL_DIR
)

# 7-class label mapping for fine-tuned model
CLASS_LABELS = [
    "LEGITIMATE",
    "SUSPICIOUS", 
    "PHISHING",
    "IMPERSONATION",
    "BEC_PAYMENT_DIVERSION",
    "CREDENTIAL_HARVESTING",
    "MALWARE_DELIVERY"
]

label_to_id = {label: idx for idx, label in enumerate(CLASS_LABELS)}
id_to_label = {idx: label for label, idx in label_to_id.items()}

logger = logging.getLogger(__name__)

@dataclass
class NLPResult:
    label: ThreatLabel
    confidence: float
    scores: Dict[str, float]
    model_name: str
    mode: TextModelMode

    def to_dict(self) -> dict:
        return {
            "label": self.label.value if hasattr(self.label, 'value') else self.label,
            "confidence": self.confidence,
            "scores": self.scores,
            "model_name": self.model_name,
            "mode": self.mode.value if hasattr(self.mode, 'value') else self.mode
        }

class NLPClassifier:
    def __init__(self, mode: TextModelMode = None, device: str = None):
        self._active_mode = mode if mode is not None else TEXT_MODEL_MODE
        self.device = device if device is not None else DEVICE
        self._pipeline = None
        self._onnx_model = None
        self._tokenizer = None
        self._model_name = "unknown"

        if self._active_mode == TextModelMode.ZERO_SHOT:
            try:
                from transformers import pipeline
                # Use device 0 for cuda, -1 for cpu/mps fallback handling
                dev = 0 if self.device.startswith("cuda") else -1 
                self._pipeline = pipeline(
                    "zero-shot-classification",
                    model=ZERO_SHOT_MODEL_NAME,
                    device=dev
                )
                self._model_name = ZERO_SHOT_MODEL_NAME
            except Exception as e:
                logger.warning(f"Failed to load ZERO_SHOT model {ZERO_SHOT_MODEL_NAME}: {e}. Falling back to RULES_ONLY.")
                self._active_mode = TextModelMode.RULES_ONLY
                self._model_name = "rules_heuristic"

        elif self._active_mode == TextModelMode.FINE_TUNED:
            try:
                from optimum.onnxruntime import ORTModelForSequenceClassification
                from transformers import AutoTokenizer
                
                # Load ONNX model and tokenizer
                self._onnx_model = ORTModelForSequenceClassification.from_pretrained(str(FINE_TUNED_MODEL_DIR))
                self._tokenizer = AutoTokenizer.from_pretrained(str(FINE_TUNED_MODEL_DIR))
                self._model_name = str(FINE_TUNED_MODEL_DIR)
                
                logger.info(f"Loaded ONNX fine-tuned model from {FINE_TUNED_MODEL_DIR}")
            except Exception as e:
                logger.warning(f"Failed to load FINE_TUNED ONNX model from {FINE_TUNED_MODEL_DIR}: {e}. Falling back to ZERO_SHOT.")
                self._active_mode = TextModelMode.ZERO_SHOT
                try:
                    from transformers import pipeline
                    dev = 0 if self.device.startswith("cuda") else -1 
                    self._pipeline = pipeline(
                        "zero-shot-classification",
                        model=ZERO_SHOT_MODEL_NAME,
                        device=dev
                    )
                    self._model_name = ZERO_SHOT_MODEL_NAME
                except Exception as e2:
                    logger.warning(f"Failed to load ZERO_SHOT fallback: {e2}. Falling back to RULES_ONLY.")
                    self._active_mode = TextModelMode.RULES_ONLY
                    self._model_name = "rules_heuristic"
        
    def classify(self, text: str) -> NLPResult:
        if not text or not text.strip():
            return NLPResult(
                label=ThreatLabel.LEGITIMATE,
                confidence=0.5,
                scores={},
                model_name="fallback",
                mode=self._active_mode
            )

        if self._active_mode == TextModelMode.ZERO_SHOT:
            # Truncate text to approx 1500 chars for ~512 tokens estimate
            truncated_text = text[:1500]
            result = self._pipeline(truncated_text, candidate_labels=ZERO_SHOT_LABELS, multi_label=False)
            
            top_label_str = result["labels"][0]
            top_score = result["scores"][0]
            
            label = ZERO_SHOT_LABEL_MAP.get(top_label_str, ThreatLabel.LEGITIMATE)
            scores = {lbl: scr for lbl, scr in zip(result["labels"], result["scores"])}
            
            return NLPResult(
                label=label,
                confidence=top_score,
                scores=scores,
                model_name=ZERO_SHOT_MODEL_NAME,
                mode=self._active_mode
            )

        elif self._active_mode == TextModelMode.FINE_TUNED:
            truncated_text = text[:1500]
            
            # ONNX inference
            inputs = self._tokenizer(
                truncated_text,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt"
            )
            
            outputs = self._onnx_model(**inputs)
            logits = outputs.logits
            predictions = torch.argmax(logits, dim=1)
            
            label_idx = predictions.item()
            label_str = id_to_label.get(label_idx, "LEGITIMATE")
            score = torch.softmax(logits, dim=1)[0][label_idx].item()
            
            try:
                label = ThreatLabel(label_str)
            except ValueError:
                label = ThreatLabel.LEGITIMATE

            return NLPResult(
                label=label,
                confidence=score,
                scores={label.value if hasattr(label, 'value') else label: score},
                model_name=str(FINE_TUNED_MODEL_DIR),
                mode=self._active_mode
            )

        else:
            # RULES_ONLY
            phishing_keywords = {"verify", "account", "password", "urgent", "suspended", "click", "login", "credentials", "security alert", "unauthorized"}
            legitimate_keywords = {"meeting", "project", "schedule", "team", "quarterly", "update", "agenda", "minutes", "review", "discussion"}
            
            text_lower = text.lower()
            phishing_count = sum(1 for word in phishing_keywords if word in text_lower)
            legitimate_count = sum(1 for word in legitimate_keywords if word in text_lower)
            
            if phishing_count > legitimate_count + 2:
                label = ThreatLabel.PHISHING
                confidence = min(0.5 + phishing_count * 0.05, 0.85)
            elif phishing_count > legitimate_count:
                label = ThreatLabel.SPAM
                confidence = 0.5
            else:
                label = ThreatLabel.LEGITIMATE
                confidence = min(0.5 + legitimate_count * 0.03, 0.85)
            
            all_labels = [l.value if hasattr(l, 'value') else l for l in ThreatLabel]
            n = len(all_labels)
            scores = {}
            for l in all_labels:
                lbl_val = label.value if hasattr(label, 'value') else label
                if l == lbl_val:
                    scores[l] = confidence
                else:
                    scores[l] = (1.0 - confidence) / max(1, (n - 1))
                    
            return NLPResult(
                label=label,
                confidence=confidence,
                scores=scores,
                model_name="rules_heuristic",
                mode=self._active_mode
            )
