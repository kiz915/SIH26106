#!/usr/bin/env python3
"""
Parity test: Compare PyTorch vs ONNX outputs
Expected: >= 98% argmax match
"""

import logging
import time
import numpy as np
import torch
from pathlib import Path
from transformers import AutoTokenizer, DistilBertForSequenceClassification
from optimum.onnxruntime import ORTModelForSequenceClassification

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_OUTPUT_DIR = PROJECT_ROOT / "models" / "distilbert-phishing-v1"
ONNX_OUTPUT_DIR = MODEL_OUTPUT_DIR / "onnx"

# Sample texts for testing
TEST_TEXTS = [
    "This is a legitimate business email about our quarterly meeting.",
    "URGENT: Your account will be suspended unless you click this link immediately.",
    "Dear friend, I am a Nigerian prince and I need your help to transfer $30 million.",
    "Please update your password by clicking on this suspicious link.",
    "Invoice attached for payment - please review and process.",
    "Your Microsoft account has been compromised - verify your credentials now.",
    "Download this free software to improve your computer performance.",
    "CEO requesting urgent wire transfer to new bank account.",
    "Confirm your identity by providing your social security number.",
    "Meeting reminder: Project review at 2pm today.",
    "You have won a lottery! Click here to claim your prize.",
    "Security alert: Unusual login detected from unknown location.",
    "Please verify your email address by clicking this link.",
    "Your order has been shipped - track your package here.",
    "Free gift card offer - limited time only!",
    "Update your payment information to avoid service interruption.",
    "Important notice about your account security settings.",
    "Congratulations! You've been selected for a special offer.",
    "Please review the attached document and provide feedback.",
    "Click here to unsubscribe from our mailing list.",
    "Your account password needs to be reset immediately.",
    "Confirm your identity by entering your credentials.",
    "Download this antivirus software to protect your computer.",
    "Urgent: Payment required for your recent purchase.",
    "Your subscription is about to expire - renew now.",
    "New login detected from unfamiliar device.",
    "Verify your account information to continue service.",
    "Important security update for your account.",
    "Click here to claim your free trial offer.",
    "Your payment method needs to be updated.",
    "Suspicious activity detected on your account.",
    "Free download available for limited time.",
    "Confirm your email address to continue.",
    "Your account has been locked due to suspicious activity.",
    "Download this software to fix your computer issues.",
    "Urgent action required: Verify your identity.",
    "Your subscription has been successfully renewed.",
    "Click here to access your account dashboard.",
    "Payment confirmation for your recent order.",
    "Your password has been successfully changed.",
    "Important notice regarding your account security.",
    "Free upgrade available for your account.",
    "Your account will be deactivated unless you act now.",
    "Confirm your identity to restore account access.",
    "Download this file to view important information.",
    "Your payment has been processed successfully.",
    "Security alert: Your account needs verification.",
    "Click here to update your account preferences.",
    "Your subscription will expire in 3 days.",
    "Important: Your account requires immediate attention.",
    "Free software download to enhance productivity.",
    "Confirm your identity to prevent account suspension.",
    "Your recent transaction has been completed.",
    "Security warning: Unusual account activity detected.",
    "Click here to claim your exclusive reward.",
    "Your account information needs to be updated.",
]

def run_parity_test():
    """Run parity test between PyTorch and ONNX models"""
    logger.info("=" * 60)
    logger.info("PARITY TEST: PyTorch vs ONNX")
    logger.info("=" * 60)
    
    # Load tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_OUTPUT_DIR))
    
    # Load PyTorch model
    logger.info("Loading PyTorch model...")
    pytorch_model = DistilBertForSequenceClassification.from_pretrained(str(MODEL_OUTPUT_DIR))
    pytorch_model.eval()
    
    # Load ONNX model
    logger.info("Loading ONNX model...")
    onnx_model = ORTModelForSequenceClassification.from_pretrained(str(ONNX_OUTPUT_DIR))
    
    # Tokenize inputs
    logger.info(f"Testing with {len(TEST_TEXTS)} samples...")
    inputs = tokenizer(
        TEST_TEXTS,
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )
    
    # Run PyTorch inference
    logger.info("Running PyTorch inference...")
    with torch.no_grad():
        pytorch_outputs = pytorch_model(**inputs)
        pytorch_predictions = torch.argmax(pytorch_outputs.logits, dim=1)
    
    # Run ONNX inference
    logger.info("Running ONNX inference...")
    onnx_outputs = onnx_model(**inputs)
    onnx_predictions = torch.argmax(onnx_outputs.logits, dim=1)
    
    # Compare predictions
    pytorch_preds = pytorch_predictions.cpu().numpy()
    onnx_preds = onnx_predictions.cpu().numpy()
    
    matches = (pytorch_preds == onnx_preds).sum()
    total = len(pytorch_preds)
    match_rate = matches / total * 100
    
    logger.info(f"Matches: {matches}/{total} ({match_rate:.2f}%)")
    
    # Detailed comparison
    mismatches = np.where(pytorch_preds != onnx_preds)[0]
    if len(mismatches) > 0:
        logger.warning(f"Mismatches at indices: {mismatches}")
        for idx in mismatches[:5]:  # Show first 5 mismatches
            logger.warning(f"  Index {idx}: PyTorch={pytorch_preds[idx]}, ONNX={onnx_preds[idx]}")
    
    # Promotion gate
    logger.info("\n" + "=" * 60)
    logger.info("PARITY TEST RESULTS")
    logger.info("=" * 60)
    logger.info(f"Match Rate: {match_rate:.2f}%")
    logger.info(f"Threshold: 98%")
    
    if match_rate >= 98:
        logger.info("✓ PARITY TEST PASSED")
        return True
    else:
        logger.info("✗ PARITY TEST FAILED")
        return False

if __name__ == "__main__":
    import torch
    try:
        passed = run_parity_test()
        exit(0 if passed else 1)
    except Exception as e:
        logger.error(f"Parity test failed: {e}")
        raise