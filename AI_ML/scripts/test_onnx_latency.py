#!/usr/bin/env python3
"""
CPU Latency Test: Measure p50/p95 latency for ONNX model
Requirement: p95 ≤ 150ms
"""

import logging
import time
import numpy as np
from pathlib import Path
from transformers import AutoTokenizer
from optimum.onnxruntime import ORTModelForSequenceClassification

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ONNX_OUTPUT_DIR = PROJECT_ROOT / "models" / "distilbert-phishing-v1" / "onnx"

# Sample texts for latency testing
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
    "Legitimate business communication regarding project timeline.",
    "Team meeting scheduled for tomorrow at 10am.",
    "Please review the attached quarterly report.",
    "Action required: Approve the pending purchase order.",
    "Your invoice has been processed successfully.",
    "Meeting notes from yesterday's discussion attached.",
    "Project deadline extension request approved.",
    "Please sign the attached contract document.",
    "Your support ticket has been resolved.",
    "Weekly team sync meeting reminder.",
    "Document review request for approval.",
    "Your leave request has been approved.",
    "Important client meeting preparation notes.",
    "Please confirm your attendance for the training session.",
    "Your expense report has been processed.",
    "Team building event invitation for next week.",
    "Project milestone achievement notification.",
    "Your performance review is scheduled for next month.",
    "Please complete the required compliance training.",
    "New company policy document attached for review.",
    "Your password change request has been confirmed.",
    "Meeting rescheduled to next week Tuesday.",
    "Please provide feedback on the proposed changes.",
    "Your account settings have been updated successfully.",
    "Important announcement regarding office closure.",
    "Please review the updated project timeline.",
    "Your access request has been approved.",
    "Monthly newsletter subscription confirmation.",
    "Please complete the employee satisfaction survey.",
    "Your timesheet submission reminder.",
    "New product launch announcement details.",
    "Please confirm your travel arrangements.",
    "Your direct deposit information updated.",
    "Important security training required for all staff.",
    "Meeting agenda for upcoming board meeting.",
    "Please update your emergency contact information.",
    "Your certification renewal deadline approaching.",
    "New office location and contact information.",
    "Please complete the mandatory ethics training.",
    "Your workspace assignment has been confirmed.",
    "Important reminder about upcoming holidays.",
    "Please review the updated safety protocols.",
    "Your user account permissions have been modified.",
    "Company annual meeting invitation details.",
    "Please confirm your benefit enrollment selections.",
    "Your parking permit application status update.",
    "Important changes to IT support procedures.",
    "Please review the new employee handbook.",
    "Your email signature needs to be updated.",
    "Meeting invitation for cross-functional collaboration.",
    "Please complete the required security awareness training.",
    "Your access card replacement request processed.",
    "Important information about workplace accommodations.",
    "Please update your department directory information.",
    "Your project budget approval notification.",
    "Meeting to discuss quarterly goals and objectives.",
    "Please confirm your attendance at the town hall.",
    "Your performance goals for the current quarter.",
]

def run_latency_test():
    """Run CPU latency test for ONNX model"""
    logger.info("=" * 60)
    logger.info("CPU LATENCY TEST: ONNX Model")
    logger.info("=" * 60)
    
    # Force CPU inference
    import os
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    
    # Load tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(str(ONNX_OUTPUT_DIR))
    
    # Load ONNX model (CPU)
    logger.info("Loading ONNX model on CPU...")
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
    
    # Warm-up runs
    logger.info("Running warm-up...")
    for _ in range(5):
        _ = onnx_model(**inputs)
    
    # Latency measurements
    logger.info("Running latency measurements...")
    latencies = []
    
    for i in range(100):
        start_time = time.time()
        _ = onnx_model(**inputs)
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        latencies.append(latency_ms)
        
        if (i + 1) % 20 == 0:
            logger.info(f"Completed {i + 1}/100 runs")
    
    # Calculate statistics
    latencies_array = np.array(latencies)
    p50 = np.percentile(latencies_array, 50)
    p95 = np.percentile(latencies_array, 95)
    p99 = np.percentile(latencies_array, 99)
    mean = np.mean(latencies_array)
    std = np.std(latencies_array)
    
    logger.info("\n" + "=" * 60)
    logger.info("LATENCY TEST RESULTS")
    logger.info("=" * 60)
    logger.info(f"p50 (median): {p50:.2f} ms")
    logger.info(f"p95: {p95:.2f} ms")
    logger.info(f"p99: {p99:.2f} ms")
    logger.info(f"Mean: {mean:.2f} ms")
    logger.info(f"Std Dev: {std:.2f} ms")
    logger.info(f"Min: {np.min(latencies_array):.2f} ms")
    logger.info(f"Max: {np.max(latencies_array):.2f} ms")
    
    # Promotion gate
    logger.info("\n" + "=" * 60)
    logger.info("LATENCY TEST GATE")
    logger.info("=" * 60)
    logger.info(f"p95: {p95:.2f} ms")
    logger.info(f"Threshold: 150 ms")
    
    if p95 <= 150:
        logger.info("✓ LATENCY TEST PASSED")
        return True, p50, p95
    else:
        logger.info("✗ LATENCY TEST FAILED")
        return False, p50, p95

if __name__ == "__main__":
    try:
        passed, p50, p95 = run_latency_test()
        logger.info(f"\nFinal Latency Metrics: p50={p50:.2f}ms, p95={p95:.2f}ms")
        exit(0 if passed else 1)
    except Exception as e:
        logger.error(f"Latency test failed: {e}")
        raise