#!/usr/bin/env python3
"""
Export fine-tuned DistilBERT to ONNX int8 format via optimum
"""

import logging
from pathlib import Path
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_OUTPUT_DIR = PROJECT_ROOT / "models" / "distilbert-phishing-v1"
ONNX_OUTPUT_DIR = MODEL_OUTPUT_DIR / "onnx"

def export_to_onnx_int8():
    """Export model to ONNX int8 format"""
    logger.info("=" * 60)
    logger.info("EXPORTING TO ONNX INT8")
    logger.info("=" * 60)
    
    # Load tokenizer
    logger.info(f"Loading tokenizer from {MODEL_OUTPUT_DIR}")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_OUTPUT_DIR))
    
    # Export to ONNX with dynamic quantization (int8)
    logger.info(f"Exporting model to ONNX int8 at {ONNX_OUTPUT_DIR}")
    model = ORTModelForSequenceClassification.from_pretrained(
        str(MODEL_OUTPUT_DIR),
        export=True
    )
    
    # Save the model and tokenizer
    logger.info(f"Saving ONNX model to {ONNX_OUTPUT_DIR}")
    model.save_pretrained(str(ONNX_OUTPUT_DIR))
    tokenizer.save_pretrained(str(ONNX_OUTPUT_DIR))
    
    logger.info("✓ ONNX export completed successfully")
    logger.info(f"Model saved to: {ONNX_OUTPUT_DIR}")
    
    return ONNX_OUTPUT_DIR

if __name__ == "__main__":
    try:
        onnx_dir = export_to_onnx_int8()
        logger.info(f"Export successful: {onnx_dir}")
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise