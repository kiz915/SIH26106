#!/usr/bin/env python3
"""
Combined Test Set Evaluation - Re-evaluate on full test set (real + synthetic)
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import torch
import torch.nn as nn
from torch.utils.data import Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments
)
from sklearn.metrics import precision_recall_fscore_support, accuracy_score
import numpy as np

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# STRICT DEVICE ENFORCEMENT
device = torch.device("cuda")
logger.info(f"Using device: {device}")
if not torch.cuda.is_available():
    raise RuntimeError("FATAL: CUDA is not available. This script requires CUDA.")

# Hyperparameters
BATCH_SIZE = 16
MAX_LENGTH = 512
SEED = 42

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_OUTPUT_DIR = PROJECT_ROOT / "models" / "distilbert-phishing-v1"

# Set random seeds
torch.manual_seed(SEED)
np.random.seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

# 7-class enum as per contract
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


class PhishingDataset(Dataset):
    def __init__(self, data_path: Path, tokenizer: DistilBertTokenizerFast, max_samples: Optional[int] = None):
        self.tokenizer = tokenizer
        self.data = []
        self.max_length = MAX_LENGTH
        
        logger.info(f"Loading data from {data_path}")
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                if max_samples and len(self.data) >= max_samples:
                    break
                item = json.loads(line)
                self.data.append({
                    'text': item['text'],
                    'label': label_to_id[item['label']],
                    'synthetic': item.get('synthetic', False)
                })
        
        logger.info(f"Loaded {len(self.data)} samples")
        
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        item = self.data[idx]
        # Tokenize on the fly
        encoding = self.tokenizer(
            item['text'],
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(item['label'], dtype=torch.long)
        }


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=1)
    
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='macro', zero_division=0
    )
    accuracy = accuracy_score(labels, predictions)
    
    # Per-class metrics
    per_class_precision, per_class_recall, per_class_f1, _ = precision_recall_fscore_support(
        labels, predictions, average=None, zero_division=0
    )
    
    metrics = {
        'accuracy': accuracy,
        'macro_precision': precision,
        'macro_recall': recall,
        'macro_f1': f1
    }
    
    # Add per-class metrics only for classes present in the data
    unique_labels = np.unique(labels)
    for idx, label_idx in enumerate(unique_labels):
        label_name = id_to_label[label_idx]
        metrics[f'{label_name}_precision'] = per_class_precision[idx]
        metrics[f'{label_name}_recall'] = per_class_recall[idx]
        metrics[f'{label_name}_f1'] = per_class_f1[idx]
    
    return metrics


def evaluate_combined():
    """Evaluate on COMBINED test set (real + synthetic)"""
    logger.info("=" * 60)
    logger.info("COMBINED TEST SET EVALUATION (REAL + SYNTHETIC)")
    logger.info("=" * 60)
    
    # Initialize tokenizer
    tokenizer = DistilBertTokenizerFast.from_pretrained(str(MODEL_OUTPUT_DIR))
    
    # Load combined test set
    test_dataset = PhishingDataset(DATA_DIR / "test.jsonl", tokenizer)
    
    # Split into real and synthetic for reporting
    test_real_indices = [i for i, item in enumerate(test_dataset.data) if not item['synthetic']]
    test_synth_indices = [i for i, item in enumerate(test_dataset.data) if item['synthetic']]
    
    logger.info(f"Test set: {len(test_real_indices)} real, {len(test_synth_indices)} synthetic, {len(test_dataset)} total")
    
    # Load trained model
    model = DistilBertForSequenceClassification.from_pretrained(str(MODEL_OUTPUT_DIR))
    model.to(device)
    
    # Training args for evaluation
    training_args = TrainingArguments(
        output_dir=str(MODEL_OUTPUT_DIR / "eval"),
        per_device_eval_batch_size=BATCH_SIZE,
        dataloader_num_workers=0,
        dataloader_pin_memory=True,
        report_to="none"
    )
    
    # Trainer for combined evaluation
    trainer = Trainer(
        model=model,
        args=training_args,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics
    )
    
    # Evaluate on combined dataset
    results = trainer.evaluate()
    
    # Print Combined Results
    logger.info("\n" + "=" * 60)
    logger.info("COMBINED TEST SET (REAL + SYNTHETIC) - Per-class Metrics")
    logger.info("=" * 60)
    logger.info(f"{'Class':<25} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    logger.info("-" * 60)
    
    # Print only classes that have metrics
    for label in CLASS_LABELS:
        if f'eval_{label}_precision' in results:
            p = results.get(f'eval_{label}_precision', 0.0)
            r = results.get(f'eval_{label}_recall', 0.0)
            f = results.get(f'eval_{label}_f1', 0.0)
            logger.info(f"{label:<25} {p:<12.4f} {r:<12.4f} {f:<12.4f}")
    
    macro_f1_combined = results.get('eval_macro_f1', 0.0)
    logger.info("-" * 60)
    logger.info(f"{'COMBINED MACRO-F1':<25} {'':<12} {'':<12} {macro_f1_combined:<12.4f}")
    
    # Promotion gate
    logger.info("\n" + "=" * 60)
    logger.info("PROMOTION GATE (COMBINED EVALUATION)")
    logger.info("=" * 60)
    logger.info(f"Combined Macro-F1: {macro_f1_combined:.4f}")
    logger.info(f"Threshold: 0.90")
    
    if macro_f1_combined >= 0.90:
        logger.info("✓ PROMOTION GATE PASSED - Proceeding to ONNX export")
        return True, results
    else:
        logger.info("✗ PROMOTION GATE FAILED - Skipping ONNX export")
        logger.info("Model will remain in hybrid_zero_shot mode")
        return False, results


if __name__ == "__main__":
    try:
        passed, results = evaluate_combined()
        exit(0 if passed else 1)
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise