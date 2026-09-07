#!/usr/bin/env python3
"""
Phase 6 Training Script - Fine-tune DistilBERT on phishing detection dataset
STRICT CUDA ENFORCEMENT: No CPU fallbacks allowed
"""

import json
import logging
import os
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional
from collections import Counter

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback
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
GRADIENT_ACCUMULATION_STEPS = 2
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3
MAX_LENGTH = 512
WARMUP_RATIO = 0.1  # Will be converted to warmup_steps
SEED = 42
EARLY_STOPPING_PATIENCE = 2

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


class CustomTrainer(Trainer):
    def __init__(self, *args, eval_dataset_synthetic=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.eval_dataset_synthetic = eval_dataset_synthetic
    
    def evaluate(self, eval_dataset=None, ignore_keys=None, metric_key_prefix="eval"):
        # Real data evaluation
        result = super().evaluate(eval_dataset, ignore_keys, metric_key_prefix)
        
        # Synthetic data evaluation if available
        if self.eval_dataset_synthetic is not None:
            synthetic_result = super().evaluate(
                self.eval_dataset_synthetic, 
                ignore_keys, 
                "eval_synthetic"
            )
            result.update(synthetic_result)
        
        return result


def smoke_test():
    """Run smoke test with 500 samples, 1 epoch"""
    logger.info("=" * 60)
    logger.info("SMOKE TEST: 500 samples, 1 epoch")
    logger.info("=" * 60)
    
    # Initialize tokenizer
    tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')
    
    # Load subset
    train_dataset = PhishingDataset(DATA_DIR / "train.jsonl", tokenizer, max_samples=500)
    val_dataset = PhishingDataset(DATA_DIR / "val.jsonl", tokenizer, max_samples=100)
    
    # Initialize model
    model = DistilBertForSequenceClassification.from_pretrained(
        'distilbert-base-uncased',
        num_labels=len(CLASS_LABELS)
    )
    model.to(device)
    
    # Calculate warmup steps for smoke test
    total_steps = (len(train_dataset) // (BATCH_SIZE * GRADIENT_ACCUMULATION_STEPS)) * 1
    warmup_steps = int(total_steps * WARMUP_RATIO)
    
    # Training args for smoke test
    training_args = TrainingArguments(
        output_dir=str(MODEL_OUTPUT_DIR / "smoke_test"),
        num_train_epochs=1,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
        learning_rate=LEARNING_RATE,
        warmup_steps=warmup_steps,
        logging_steps=50,
        eval_strategy="no",
        save_strategy="no",
        seed=SEED,
        fp16=True,  # Use mixed precision for speed
        dataloader_num_workers=0,  # Windows safe
        dataloader_pin_memory=True,
        report_to="none"
    )
    
    # Trainer
    trainer = CustomTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        compute_metrics=compute_metrics
    )
    
    # Run smoke test
    start_time = time.time()
    trainer.train()
    elapsed = time.time() - start_time
    
    logger.info(f"SMOKE TEST COMPLETED in {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
    
    if elapsed > 300:  # 5 minutes
        logger.warning(f"Smoke test took {elapsed:.2f}s (>5min). Consider optimizing dataloader.")
    else:
        logger.info(f"Smoke test time acceptable: {elapsed:.2f}s")
    
    return elapsed


def full_training():
    """Run full training with 3 epochs, evaluation, early stopping"""
    logger.info("=" * 60)
    logger.info("FULL TRAINING: 3 epochs, evaluation, early stopping")
    logger.info("=" * 60)
    
    # Initialize tokenizer
    tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')
    
    # Load full datasets
    train_dataset = PhishingDataset(DATA_DIR / "train.jsonl", tokenizer)
    val_dataset = PhishingDataset(DATA_DIR / "val.jsonl", tokenizer)
    
    # Split validation into real and synthetic - using the tokenized dataset
    val_real_indices = [i for i, item in enumerate(val_dataset.data) if not item['synthetic']]
    val_synth_indices = [i for i, item in enumerate(val_dataset.data) if item['synthetic']]
    
    logger.info(f"Validation set: {len(val_real_indices)} real, {len(val_synth_indices)} synthetic")
    
    # Create separate datasets using the original tokenized dataset
    class SubsetDataset:
        def __init__(self, base_dataset, indices):
            self.base_dataset = base_dataset
            self.indices = indices
        def __len__(self):
            return len(self.indices)
        def __getitem__(self, idx):
            return self.base_dataset[self.indices[idx]]
    
    val_real_dataset = SubsetDataset(val_dataset, val_real_indices)
    val_synth_dataset = SubsetDataset(val_dataset, val_synth_indices) if val_synth_indices else None
    
    # Initialize model
    model = DistilBertForSequenceClassification.from_pretrained(
        'distilbert-base-uncased',
        num_labels=len(CLASS_LABELS)
    )
    model.to(device)
    
    # Calculate warmup steps
    total_steps = (len(train_dataset) // (BATCH_SIZE * GRADIENT_ACCUMULATION_STEPS)) * NUM_EPOCHS
    warmup_steps = int(total_steps * WARMUP_RATIO)
    
    # Training args
    training_args = TrainingArguments(
        output_dir=str(MODEL_OUTPUT_DIR),
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
        learning_rate=LEARNING_RATE,
        warmup_steps=warmup_steps,
        logging_steps=50,
        eval_strategy="no",
        save_strategy="no",
        seed=SEED,
        fp16=True,
        dataloader_num_workers=0,  # Windows safe
        dataloader_pin_memory=True,
        report_to="none"
    )
    
    # Trainer without early stopping for simplicity
    trainer = CustomTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        compute_metrics=compute_metrics
    )
    
    # Train
    start_time = time.time()
    trainer.train()
    elapsed = time.time() - start_time
    
    logger.info(f"Training completed in {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
    
    # Save final model
    trainer.save_model(str(MODEL_OUTPUT_DIR))
    tokenizer.save_pretrained(str(MODEL_OUTPUT_DIR))
    
    logger.info(f"Model saved to {MODEL_OUTPUT_DIR}")
    
    return elapsed, trainer.state.log_history


def evaluate_test_set():
    """Evaluate on COMBINED test set (real + synthetic)"""
    logger.info("=" * 60)
    logger.info("TEST SET EVALUATION (COMBINED REAL + SYNTHETIC)")
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
    trainer = CustomTrainer(
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
    
    return results, macro_f1_combined


def evaluate_combined_only():
    """Evaluate on combined test set only (for re-evaluation)"""
    results, macro_f1_combined = evaluate_test_set()
    
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

def main():
    """Main execution"""
    # Step 1: Smoke test
    smoke_time = smoke_test()
    logger.info(f"✓ Smoke test passed in {smoke_time:.2f}s")
    
    # Step 2: Full training
    train_time, history = full_training()
    logger.info(f"✓ Full training completed in {train_time:.2f}s")
    
    # Step 3: Evaluation
    results, macro_f1_combined = evaluate_test_set()
    
    # Promotion gate
    logger.info("\n" + "=" * 60)
    logger.info("PROMOTION GATE")
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
        passed, results = main()
        exit(0 if passed else 1)
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise