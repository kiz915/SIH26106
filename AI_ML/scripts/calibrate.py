"""Calibration script for classifier confidence scores."""

import json
import joblib
import numpy as np
from pathlib import Path
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from ml import EmailAnalyzer
from ml.schemas import LABELS


def load_validation_data(val_path: str, max_samples: int = 2000) -> tuple:
    """Load validation data and return texts and labels."""
    texts = []
    labels = []
    
    with open(val_path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= max_samples:
                break
            data = json.loads(line)
            texts.append(data["text"])
            labels.append(data["label"])
    
    return texts, labels


def get_predictions(analyzer: EmailAnalyzer, texts: list[str]) -> tuple:
    """Get classifier predictions for texts."""
    all_scores_list = []
    pred_labels = []
    confidences = []
    
    for text in texts:
        result = analyzer.classifier.classify(text, "")
        all_scores = result["all_scores"]
        label = result["label"]
        confidence = result["confidence"]
        
        # Convert all_scores to probability distribution
        scores_array = np.array([all_scores.get(l, 0.0) for l in LABELS])
        # Normalize to probabilities
        if scores_array.sum() > 0:
            probs = scores_array / scores_array.sum()
        else:
            probs = np.ones(len(LABELS)) / len(LABELS)
        
        all_scores_list.append(probs)
        pred_labels.append(label)
        confidences.append(confidence)
    
    return np.array(all_scores_list), pred_labels, np.array(confidences)


def calibrate_confidence(val_probs: np.ndarray, val_labels: list[str], confidences: np.ndarray) -> tuple:
    """
    Calibrate confidence scores using isotonic regression.
    
    We calibrate the confidence of the predicted class.
    """
    label_to_idx = {label: i for i, label in enumerate(LABELS)}
    
    # Get confidence for the true class
    y_true = np.array([label_to_idx[l] for l in val_labels])
    y_pred = np.argmax(val_probs, axis=1)
    y_conf = confidences
    
    # For calibration, we need binary: correct or incorrect
    y_correct = (y_pred == y_true).astype(int)
    
    # Fit isotonic regression on confidence -> correctness
    iso_reg = IsotonicRegression(out_of_bounds="clip")
    iso_reg.fit(y_conf, y_correct)
    
    # Also fit a logistic regression as backup
    lr = LogisticRegression()
    lr.fit(y_conf.reshape(-1, 1), y_correct)
    
    return iso_reg, lr


def main():
    print("Loading validation data...")
    texts, labels = load_validation_data("data/processed/val.jsonl", max_samples=1000)
    print(f"Loaded {len(texts)} validation samples")
    
    print("Initializing analyzer...")
    analyzer = EmailAnalyzer()
    analyzer.warmup()
    
    print("Getting predictions...")
    val_probs, pred_labels, confidences = get_predictions(analyzer, texts)
    
    print("Calibrating...")
    iso_reg, lr = calibrate_confidence(val_probs, labels, confidences)
    
    # Save calibrators
    output_dir = Path("models/calibration")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(iso_reg, output_dir / "isotonic_calibrator.pkl")
    joblib.dump(lr, output_dir / "logistic_calibrator.pkl")
    
    # Test calibration
    print("\nCalibration results:")
    print(f"  Original accuracy: {(np.array(pred_labels) == np.array(labels)).mean():.3f}")
    
    # Calibrate confidences
    cal_conf_iso = iso_reg.predict(confidences)
    cal_conf_lr = lr.predict_proba(confidences.reshape(-1, 1))[:, 1]
    
    print(f"  Mean original confidence: {confidences.mean():.3f}")
    print(f"  Mean isotonic calibrated: {cal_conf_iso.mean():.3f}")
    print(f"  Mean logistic calibrated: {cal_conf_lr.mean():.3f}")
    
    # Save calibration metadata
    meta = {
        "method": "isotonic",
        "n_samples": len(texts),
        "original_accuracy": float((np.array(pred_labels) == np.array(labels)).mean()),
        "mean_original_confidence": float(confidences.mean()),
        "mean_calibrated_confidence": float(cal_conf_iso.mean()),
    }
    with open(output_dir / "calibration_meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    
    print(f"\nCalibrators saved to {output_dir}")


if __name__ == "__main__":
    main()