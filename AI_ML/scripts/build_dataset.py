#!/usr/bin/env python3
"""
PHASE D3: Build, Merge, and Split Dataset
SIH 2026 · Problem 26106 · AI/ML Module

Merges all sources, cleans, sub-classifies, deduplicates,
and splits into train/val/test JSONLs.

CRITICAL:
  - Test set = REAL data ONLY (no synthetic)
  - Synthetic goes to train/val only
  - Nazario sub-classification via keyword rules
"""

import collections
import email
import hashlib
import html
import json
import logging
import random
import re
import unicodedata
from collections import Counter
from email import policy
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
SYNTHETIC_DIR = BASE_DIR / "data" / "synthetic"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MANIFEST_PATH = BASE_DIR / "data" / "manifest.json"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42
TEST_FRAC = 0.10
VAL_FRAC = 0.10
ENRON_MAX_SAMPLES = 10_000

random.seed(SEED)

NAZARIO_RULES = {
    "CREDENTIAL_HARVESTING": {
        "keywords": [
            "verify account", "confirm password", "reset password", "sign in",
            "account suspended", "unusual activity", "update credentials",
        ],
        "threshold": 2,
    },
    "MALWARE_DELIVERY": {
        "keywords": [
            ".exe", ".zip", ".docm", "enable macros", "enable content",
            "attachment contains", "run the file",
        ],
        "threshold": 1,
    },
    "BEC_PAYMENT_DIVERSION": {
        "keywords": [
            "wire transfer", "payment redirect", "updated bank", "iban",
            "pending payment", "invoice #",
        ],
        "threshold": 2,
    },
    "IMPERSONATION": {
        "keywords": [
            "ceo", "cfo", "Managing Director", "in a meeting", "keep this confidential",
        ],
        "threshold": 2,
    },
}

SUSPICIOUS_LABELS = {"SUSPICIOUS", "BEC_PAYMENT_DIVERSION", "IMPERSONATION",
                      "CREDENTIAL_HARVESTING", "MALWARE_DELIVERY", "PHISHING"}


def normalize_text(text: str) -> str:
    """NFKC normalize, strip non-printable/Latin, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = html.unescape(text)
    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Lu", "Ll", "Lt", "Lm", "Lo", "Nd", "Nl", "No",
                   "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
                   "Sm", "Sc", "Sk", "So", "Zs"):
            cleaned.append(ch)
        elif ch in " \t\n\r":
            cleaned.append(" ")
    text = "".join(cleaned)
    text = re.sub(r" {2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def classify_nazario(subject: str, body: str) -> Tuple[str, int]:
    """Apply §4 keyword rules in order. Returns (label, matched_rule_idx)."""
    combined = (subject + " " + body).lower()

    rules_order = [
        ("CREDENTIAL_HARVESTING", NAZARIO_RULES["CREDENTIAL_HARVESTING"]),
        ("MALWARE_DELIVERY", NAZARIO_RULES["MALWARE_DELIVERY"]),
        ("BEC_PAYMENT_DIVERSION", NAZARIO_RULES["BEC_PAYMENT_DIVERSION"]),
        ("IMPERSONATION", NAZARIO_RULES["IMPERSONATION"]),
    ]

    for label, rule in rules_order:
        score = sum(1 for kw in rule["keywords"] if kw in combined)
        if score >= rule["threshold"]:
            return label, score

    return "PHISHING", 0


def parse_enron(csv_path: Path, max_samples: int = ENRON_MAX_SAMPLES) -> List[Dict]:
    """Parse Enron CSV in chunks, drop <50-char body, cap at max_samples."""
    logger.info(f"Parsing Enron CSV (max {max_samples} samples)...")
    records = []
    total_rows = 0
    skipped_short = 0
    skipped_parse = 0
    chunk_count = 0

    for chunk in pd.read_csv(csv_path, chunksize=5000):
        chunk_count += 1
        for _, row in chunk.iterrows():
            total_rows += 1
            raw_msg = str(row.get("message", ""))
            if not raw_msg or raw_msg == "nan":
                skipped_parse += 1
                continue

            try:
                msg = email.message_from_string(raw_msg, policy=policy.default)
            except Exception:
                skipped_parse += 1
                continue

            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            cs = part.get_content_charset() or "utf-8"
                            t = part.get_payload(decode=True).decode(cs, errors="replace")
                            body_parts.append(t)
                        except Exception:
                            pass
            else:
                try:
                    cs = msg.get_content_charset() or "utf-8"
                    b = msg.get_payload(decode=True).decode(cs, errors="replace")
                    body_parts.append(b)
                except Exception:
                    pass

            body = "\n".join(body_parts)
            if len(body.strip()) < 50:
                skipped_short += 1
                continue

            subject = msg.get("subject", "") or ""
            body = normalize_text(body)
            text = normalize_text(raw_msg)
            subject_clean = normalize_text(subject)

            records.append({
                "text": f"{subject_clean} [SEP] {body}",
                "raw_text": raw_msg,
                "subject": subject_clean,
                "body": body,
                "label": "LEGITIMATE",
                "source": "enron",
                "synthetic": False,
                "content_hash": content_hash(text),
            })

        if len(records) >= max_samples:
            break

        if chunk_count % 10 == 0:
            logger.info(f"  Chunk {chunk_count}, total rows: {total_rows}, kept: {len(records)}")

    if len(records) > max_samples:
        records = random.sample(records, max_samples)

    logger.info(f"  Enron: {total_rows} rows read, {skipped_short} dropped (<50 body), "
                f"{skipped_parse} parse failures, {len(records)} kept (capped at {max_samples})")
    return records


def parse_spamassassin_folder(folder_path: Path, is_spam_folder: bool) -> List[Dict]:
    """Parse SpamAssassin raw email files (no extension)."""
    records = []
    skipped = 0
    files = list(folder_path.iterdir())

    for fpath in files:
        try:
            raw_bytes = fpath.read_bytes()
            raw_str = raw_bytes.decode("utf-8", errors="replace")

            for enc in ("utf-8", "latin-1"):
                try:
                    msg = email.message_from_string(raw_str, policy=policy.default)
                    body_parts = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                cs = part.get_content_charset() or "utf-8"
                                t = part.get_payload(decode=True).decode(cs, errors="replace")
                                body_parts.append(t)
                    else:
                        cs = msg.get_content_charset() or "utf-8"
                        b = msg.get_payload(decode=True).decode(cs, errors="replace")
                        body_parts.append(b)
                    body = "\n".join(body_parts)
                    if len(body.strip()) < 50:
                        break
                    subject = msg.get("subject", "") or ""
                    body = normalize_text(body)
                    text = normalize_text(raw_str)
                    subject_clean = normalize_text(subject)
                    records.append({
                        "text": f"{subject_clean} [SEP] {body}",
                        "raw_text": raw_str,
                        "subject": subject_clean,
                        "body": body,
                        "label": None,
                        "source": f"spamassassin/{folder_path.parent.name}",
                        "synthetic": False,
                        "content_hash": content_hash(text),
                    })
                    break
                except Exception:
                    continue
            else:
                skipped += 1
        except Exception:
            skipped += 1

    label = "SUSPICIOUS" if is_spam_folder else "LEGITIMATE"
    for r in records:
        r["label"] = label

    logger.info(f"  SpamAssassin {folder_path.name}: {len(records)} parsed, {skipped} skipped → {label}")
    return records


def parse_nazario_phishing_csv(csv_path: Path) -> Tuple[List[Dict], Dict[str, int]]:
    """Parse Nazario phishing_email.csv with sub-classification."""
    logger.info(f"Parsing Nazario phishing_email.csv...")
    records = []
    rule_counts = Counter()
    total = 0
    skipped = 0

    for chunk in pd.read_csv(csv_path, chunksize=5000):
        for _, row in chunk.iterrows():
            total += 1
            text_raw = str(row.get("text_combined", ""))
            if not text_raw or text_raw == "nan" or len(text_raw.strip()) < 50:
                skipped += 1
                continue

            label_int = row.get("label", None)
            if label_int == 0:
                label = "LEGITIMATE"
            elif label_int == 1:
                label, score = classify_nazario("", text_raw)
                rule_counts[label] += 1
            else:
                skipped += 1
                continue

            body = normalize_text(text_raw)
            text_norm = normalize_text(text_raw)

            records.append({
                "text": body,
                "raw_text": text_raw,
                "subject": "",
                "body": body,
                "label": label,
                "source": "nazario_phishing",
                "synthetic": False,
                "content_hash": content_hash(text_norm),
            })

    logger.info(f"  Nazario phishing: {total} rows, {len(records)} kept, {skipped} skipped")
    return records, dict(rule_counts)


def parse_nazario_nigerian_csv(csv_path: Path) -> List[Dict]:
    """Parse Nigerian_Fraud.csv → all BEC_PAYMENT_DIVERSION."""
    logger.info(f"Parsing Nigerian_Fraud.csv...")
    records = []
    skipped = 0

    for chunk in pd.read_csv(csv_path, chunksize=2000):
        for _, row in chunk.iterrows():
            body = str(row.get("body", ""))
            if not body or body == "nan" or len(body.strip()) < 50:
                skipped += 1
                continue
            subject = str(row.get("subject", "") or "")
            body = normalize_text(body)
            text_norm = normalize_text(body)

            records.append({
                "text": f"{normalize_text(subject)} [SEP] {body}",
                "raw_text": body,
                "subject": normalize_text(subject),
                "body": body,
                "label": "BEC_PAYMENT_DIVERSION",
                "source": "nazario_nigerian",
                "synthetic": False,
                "content_hash": content_hash(text_norm),
            })

    logger.info(f"  Nigerian_Fraud: {len(records)} parsed, {skipped} skipped")
    return records


def load_synthetic(jsonl_path: Path) -> List[Dict]:
    """Load synthetic BEC JSONL."""
    logger.info(f"Loading synthetic BEC from {jsonl_path}...")
    records = []
    with open(jsonl_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            obj = json.loads(line)
            raw_text = obj["text"]
            body = normalize_text(raw_text)

            records.append({
                "text": body,
                "raw_text": raw_text,
                "subject": "",
                "body": body,
                "label": obj["label"],
                "source": obj.get("source", "synthetic_bec"),
                "synthetic": obj.get("synthetic", True),
                "content_hash": obj.get("email_hash", content_hash(body)),
            })
    logger.info(f"  Synthetic BEC: {len(records)} loaded")
    return records


def deduplicate(records: List[Dict]) -> Tuple[List[Dict], int]:
    """Deduplicate by content_hash. Returns (unique_records, duplicates_removed)."""
    seen = set()
    unique = []
    dupes = 0
    for r in records:
        h = r["content_hash"]
        if h not in seen:
            seen.add(h)
            unique.append(r)
        else:
            dupes += 1
    logger.info(f"  Deduplication: {len(records)} → {len(unique)} ({dupes} dupes removed)")
    return unique, dupes


def oversample_to_min(records: List[Dict], target_min: int, seed: int = SEED) -> List[Dict]:
    """Oversample minority classes to target_min per class."""
    by_label = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)

    min_count = min(len(v) for v in by_label.values())
    logger.info(f"  Class counts before oversampling: { {k: len(v) for k,v in by_label.items()} }")

    if min_count >= target_min:
        logger.info(f"  Min class ({min_count}) >= target ({target_min}), no oversampling")
        return records

    logger.info(f"  Oversampling all classes to {target_min}...")
    random.seed(seed)
    oversampled = []
    for label, recs in by_label.items():
        oversampled.extend(recs)
        needed = target_min - len(recs)
        if needed > 0:
            extra = random.choices(recs, k=needed)
            oversampled.extend(extra)
            logger.info(f"    {label}: {len(recs)} → {len(recs) + needed} (+{needed})")

    random.shuffle(oversampled)
    return oversampled


def stratified_split_2(
    records: List[Dict],
    holdout_frac: float,
    seed: int = SEED,
) -> Tuple[List[Dict], List[Dict]]:
    """Stratified 2-way split: main (1-holdout_frac) + holdout (holdout_frac)."""
    random.seed(seed)
    by_label = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)

    main, holdout = [], []
    for label, recs in by_label.items():
        random.shuffle(recs)
        n = len(recs)
        n_holdout = max(1, int(n * holdout_frac))
        holdout.extend(recs[:n_holdout])
        main.extend(recs[n_holdout:])

    random.seed(seed)
    random.shuffle(main)
    random.seed(seed)
    random.shuffle(holdout)

    return main, holdout


def verify_no_synthetic_leakage(train: List[Dict], val: List[Dict], test: List[Dict]) -> None:
    """Verify test has ZERO synthetic samples."""
    test_synth = sum(1 for r in test if r.get("synthetic", False))
    val_synth = sum(1 for r in val if r.get("synthetic", False))
    train_synth = sum(1 for r in train if r.get("synthetic", False))
    if test_synth != 0:
        raise ValueError(f"TEST SET CONTAINS {test_synth} SYNTHETIC SAMPLES!")
    logger.info(f"  Synthetic leakage check: train={train_synth}, val={val_synth}, test={test_synth} ✓")


def verify_zero_overlap(train: List[Dict], val: List[Dict], test: List[Dict]) -> None:
    """Verify zero hash overlap across splits."""
    train_h = {r["content_hash"] for r in train}
    val_h = {r["content_hash"] for r in val}
    test_h = {r["content_hash"] for r in test}

    overlaps = []
    if train_h & val_h: overlaps.append(f"train/val: {len(train_h & val_h)}")
    if train_h & test_h: overlaps.append(f"train/test: {len(train_h & test_h)}")
    if val_h & test_h: overlaps.append(f"val/test: {len(val_h & test_h)}")

    if overlaps:
        raise ValueError(f"Hash overlaps detected: {', '.join(overlaps)}")
    logger.info("  Hash overlap check: ZERO across all splits ✓")


def save_jsonl(records: List[Dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    logger.info(f"  Saved {len(records)} → {path}")


def class_table(splits: Dict[str, List[Dict]]) -> None:
    print("\n" + "=" * 72)
    print("GLOBAL CLASS DISTRIBUTION (Train / Val / Test)")
    print("=" * 72)
    header = f"{'Label':<28} {'Train':>8} {'Val':>8} {'Test':>8} {'Total':>8}"
    print(header)
    print("-" * 72)

    all_labels = set()
    for sr in splits.values():
        all_labels.update(r["label"] for r in sr)

    totals = Counter()
    rows = {}
    for label in sorted(all_labels):
        rows[label] = {}
        row_total = 0
        for split, recs in splits.items():
            cnt = sum(1 for r in recs if r["label"] == label)
            rows[label][split] = cnt
            row_total += cnt
            totals[split] = totals.get(split, 0) + cnt
        print(f"{label:<28} {rows[label].get('train',0):>8} {rows[label].get('val',0):>8} "
              f"{rows[label].get('test',0):>8} {row_total:>8}")

    print("-" * 72)
    print(f"{'TOTAL':<28} {totals.get('train',0):>8} {totals.get('val',0):>8} "
          f"{totals.get('test',0):>8} {sum(totals.values()):>8}")
    print("=" * 72)


def main():
    logger.info("=" * 60)
    logger.info("PHASE D3: Build, Merge, and Split Dataset")
    logger.info("=" * 60)

    all_real: List[Dict] = []
    all_synthetic: List[Dict] = []

    logger.info("\n[1] Parsing Enron (LEGITIMATE, capped at %d)...", ENRON_MAX_SAMPLES)
    enron_records = parse_enron(RAW_DIR / "enron" / "emails.csv", max_samples=ENRON_MAX_SAMPLES)
    all_real.extend(enron_records)

    logger.info("\n[2] Parsing SpamAssassin (ham → LEGITIMATE, spam → SUSPICIOUS)...")
    sa_ham = []
    for subdir in ["easy_ham/easy_ham", "hard_ham/hard_ham"]:
        sa_ham.extend(parse_spamassassin_folder(RAW_DIR / "spamassassin" / subdir, is_spam_folder=False))
    sa_spam = parse_spamassassin_folder(RAW_DIR / "spamassassin" / "spam_2" / "spam_2", is_spam_folder=True)
    all_real.extend(sa_ham)
    all_real.extend(sa_spam)
    logger.info(f"  SpamAssassin: ham={len(sa_ham)}, spam(SUSPICIOUS)={len(sa_spam)}")

    logger.info("\n[3] Parsing Nazario phishing_email.csv (sub-classification)...")
    nazario_phish, rule_captures = parse_nazario_phishing_csv(
        RAW_DIR / "Nazario" / "phishing_email.csv"
    )
    all_real.extend(nazario_phish)

    logger.info("\n  --- Nazario Sub-classification Capture Counts ---")
    total_captured = 0
    for label in ["CREDENTIAL_HARVESTING", "MALWARE_DELIVERY",
                  "BEC_PAYMENT_DIVERSION", "IMPERSONATION", "PHISHING"]:
        cnt = rule_captures.get(label, 0)
        total_captured += cnt
        print(f"    {label}: {cnt}")
    remaining = len(nazario_phish) - total_captured
    if remaining > 0:
        print(f"    (remaining unlabeled PHISHING): {remaining}")
    cred = rule_captures.get("CREDENTIAL_HARVESTING", 0)
    mal = rule_captures.get("MALWARE_DELIVERY", 0)
    if cred < 1500:
        print(f"    *** WARNING: CREDENTIAL_HARVESTING={cred} < 1500 — may need threshold adjustment")
    if mal < 800:
        print(f"    *** WARNING: MALWARE_DELIVERY={mal} < 800 — may need threshold adjustment")

    logger.info("\n[4] Parsing Nazario Nigerian_Fraud.csv (BEC_PAYMENT_DIVERSION)...")
    nigerian_records = parse_nazario_nigerian_csv(
        RAW_DIR / "Nazario" / "Nigerian_Fraud.csv"
    )
    all_real.extend(nigerian_records)

    logger.info("\n[5] Loading synthetic BEC (train/val only)...")
    synthetic_records = load_synthetic(SYNTHETIC_DIR / "bec_synthetic.jsonl")
    all_synthetic.extend(synthetic_records)

    logger.info("\n[6] Cleaning and normalizing all text...")
    logger.info(f"  Real records: {len(all_real)}")
    logger.info(f"  Synthetic records: {len(all_synthetic)}")

    logger.info("\n[7] Deduplicating REAL records...")
    all_real, real_dupes = deduplicate(all_real)
    all_synthetic, synth_dupes = deduplicate(all_synthetic)
    total_dupes = real_dupes + synth_dupes
    logger.info(f"  Total dupes removed: {total_dupes}")

    real_by_label = Counter(r["label"] for r in all_real)
    logger.info(f"  Real class distribution after dedup: {dict(real_by_label)}")

    logger.info("\n[8] Splitting — Test = REAL only (no synthetic)...")
    # Step 1: real data → train_val (90%) + test (10%)
    real_train_val, real_test = stratified_split_2(all_real, holdout_frac=TEST_FRAC, seed=SEED)
    # Step 2: real train_val → real_train (80%) + real_val (10%)
    val_frac_of_train_val = 0.10 / 0.90  # 0.111...
    real_train, real_val = stratified_split_2(real_train_val, holdout_frac=val_frac_of_train_val, seed=SEED)
    # Step 3: synthetic → train (90%) + val (10%), synthetic NOT in test
    synth_train, synth_val = stratified_split_2(all_synthetic, holdout_frac=0.10, seed=SEED)

    logger.info(f"  Pre-oversample: train={len(real_train)}, val={len(real_val)}, test={len(real_test)}")

    logger.info("\n[9] Oversampling minority classes in train/val (target min=1500, per-split)...")
    TARGET_MIN = 1500
    real_train = oversample_to_min(real_train, target_min=TARGET_MIN)
    real_val = oversample_to_min(real_val, target_min=TARGET_MIN)
    # NOTE: do NOT oversample test set — it must reflect true distribution

    final_train = real_train + synth_train
    final_val = real_val + synth_val
    final_test = real_test

    logger.info(f"  Split sizes: train={len(final_train)}, val={len(final_val)}, test={len(final_test)}")

    logger.info("\n[10] Verifying synthetic NOT in test...")
    verify_no_synthetic_leakage(final_train, final_val, final_test)
    verify_zero_overlap(final_train, final_val, final_test)

    logger.info("\n[11] Saving splits...")
    save_jsonl(final_train, PROCESSED_DIR / "train.jsonl")
    save_jsonl(final_val, PROCESSED_DIR / "val.jsonl")
    save_jsonl(final_test, PROCESSED_DIR / "test.jsonl")

    logger.info("\n[12] Summary tables...")
    splits = {"train": final_train, "val": final_val, "test": final_test}
    class_table(splits)

    test_synth = sum(1 for r in final_test if r.get("synthetic", False))
    val_synth = sum(1 for r in final_val if r.get("synthetic", False))
    train_synth = sum(1 for r in final_train if r.get("synthetic", False))
    print(f"\n  Synthetic Leakage Check:")
    print(f"    Train synthetic: {train_synth}")
    print(f"    Val synthetic:   {val_synth}")
    print(f"    Test synthetic:  {test_synth} ← MUST BE 0")

    print(f"\n  Deduplication: {total_dupes} duplicates removed")

    logger.info("\n[13] Updating manifest.json...")
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        manifest = {}

    manifest["phase_D3"] = {
        "status": "complete",
        "split_files": {
            "train": str(PROCESSED_DIR / "train.jsonl"),
            "val": str(PROCESSED_DIR / "val.jsonl"),
            "test": str(PROCESSED_DIR / "test.jsonl"),
        },
        "counts": {
            "train": len(final_train),
            "val": len(final_val),
            "test": len(final_test),
        },
        "nazario_rule_captures": rule_captures,
        "dedup_removed": total_dupes,
        "enron_max_samples": ENRON_MAX_SAMPLES,
        "synthetic_in_test": test_synth,
        "test_set_note": "Test set = REAL data only; synthetic excluded per spec",
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 72)
    print("PHASE D3 COMPLETE — STOPPING FOR REVIEW")
    print("=" * 72)
    print("Next: PHASE D4 verification → D5 smoke training")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
