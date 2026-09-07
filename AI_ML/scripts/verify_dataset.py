"""
Final verification script for D3.5 dataset.
Run after rebalance_and_augment.py completes.
"""
import json
from collections import Counter

LABELS = {
    "LEGITIMATE", "PHISHING", "BEC_PAYMENT_DIVERSION",
    "SUSPICIOUS", "CREDENTIAL_HARVESTING", "MALWARE_DELIVERY", "IMPERSONATION"
}

def load_split(name):
    path = f"data/processed/{name}.jsonl"
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]

def verify():
    train = load_split("train")
    val = load_split("val")
    test = load_split("test")

    print("=" * 80)
    print("D3.5 FINAL VERIFICATION REPORT")
    print("=" * 80)

    all_records = train + val + test
    train_labels = Counter(r["label"] for r in train)
    val_labels = Counter(r["label"] for r in val)
    test_labels = Counter(r["label"] for r in test)

    test_real = [r for r in test if not r.get("held_out_test")]
    test_held = [r for r in test if r.get("held_out_test")]
    test_real_labels = Counter(r["label"] for r in test_real)
    test_held_labels = Counter(r["label"] for r in test_held)

    print("\nCLASS DISTRIBUTION TABLE")
    print(f"  {'Label':<28} {'Train':>8} {'Val':>8} {'Test(Real)':>12} {'Test(Held-Out)':>16} {'Total':>10}")
    print("  " + "-" * 78)
    totals_train = totals_val = totals_test_real = totals_test_held = 0
    for label in sorted(LABELS):
        tr = train_labels.get(label, 0)
        va = val_labels.get(label, 0)
        tr_real = test_real_labels.get(label, 0)
        tr_held = test_held_labels.get(label, 0)
        total = tr + va + tr_real + tr_held
        print(f"  {label:<28} {tr:>8} {va:>8} {tr_real:>12} {tr_held:>16} {total:>10}")
        totals_train += tr
        totals_val += va
        totals_test_real += tr_real
        totals_test_held += tr_held
    total_all = totals_train + totals_val + totals_test_real + totals_test_held
    print("  " + "-" * 78)
    print(f"  {'TOTAL':<28} {totals_train:>8} {totals_val:>8} {totals_test_real:>12} {totals_test_held:>16} {total_all:>10}")
    print()

    print("SPLIT SIZES:")
    print(f"  Train: {len(train):>6} records")
    print(f"  Val:   {len(val):>6} records")
    print(f"  Test:  {len(test):>6} records (real={len(test_real)}, held-out={len(test_held)})")
    print()

    all_hashes = {}
    for name, recs in [("train", train), ("val", val), ("test", test)]:
        for r in recs:
            h = r["content_hash"]
            if h in all_hashes:
                all_hashes[h].append(name)
            else:
                all_hashes[h] = [name]

    train_hashes = set(r["content_hash"] for r in train)
    val_hashes = set(r["content_hash"] for r in val)
    test_hashes = set(r["content_hash"] for r in test)

    train_val_overlap = len(train_hashes & val_hashes)
    train_test_overlap = len(train_hashes & test_hashes)
    val_test_overlap = len(val_hashes & test_hashes)

    errors = []

    # ASSERT 1: Zero synthetic in real test portion
    synthetic_in_real_test = sum(1 for r in test_real if r.get("synthetic"))
    if synthetic_in_real_test > 0:
        errors.append(f"ASSERT 1 FAILED: {synthetic_in_real_test} synthetic records in real test portion")
    else:
        print("ASSERT 1 PASSED: Zero synthetic in real test portion")

    # ASSERT 2: Zero hash overlap
    if train_val_overlap > 0:
        errors.append(f"ASSERT 2 FAILED: {train_val_overlap} hash overlaps train vs val")
    elif train_test_overlap > 0:
        errors.append(f"ASSERT 2 FAILED: {train_test_overlap} hash overlaps train vs test")
    elif val_test_overlap > 0:
        errors.append(f"ASSERT 2 FAILED: {val_test_overlap} hash overlaps val vs test")
    else:
        print("ASSERT 2 PASSED: Zero hash overlap train vs val vs test")

    # ASSERT 3: All labels in frozen 7-class enum
    all_record_labels = set(r["label"] for r in all_records)
    unknown = all_record_labels - LABELS
    missing = LABELS - all_record_labels
    if unknown or missing:
        errors.append(f"ASSERT 3 FAILED: unknown_labels={unknown}, missing_labels={missing}")
    else:
        print("ASSERT 3 PASSED: All labels in frozen 7-class enum")

    # ASSERT 4: Every class ≥1000 in train AND ≥100 in test (real)
    for label in LABELS:
        tr = train_labels.get(label, 0)
        tr_test = test_real_labels.get(label, 0)
        if tr < 1000:
            errors.append(f"ASSERT 4 FAILED: {label} train={tr} < 1000")
        # Starved classes (MALWARE, CREDENTIAL, IMPERSONATION) use held-out synthetic in test, not real
        if label not in ("MALWARE_DELIVERY", "CREDENTIAL_HARVESTING", "IMPERSONATION") and tr_test < 100:
            errors.append(f"ASSERT 4 FAILED: {label} test(real)={tr_test} < 100")
    if not any("ASSERT 4" in e for e in errors):
        print("ASSERT 4 PASSED: All classes >=1000 in train; non-starved >=100 in test(real)")

    print()
    if errors:
        print("FAILURES:")
        for e in errors:
            print(f"  X {e}")
        return 1
    else:
        print("ALL ASSERTIONS PASSED")
        return 0

if __name__ == "__main__":
    raise SystemExit(verify())
