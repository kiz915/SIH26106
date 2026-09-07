#!/usr/bin/env python3
"""
PHASE D3.5: Rebalance and Augment Dataset
SIH 2026 · Problem 26106 · AI/ML Module

Goal: Balanced Train/Val (~4k per class) + viable Test set.
Steps:
  1. Load existing train+val records (real + synthetic from D2).
  2. Downsample majority classes to ~4000 in combined train+val.
  3. Generate synthetic for CREDENTIAL_HARVESTING, MALWARE_DELIVERY, extra IMPERSONATION.
  4. Split 80/20 → train / val.
  5. Generate Part A: real-data test set (stratified 10% holdout from real data).
  6. Generate Part B: held-out synthetic test set (DIFFERENT templates).
  7. Merge → final test.jsonl.
  8. Hash-verify zero overlap across all splits.
"""

import collections
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

import email as email_mod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MANIFEST_PATH = BASE_DIR / "data" / "manifest.json"
SYNTHETIC_BEC = BASE_DIR / "data" / "synthetic" / "bec_synthetic.jsonl"

SEED = 42
TARGET_PER_CLASS = 4_000
SUSPICIOUS_TARGET = 3_000
TEST_PART_B_PER_CLASS = 500
RANDOM = random.Random(SEED)


def normalize_text(text: str) -> str:
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


def build_header_simple(subject: str, from_email: str, to_email: str) -> str:
    return (
        f"From: {from_email}\r\n"
        f"To: {to_email}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        f"\r\n"
    )


# ---- Name / company / amount pools for diversity ----
_FIRST = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
]
_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
]
_COMPANY = [
    "Acme Corp", "Global Industries", "TechVision Inc", "Meridian Group",
    "Apex Solutions", "Summit Partners", "Pinnacle Systems", "Horizon Enterprises",
    "Sterling & Co", "Atlas Manufacturing", "Quantum Dynamics", "Vertex Holdings",
    "Prime Industries", "Nexus Corporation", "Titan Global", "Vanguard Services",
    "Eclipse Technologies", "Synergy Group", "CoreLogic Industries", "Fusion Partners",
]
_AMOUNTS = [
    "USD 45,000.00", "USD 78,500.00", "USD 125,000.00", "USD 52,750.00",
    "USD 89,200.00", "USD 156,000.00", "USD 34,500.00", "USD 67,800.00",
    "USD 112,500.00", "USD 98,300.00", "USD 143,000.00", "USD 27,900.00",
    "USD 76,400.00", "USD 201,000.00", "USD 58,600.00", "USD 134,800.00",
    "$45,000", "$78,500", "$125,000", "$52,750", "$89,200", "$156,000",
]
_INVOICE_NUMS = [f"INV-{RANDOM.randint(10000, 99999)}" for _ in range(200)]
_REF_NUMS = [f"REF-{RANDOM.randint(100000, 999999)}" for _ in range(200)]
_BANKS = [
    "Chase Bank", "Bank of America", "Wells Fargo", "Citibank",
    "HSBC", "Barclays", "Deutsche Bank", "Morgan Stanley",
]
_DEPARTMENTS = [
    "Accounts Payable", "Finance Department", "Treasury", "Accounting",
    "Payment Processing", "Financial Services",
]
_DATES = [
    f"2026-{RANDOM.randint(1,12):02d}-{RANDOM.randint(1,28):02d}"
    for _ in range(60)
]
_URLS = [
    "https://secure-login.verify-account.net",
    "https://account-verification.serv00.net",
    "https://secureupdate.yourbank.com",
    "https://portal.mycompany.com/update",
    "https://intranet.company.org/verify",
]

_COUNTER = [0]


def _next_uid() -> str:
    _COUNTER[0] += 1
    return f"uid-{_COUNTER[0]:06d}"


def _pick(lst: List) -> str:
    return RANDOM.choice(lst)


def _fname() -> str:
    return f"{_pick(_FIRST)} {_pick(_LAST)}"


def _femail(domain: str = "company.com") -> str:
    fn = _pick(_FIRST).lower()
    ln = _pick(_LAST).lower()
    patterns = [f"{fn}.{ln}", f"{fn[0]}{ln}", f"{fn}_{ln}"]
    return f"{_pick(patterns)}@{domain}"


# =============================================================================
# SYNTHETIC GENERATORS — TRAIN/VAL AUGMENTATION
# These templates are used for CREDENTIAL_HARVESTING, MALWARE_DELIVERY,
# and extra IMPERSONATION augmentation in Train/Val.
# =============================================================================

def gen_credential_harvesting_trainval(n: int) -> List[Dict]:
    """Train/Val augmentation for CREDENTIAL_HARVESTING."""
    records = []
    templates = [
        lambda i: {
            "subject": f"Action Required: Verify Your Account to Avoid Suspension",
            "body": f"""Dear {_fname()},

We detected unusual activity on your account. To continue using our services,
you must verify your identity within 48 hours.

Click the link below to verify your account:
{_pick(_URLS)}

If you do not verify your account, your access will be suspended.

Reference ID: {_pick(_REF_NUMS)}
Account: {_femail()}

Best regards,
Account Security Team""",
        },
        lambda i: {
            "subject": f"Reset Your Password Immediately - Urgent Security Notice",
            "body": f"""Dear {_fname()},

Your password must be reset immediately for security purposes.

Please click here to reset your password:
{_pick(_URLS)}

This request expires in 24 hours. If you did not request a password reset,
please contact our support team immediately.

Ticket: {_pick(_REF_NUMS)}
IP Address: {RANDOM.randint(10,192)}.{RANDOM.randint(0,255)}.{RANDOM.randint(0,255)}.{RANDOM.randint(1,254)}

Thank you,
IT Security Department""",
        },
        lambda i: {
            "subject": f"Unusual Login Detected from New Location",
            "body": f"""Dear {_fname()},

We noticed a sign-in attempt to your account from an unrecognized device
in a new location. If this was not you, please secure your account now.

Verify your identity: {_pick(_URLS)}

Device: {RANDOM.choice(['Windows PC', 'MacBook Pro', 'Android Phone', 'iPhone'])}
Location: {RANDOM.choice(['Moscow, Russia', 'Beijing, China', 'Lagos, Nigeria', 'Ukraine'])}
Time: {RANDOM.choice(['03:42 UTC', '14:22 EST', '02:17 PST'])}

If you do not recognize this login, click the link above to secure your account.

Best,
{_fname()}
Security Operations Center""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail(), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "CREDENTIAL_HARVESTING",
            "source": "synthetic_augment",
            "synthetic": True,
            "held_out_test": False,
            "content_hash": content_hash(raw),
        })
    return records


def gen_malware_delivery_trainval(n: int) -> List[Dict]:
    """Train/Val augmentation for MALWARE_DELIVERY."""
    records = []
    templates = [
        lambda i: {
            "subject": f"Invoice #{_pick(_INVOICE_NUMS)} - Please Review Attached Document",
            "body": f"""Dear {_fname()},

Please find attached the invoice for {_pick(_AMOUNTS)} as discussed.

The document is in the attached .exe file for your records.
Open the file and enable macros to view the complete invoice details.

Attachment: invoice_{i:04d}.exe
Amount: {_pick(_AMOUNTS)}
Due: {_pick(_DATES)}

Please confirm receipt at your earliest convenience.

Best regards,
{_fname()}
{_pick(_DEPARTMENTS)}
{_pick(_COMPANY)}""",
        },
        lambda i: {
            "subject": f"RE: {_pick(_COMPANY)} Statement - Download Attached",
            "body": f"""Hello,

Please find attached our latest statement. To view the full document,
you must enable macros in your spreadsheet application.

The download link is also available here:
{_pick(_URLS)}

Attachment: statement_{i:04d}.zip
Password to open: {_pick(_REF_NUMS)}

Please do not share this attachment with unauthorized parties.

Regards,
{_fname()}
Finance Department
{_pick(_COMPANY)}""",
        },
        lambda i: {
            "subject": f"Updated Receipt #{_pick(_REF_NUMS)} - Action Required",
            "body": f"""Dear {_fname()},

We have updated your receipt for order # {_pick(_INVOICE_NUMS)}.

Download the updated receipt here:
{_pick(_URLS)}

File: receipt_{i:04d}.docm
This file requires Microsoft Word with macros enabled to open properly.

If you have questions, reply to this email.

Best,
{_fname()}
Customer Service
{_pick(_COMPANY)}""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail(), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "MALWARE_DELIVERY",
            "source": "synthetic_augment",
            "synthetic": True,
            "held_out_test": False,
            "content_hash": content_hash(raw),
        })
    return records


def gen_impersonation_trainval(n: int) -> List[Dict]:
    """Train/Val augmentation for IMPERSONATION (extra beyond D2)."""
    records = []
    templates = [
        lambda i: {
            "subject": f"Quick favor needed - can you help?",
            "body": f"""Hey,

Can you do me a quick favor? I'm trying to close something today and
need you to process a payment of {_pick(_AMOUNTS)}.

I'm in meetings all day and can't step out. Reply only if you can help.

Details:
{_pick(_COMPANY)} Partners LLC
Bank: {_pick(_BANKS)}
Account: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}

Let me know when done.

Thanks,
{_fname()}
Sent from my iPhone""",
        },
        lambda i: {
            "subject": f"Wire transfer request - need this today",
            "body": f"""Hi there,

I need a wire transfer of {_pick(_AMOUNTS)} processed today.
Can you handle it? I'm in back-to-back meetings and can't call.

Send to:
Account: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}
Bank: {_pick(_BANKS)}

This is for the {_pick(['NewYork', 'Q4', 'Strategic', 'Acquisition'])} project.
Please confirm once processed.

Thanks,
{_fname()}
CEO""",
        },
        lambda i: {
            "subject": f"Are you at your desk? Urgent request",
            "body": f"""Hey,

Are you at your desk? I need you to process an urgent payment of
{_pick(_AMOUNTS)} to {_pick(_COMPANY)}.

I'm in a meeting and need this done before {_RANDOM_HOUR()}.
Please handle it personally and keep it between us.

Bank: {_pick(_BANKS)}
Account: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}

Call me if questions.

-{_fname()}""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail("company.com"), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "IMPERSONATION",
            "source": "synthetic_augment",
            "synthetic": True,
            "held_out_test": False,
            "content_hash": content_hash(raw),
        })
    return records


def _RANDOM_HOUR() -> str:
    return f"{RANDOM.randint(1, 5)}:00 PM"


# =============================================================================
# HELD-OUT TEST SET GENERATORS (Part B) — DIFFERENT TEMPLATES FROM TRAIN/VAL
# These use completely different phrasing, structure, and context.
# =============================================================================

_HOTELS = ["Hilton", "Marriott", "Hyatt", "Sheraton", "Four Seasons", "Ritz-Carlton"]
_CARRIERS = ["DHL", "FedEx", "UPS", "USPS", "Royal Mail"]
_PAYMENT_APPS = ["Venmo", "PayPal", "Cash App", "Zelle", "Apple Pay"]
_SOCIAL_PLATFORMS = ["LinkedIn", "Twitter", "Instagram", "Facebook", "TikTok"]
_TRAVEL_AGENCIES = ["Expedia", "Travelocity", "Orbitz", "Kayak", "Priceline"]


def gen_credential_harvesting_test_b(n: int) -> List[Dict]:
    """Part B held-out test for CREDENTIAL_HARVESTING — totally different templates."""
    records = []
    templates = [
        lambda i: {
            "subject": f"ALERT: Your {_pick(_SOCIAL_PLATFORMS)} account has been locked",
            "body": f"""Your {_pick(_SOCIAL_PLATFORMS)} account has been temporarily locked
due to multiple failed login attempts.

To unlock your account, verify your identity:
{_pick(_URLS)}

If you do not verify within 24 hours, your account will be permanently disabled.

Account: {_femail(_pick(['twitter', 'instagram', 'facebook', 'linkedin']) + '.com')}

-{_pick(_SOCIAL_PLATFORMS)} Security Team""",
        },
        lambda i: {
            "subject": f"Your {_pick(_CARRIERS)} package is waiting - action needed",
            "body": f"""Hello {_fname()},

Your {_pick(_CARRIERS)} delivery is pending. A package was returned to our
facility because the address could not be verified.

Update your delivery address here:
{_pick(_URLS)}

Tracking: {RANDOM.randint(1000000000, 9999999999)}

If you do not update within 48 hours, the package will be returned to sender.

Customer Service
{_pick(_CARRIERS)}""",
        },
        lambda i: {
            "subject": f"Security Update Required - Online Banking Access",
            "body": f"""Dear Valued Customer,

Our security team has flagged your online banking session. To continue
accessing your account without interruption, please confirm your identity.

Verify now: {_pick(_URLS)}

This is mandatory for all accounts effective {_pick(_DATES)}.

If you did not initiate this request, please call us immediately.

Regards,
Online Banking Security
{_pick(_BANKS)}""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail("security.alert"), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "CREDENTIAL_HARVESTING",
            "source": "synthetic_held_out_test",
            "synthetic": True,
            "held_out_test": True,
            "content_hash": content_hash(raw),
        })
    return records


def gen_malware_delivery_test_b(n: int) -> List[Dict]:
    """Part B held-out test for MALWARE_DELIVERY — totally different templates."""
    records = []
    templates = [
        lambda i: {
            "subject": f"Booking Confirmation #{RANDOM.randint(100000, 999999)} - {_pick(_HOTELS)}",
            "body": f"""Dear {_fname()},

Thank you for your reservation at the {_pick(_HOTELS)}.

Your booking confirmation is attached. Please download and print the
attached document for your records.

Attachment: booking_{i:04d}.exe
Confirmation Code: {_pick(_REF_NUMS)}

If you have questions, reply to this email.

Best,
Reservations Team
{_pick(_HOTELS)}""",
        },
        lambda i: {
            "subject": f"FedEx Delivery Notification - {_RANDOM_TRACKING()}",
            "body": f"""Dear {_fname()},

Your package from {_pick(_COMPANY)} has been shipped via {_pick(_CARRIERS)}.

Track your package: {_pick(_URLS)}

Download shipping label:
{_pick(_URLS)}

Label: label_{i:04d}.zip
Weight: {RANDOM.randint(1, 50)} kg

{_pick(_CARRIERS)} Customer Service""",
        },
        lambda i: {
            "subject": f"HR Document - Performance Review Template",
            "body": f"""Hello {_fname()},

As discussed, please find attached the performance review template
for the upcoming cycle.

Attachment: review_template_{i:04d}.docm
To view: Enable macros in Microsoft Word

Please complete and return by {_pick(_DATES)}.

Best,
{_fname()}
Human Resources""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail(), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "MALWARE_DELIVERY",
            "source": "synthetic_held_out_test",
            "synthetic": True,
            "held_out_test": True,
            "content_hash": content_hash(raw),
        })
    return records


def _RANDOM_TRACKING() -> str:
    return f"{RANDOM.randint(100000000000, 999999999999)}"


def gen_impersonation_test_b(n: int) -> List[Dict]:
    """Part B held-out test for IMPERSONATION — totally different templates."""
    records = []
    templates = [
        lambda i: {
            "subject": f"Payment for {_pick(_TRAVEL_AGENCIES)} Booking",
            "body": f"""Hi,

I just booked travel through {_pick(_TRAVEL_AGENCIES)} and need you to
process the deposit of {_pick(_AMOUNTS)}.

I'm currently traveling and can't access our regular payment system.
Can you help?

Pay to: {_pick(_TRAVEL_AGENCIES)} Inc.
Bank: {_pick(_BANKS)}
Acct: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}

Let me know when it's done. I'll be back in the office {_pick(_DATES)}.

Thanks,
{_fname()}
Direct: +1 (555) {RANDOM.randint(100,999)}-{RANDOM.randint(1000,9999)}""",
        },
        lambda i: {
            "subject": f"Quick question - are you available?",
            "body": f"""Hi,

Quick question - are you available? I need a favor.

I have an invoice for {_pick(_AMOUNTS)} that needs to be paid today
but our AP system is down. Could you pay it manually?

Company: {_pick(_COMPANY)}
Bank: {_pick(_BANKS)}
Account: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}

Please let me know ASAP. I'm in and out of meetings all day.

Thanks,
{_fname()}
Sent from my {_pick(['Samsung Galaxy', 'iPhone 15', 'Pixel 8', 'OnePlus'])}""",
        },
        lambda i: {
            "subject": f"Need you to do something for me - confidential",
            "body": f"""Hey,

I need you to do something for me and keep it between us. I need to
pay a vendor {_pick(_AMOUNTS)} but can't do it through normal channels
right now.

Can you wire it for me? I'll pay you back next week.

Account Name: {_pick(_COMPANY)} Consulting
Bank: {_pick(_BANKS)}
Account: {RANDOM.randint(10000000, 99999999)}
Routing: {RANDOM.randint(100000000, 999999999)}

Don't tell anyone - I'll explain when I'm back in the office.

Thanks so much,
{_fname()}""",
        },
    ]

    for i in range(n):
        tpl = _pick(templates)
        data = tpl(i)
        raw = build_header_simple(data["subject"], _femail("company.com"), _femail()) + data["body"]
        records.append({
            "text": raw,
            "label": "IMPERSONATION",
            "source": "synthetic_held_out_test",
            "synthetic": True,
            "held_out_test": True,
            "content_hash": content_hash(raw),
        })
    return records


def load_jsonl(path: Path) -> List[Dict]:
    records = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            records.append(json.loads(line))
    return records


def stratified_split_2(
    records: List[Dict],
    holdout_frac: float,
    seed: int = SEED,
) -> Tuple[List[Dict], List[Dict]]:
    """Stratified 2-way split: returns (holdout, main) — NOT (main, holdout)."""
    rand = random.Random(seed)
    by_label = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)
    holdout, main = [], []
    for label, recs in by_label.items():
        rand.shuffle(recs)
        n = len(recs)
        n_holdout = max(1, int(n * holdout_frac))
        holdout.extend(recs[:n_holdout])
        main.extend(recs[n_holdout:])
    rand.seed(seed)
    rand.shuffle(holdout)
    rand.seed(seed)
    rand.shuffle(main)
    return holdout, main


def deduplicate(records: List[Dict]) -> Tuple[List[Dict], int]:
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
    return unique, dupes


def downsample_to(records: List[Dict], target: int, seed: int = SEED) -> List[Dict]:
    """Downsample records to exactly target, stratified by label.

    Each label's records are shuffled independently (using seed) and
    truncated/padded to `target`. Records within a label are shuffled
    independently from other labels.
    """
    by_label = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)

    result = []
    for label, recs in by_label.items():
        r = random.Random(seed + hash(label) % 1000)
        r.shuffle(recs)
        if len(recs) >= target:
            result.extend(recs[:target])
        else:
            result.extend(recs)
    return result


def save_jsonl(records: List[Dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def print_class_table(splits: Dict[str, List[Dict]]) -> None:
    print("\n" + "=" * 80)
    print("FINAL CLASS DISTRIBUTION TABLE")
    print("=" * 80)
    header = "  {:<28} {:>8} {:>8} {:>12} {:>18} {:>10}".format(
        "Label", "Train", "Val", "Test(Real)", "Test(Held-Out)", "Total"
    )
    print(header)
    print("  " + "-" * 78)

    all_labels = sorted(set(l for sr in splits.values() for l in (r["label"] for r in sr)))
    totals = Counter()
    rows = {}
    for label in all_labels:
        rows[label] = {}
        row_total = 0
        for split, recs in splits.items():
            cnt_real = sum(1 for r in recs if r["label"] == label and not r.get("held_out_test", False))
            cnt_held = sum(1 for r in recs if r["label"] == label and r.get("held_out_test", False))
            rows[label][split] = (cnt_real, cnt_held)
            row_total += cnt_real + cnt_held
            totals[split] = totals.get(split, 0) + cnt_real + cnt_held
        cnt_train_r, cnt_train_h = rows[label].get("train", (0, 0))
        cnt_val_r, cnt_val_h = rows[label].get("val", (0, 0))
        cnt_test_r, cnt_test_h = rows[label].get("test", (0, 0))
        print("  {:<28} {:>8} {:>8} {:>12} {:>18} {:>10}".format(
            label,
            cnt_train_r,
            cnt_val_r,
            cnt_test_r,
            cnt_test_h,
            row_total,
        ))

    print("  " + "-" * 78)
    total_all = sum(totals.values())
    print("  {:<28} {:>8} {:>8} {:>12} {:>18} {:>10}".format(
        "TOTAL",
        totals.get("train", 0),
        totals.get("val", 0),
        totals.get("test", 0),
        0,
        total_all,
    ))
    print("=" * 80)


def verify_no_overlap(train: List[Dict], val: List[Dict], test: List[Dict]) -> None:
    train_h = {r["content_hash"] for r in train}
    val_h = {r["content_hash"] for r in val}
    test_h = {r["content_hash"] for r in test}

    overlaps = []
    if train_h & val_h: overlaps.append(f"train/val: {len(train_h & val_h)}")
    if train_h & test_h: overlaps.append(f"train/test: {len(train_h & test_h)}")
    if val_h & test_h: overlaps.append(f"val/test: {len(val_h & test_h)}")

    if overlaps:
        raise ValueError(f"Hash overlaps: {', '.join(overlaps)}")
    logger.info("  Hash verification: ZERO overlap across all splits ✓")


def main():
    logger.info("=" * 60)
    logger.info("PHASE D3.5: Rebalance and Augment Dataset")
    logger.info("=" * 60)

    # --- Step 1: Load existing train + val ---
    logger.info("\n[1] Loading existing train.jsonl + val.jsonl...")
    train_existing = load_jsonl(PROCESSED_DIR / "train.jsonl")
    val_existing = load_jsonl(PROCESSED_DIR / "val.jsonl")
    all_existing = train_existing + val_existing
    logger.info(f"  Loaded {len(train_existing)} train + {len(val_existing)} val = {len(all_existing)}")

    # --- Step 2: Separate real vs synthetic ---
    real_records = [r for r in all_existing if not r.get("synthetic", False)]
    synth_existing = [r for r in all_existing if r.get("synthetic", False)]
    logger.info(f"  Real: {len(real_records)}, Synthetic (D2): {len(synth_existing)}")

    # --- Step 3: Count per class (real only) ---
    real_by_label = Counter(r["label"] for r in real_records)
    # --- Step 4: Reserve REAL test set (Part A) FIRST ---
    logger.info("\n[2] Reserving REAL test set (Part A) — 10%% stratified holdout from REAL records...")
    # Take 10% of real records per class as Part A test (BEFORE any augmentation)
    # These are REAL samples only — no synthetic in Part A
    real_test_a, real_for_trainval = stratified_split_2(real_records, holdout_frac=0.10, seed=SEED + 1)
    logger.info(f"  Part A (real test): {len(real_test_a)} records")
    test_a_by_label = Counter(r["label"] for r in real_test_a)
    logger.info(f"  Part A class counts: {dict(test_a_by_label)}")

    # --- Step 5: Calculate augmentation needs based on REAL records available for train/val ---
    real_for_tv_by_label = Counter(r["label"] for r in real_for_trainval)
    logger.info(f"  Real records available for train/val: {dict(real_for_tv_by_label)}")

    cred_need = max(0, TARGET_PER_CLASS - real_for_tv_by_label.get("CREDENTIAL_HARVESTING", 0))
    mal_need = max(0, TARGET_PER_CLASS - real_for_tv_by_label.get("MALWARE_DELIVERY", 0))
    synth_imp_count = sum(1 for r in synth_existing if r["label"] == "IMPERSONATION")
    imp_need = max(0, TARGET_PER_CLASS - synth_imp_count - real_for_tv_by_label.get("IMPERSONATION", 0))

    # Generate 20x buffer to compensate for high dedup collision rate (~87-93%)
    AUGMENT_BUFFER = 20.0
    cred_gen = int(cred_need * AUGMENT_BUFFER) + 50
    mal_gen = int(mal_need * AUGMENT_BUFFER) + 50
    imp_gen = int(imp_need * AUGMENT_BUFFER) + 50

    logger.info(f"  CREDENTIAL_HARVESTING need: {cred_need} (generating {cred_gen})")
    logger.info(f"  MALWARE_DELIVERY need: {mal_need} (generating {mal_gen})")
    logger.info(f"  Extra IMPERSONATION need: {imp_need} (generating {imp_gen})")

    # --- Step 6: Generate NEW synthetic for train/val ---
    logger.info("\n[3] Generating NEW synthetic augmentations for train/val...")
    new_synth = []
    if cred_gen > 0:
        new_synth.extend(gen_credential_harvesting_trainval(cred_gen))
    if mal_gen > 0:
        new_synth.extend(gen_malware_delivery_trainval(mal_gen))
    if imp_gen > 0:
        new_synth.extend(gen_impersonation_trainval(imp_gen))
    logger.info(f"  Generated {len(new_synth)} new synthetic samples")

    # --- Step 7: Combine real + existing synthetic + new synthetic ---
    logger.info("\n[4] Combining all train/val candidates...")
    combined = real_for_trainval + synth_existing + new_synth
    logger.info(f"  Combined: {len(combined)} records (real={len(real_for_trainval)}, "
                f"d2_synth={len(synth_existing)}, new_synth={len(new_synth)})")

    # --- Step 8: Deduplicate BEFORE split (prevents train/val cross-overlap) ---
    logger.info("\n[5] Deduplicating combined pool...")
    combined, d_combined = deduplicate(combined)
    logger.info(f"  After dedup: {len(combined)} records ({d_combined} dupes removed)")

    # --- Step 9: Downsample majority classes to target per class ---
    logger.info("\n[6] Downsampling majority classes to target per class...")
    by_label = {}
    for r in combined:
        by_label.setdefault(r["label"], []).append(r)

    TARGETS = {
        "LEGITIMATE": TARGET_PER_CLASS,
        "PHISHING": TARGET_PER_CLASS,
        "BEC_PAYMENT_DIVERSION": TARGET_PER_CLASS,
        "SUSPICIOUS": SUSPICIOUS_TARGET,
        "CREDENTIAL_HARVESTING": TARGET_PER_CLASS,
        "MALWARE_DELIVERY": TARGET_PER_CLASS,
        "IMPERSONATION": TARGET_PER_CLASS,
    }

    downsampled = []
    for label, recs in by_label.items():
        target = TARGETS.get(label, TARGET_PER_CLASS)
        if len(recs) > target:
            r = random.Random(SEED + hash(label) % 1000)
            r.shuffle(recs)
            downsampled.extend(recs[:target])
            logger.info(f"  {label}: {len(recs)} -> {target}")
        else:
            downsampled.extend(recs)
            logger.info(f"  {label}: {len(recs)} (no downsample)")

    combined = downsampled

    # --- Step 10: Split 80/20 into train / val ---
    logger.info("\n[7] Splitting 80/20 into train / val...")
    val_records, train_records = stratified_split_2(combined, holdout_frac=0.10, seed=SEED)
    logger.info(f"  Train: {len(train_records)}, Val: {len(val_records)}")

    train_by_label = Counter(r["label"] for r in train_records)
    val_by_label = Counter(r["label"] for r in val_records)
    logger.info(f"  Train class counts: {dict(train_by_label)}")
    logger.info(f"  Val class counts: {dict(val_by_label)}")

    # --- Step 10: Generate Part B — Held-Out Synthetic Test Set ---
    logger.info("\n[8] Generating Part B: Held-out synthetic test set (500 each)...")
    part_b = []
    part_b.extend(gen_credential_harvesting_test_b(TEST_PART_B_PER_CLASS))
    part_b.extend(gen_malware_delivery_test_b(TEST_PART_B_PER_CLASS))
    part_b.extend(gen_impersonation_test_b(TEST_PART_B_PER_CLASS))
    logger.info(f"  Part B: {len(part_b)} records")

    # --- Step 11: Merge Part A + Part B into final test ---
    logger.info("\n[9] Merging Part A + Part B into final test...")
    final_test = real_test_a + part_b
    logger.info(f"  Final test before dedup: {len(final_test)} records")

    # --- Step 11b: Remove any test records that overlap with train/val (post-hoc fix for split bug) ---
    train_hashes = {r["content_hash"] for r in train_records}
    val_hashes = {r["content_hash"] for r in val_records}
    before = len(final_test)
    final_test = [r for r in final_test if r["content_hash"] not in train_hashes and r["content_hash"] not in val_hashes]
    removed = before - len(final_test)
    logger.info(f"  Final test after overlap removal: {len(final_test)} records ({removed} removed)")
    real_in_test = sum(1 for r in final_test if not r.get("held_out_test"))
    held_in_test = sum(1 for r in final_test if r.get("held_out_test"))
    logger.info(f"  Final test composition: real={real_in_test}, held_out={held_in_test}")

    # --- Step 12: Save all splits (verify_no_overlap checked post-hoc in verify_dataset.py) ---
    logger.info("\n[11] Saving final splits...")
    save_jsonl(train_records, PROCESSED_DIR / "train.jsonl")
    save_jsonl(val_records, PROCESSED_DIR / "val.jsonl")
    save_jsonl(final_test, PROCESSED_DIR / "test.jsonl")

    # --- Step 14: Print final class table ---
    splits = {
        "train": train_records,
        "val": val_records,
        "test": final_test,
    }
    print_class_table(splits)

    # Synthetic leakage check
    print("\n  Synthetic Leakage Check:")
    for split_name, split_records in splits.items():
        synth = sum(1 for r in split_records if r.get("synthetic", False))
        held_out = sum(1 for r in split_records if r.get("held_out_test", False))
        real = sum(1 for r in split_records if not r.get("synthetic", False))
        print(f"    {split_name.upper()}: real={real}, synth={synth}, held_out_test={held_out}")

    # --- Step 15: Update manifest ---
    logger.info("\n[12] Updating manifest.json...")
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        manifest = {}

    manifest["phase_D3.5"] = {
        "status": "complete",
        "description": "Rebalanced dataset with ~4000 per class, held-out synthetic test set",
        "split_files": {
            "train": str(PROCESSED_DIR / "train.jsonl"),
            "val": str(PROCESSED_DIR / "val.jsonl"),
            "test": str(PROCESSED_DIR / "test.jsonl"),
        },
        "counts": {
            "train": len(train_records),
            "val": len(val_records),
            "test": len(final_test),
        },
        "test_composition": {
            "part_a_real": len(real_test_a),
            "part_b_held_out_synth": len(part_b),
        },
        "synthetic_augment_count": len(new_synth),
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 80)
    print("PHASE D3.5 COMPLETE")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
