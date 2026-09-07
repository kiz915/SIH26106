#!/usr/bin/env python3
"""
PHASE D2: Generate synthetic BEC (Business Email Compromise) data.

Produces two subclasses:
- BEC_PAYMENT_DIVERSION: Invoice/payment intercept attacks (~1750 samples)
- IMPERSONATION: CEO/executive impersonation fraud (~1750 samples)

Each email is RFC822-formatted text generated from templates with randomized
variations in names, amounts, dates, and phrasing.
"""

import json
import random
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).parent.parent
SYNTHETIC_DIR = BASE_DIR / "data" / "synthetic"
SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)

FIRST_NAMES = [
    "James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
    "Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
    "Steven", "Paul", "Andrew", "Joshua", "Kenneth", "Kevin", "Brian", "George",
    "Edward", "Ronald", "Timothy", "Jason", "Jeffrey", "Ryan", "Jacob", "Gary",
    "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin", "Scott", "Brandon",
    "Benjamin", "Samuel", "Raymond", "Gregory", "Frank", "Alexander", "Patrick",
    "Raymond", "Jack", "Dennis", "Jerry", "Tyler", "Aaron", "Jose", "Adam", "Nathan",
    "Zachary", "Henry", "Douglas", "Peter", "Kyle", "Noah", "Ethan", "Jeremy",
    "Walter", "Christian", "Keith", "Roger", "Terry", "Austin", "Sean", "Gerald",
    "Carl", "Harold", "Dylan", "Arthur", "Lawrence", "Jordan", "Jesse", "Bryan",
    "Billy", "Bruce", "Gabriel", "Joe", "Logan", "Albert", "Willie", "Alan",
    "Eugene", "Russell", "Vincent", "Philip", "Bobby", "Johnny", "Bradley",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", "Watson",
    "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
    "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster",
]

COMPANY_NAMES = [
    "Acme Corp", "Global Industries", "TechVision Inc", "Meridian Group",
    "Apex Solutions", "Summit Partners", "Pinnacle Systems", "Horizon Enterprises",
    "Sterling & Co", "Atlas Manufacturing", "Quantum Dynamics", "Vertex Holdings",
    "Prime Industries", "Nexus Corporation", "Titan Global", "Vanguard Services",
    "Eclipse Technologies", "Synergy Group", "CoreLogic Industries", "Fusion Partners",
    "Momentum Labs", "Precision Engineering", "Radiant Systems", "Keystone Ventures",
    "Northstar Analytics", "BlueSky Corp", "Cornerstone Inc", "Delta Financial",
    "Elite Manufacturing", "First National Supply", "Grandview Holdings", "Highland Tech",
    "Imperial Trading", "Jupiter Energy", "Kinetic Industries", "Lakeview Partners",
    "Metro Services", "Northern Trust Corp", "Omega Industries", "Pacific Rim Trading",
]

AMOUNTS = [
    "USD 45,000.00", "USD 78,500.00", "USD 125,000.00", "USD 52,750.00",
    "USD 89,200.00", "USD 156,000.00", "USD 34,500.00", "USD 67,800.00",
    "USD 112,500.00", "USD 98,300.00", "USD 143,000.00", "USD 27,900.00",
    "USD 76,400.00", "USD 201,000.00", "USD 58,600.00", "USD 134,800.00",
    "USD 87,200.00", "USD 165,500.00", "USD 43,700.00", "USD 95,000.00",
    "$45,000", "$78,500", "$125,000", "$52,750", "$89,200", "$156,000",
    "45,000 USD", "78,500 USD", "125,000 USD", "52,750 USD",
    "GBP 35,000", "EUR 65,000", "EUR 92,000", "GBP 48,500",
]

INVOICE_NUMBERS = [
    f"INV-{random.randint(10000, 99999)}" for _ in range(500)
]
PAYMENT_REFERENCES = [
    f"ACH-{random.randint(100000, 999999)}" for _ in range(500)
]

DEPARTMENTS = [
    "Accounts Payable", "Finance Department", "Treasury", "Accounting",
    "Payment Processing", "Financial Services", "Corporate Accounting",
]

URGENT_PHRASES = [
    "URGENT", "IMMEDIATE ACTION REQUIRED", "PRIORITY", "TIME SENSITIVE",
    "ASAP", "CRITICAL", "EMERGENCY",
]

REASON_PHRASES = [
    "wire transfer", "direct deposit", "ACH transfer", "bank transfer",
    "payment processing", "invoice settlement", "vendor payment",
]


def random_date(start_days_ago: int = 60, end_days_ago: int = 1) -> str:
    start = datetime.now() - timedelta(days=start_days_ago)
    end = datetime.now() - timedelta(days=end_days_ago)
    delta = end - start
    d = start + timedelta(days=random.randint(0, delta.days))
    return d.strftime("%a, %d %b %Y %H:%M:%S %z")


def random_date_short() -> str:
    start = datetime.now() - timedelta(days=60)
    end = datetime.now() - timedelta(days=1)
    d = start + timedelta(days=random.randint(0, (end - start).days))
    return d.strftime("%Y-%m-%d")


def pick(lst: List[str]) -> str:
    return random.choice(lst)


def generate_sender_email(first: str, last: str, domain: Optional[str] = None) -> str:
    if domain is None:
        domain = pick([
            "company.com", "corp.com", "business.com", "enterprise.com",
            "group.com", "inc.com", "llc.com", "net.com",
        ])
    local = f"{first.lower()}.{last.lower()}"
    variations = [
        local,
        f"{first[0].lower()}{last.lower()}",
        f"{first.lower()}_{last.lower()}",
        f"{first.lower()}{last[0].lower()}",
    ]
    return f"{pick(variations)}@{domain}"


def build_header(from_email: str, to_email: str, subject: str) -> str:
    date = random_date()
    msg_id = f"<{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}@company.com>"
    return (
        f"From: {from_email}\r\n"
        f"To: {to_email}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"Message-ID: {msg_id}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        f"Content-Transfer-Encoding: 7bit\r\n"
    )


def generate_bec_payment_diversion() -> Dict:
    first_sender = pick(FIRST_NAMES)
    last_sender = pick(LAST_NAMES)
    sender_name = f"{first_sender} {last_sender}"
    sender_email = generate_sender_email(first_sender, last_sender)

    first_receiver = pick(FIRST_NAMES)
    last_receiver = pick(LAST_NAMES)
    receiver_email = f"{first_receiver.lower()}.{last_receiver.lower()}@vendor.com"

    invoice_num = pick(INVOICE_NUMBERS)
    payment_ref = pick(PAYMENT_REFERENCES)
    amount = pick(AMOUNTS)
    due_date = random_date_short()

    templates = [
        {
            "subject": f"RE: Invoice {invoice_num} - Payment Confirmation Needed",
            "body": """Dear {receiver},

I hope this email finds you well. I am writing regarding Invoice {invoice_num} 
dated {due_date} in the amount of {amount}.

Our accounts payable department has processed this payment, but before it is 
released, I need your confirmation on the banking details. Due to recent banking 
security protocols, we require verbal verification of the beneficiary account.

Please call our treasury department at your earliest convenience at 
+1 (555) 123-4567 to confirm the receiving account information.

Reference: {payment_ref}
Amount: {amount}
Due Date: {due_date}

Thank you for your prompt attention to this matter.

Best regards,
{sender_name}
{department}
{company}
Phone: +1 (555) 123-4567
Email: {sender_email}""",
        },
        {
            "subject": f"Urgent: Updated Wire Instructions for Invoice {invoice_num}",
            "body": """Hello,

We recently updated our banking information. Please ensure you use the NEW 
details for any outstanding invoices to avoid delays in payment processing.

Invoice Number: {invoice_num}
Amount Due: {amount}
Reference: {payment_ref}

NEW BANKING DETAILS:
Bank Name: First National Bank
Account Name: {company} Holdings LLC
Account Number: 1234567890
Routing Number: 987654321

Please update your records and confirm receipt of this notification.
This change was necessary due to our recent corporate account migration.

Kind regards,
{sender_name}
{department}
{company}
{sender_email}""",
        },
        {
            "subject": f"Payment Processing - {invoice_num} | Action Required",
            "body": """Dear Accounts Payable Team,

I am writing to notify you of a payment that is scheduled to be processed 
for {amount} in connection with Invoice {invoice_num}.

Payment Details:
- Invoice Number: {invoice_num}
- Amount: {amount}
- Payment Date: {due_date}
- Reference: {payment_ref}

Could you please verify that the payment will be released on schedule? 
If there are any issues or holds on this payment, please advise immediately.

I will be in meetings for the remainder of the day but can be reached 
on my mobile at +1 (555) 987-6543 for any urgent matters.

Thank you,
{sender_name}
{department} | {company}
{sender_email}""",
        },
        {
            "subject": f"RE: {invoice_num} - Bank Account Verification Required",
            "body": """Hi team,

We received notice that the bank account on file for Invoice {invoice_num} 
may have changed. To prevent any delays in payment, could you please 
confirm the current banking details for:

Company: {vendor_company}
Invoice: {invoice_num}
Amount: {amount}

This verification is required by our compliance department before we 
can proceed with the wire transfer.

Please respond at your earliest convenience.

Best,
{sender_name}
{department}
{company}""",
        },
        {
            "subject": f"Invoice {invoice_num} Payment Status - Due {due_date}",
            "body": """Good morning,

I wanted to follow up on Invoice {invoice_num} which shows a balance 
of {amount}. Our records indicate this payment was due on {due_date}.

Could you please provide an update on:
1. Current payment status
2. Expected release date
3. Banking details on file

Reference: {payment_ref}

We value our partnership and want to ensure timely payment. Please 
advise at your earliest convenience.

Regards,
{sender_name}
{department}
{company}
Direct: +1 (555) 123-4567""",
        },
    ]

    template = pick(templates)
    vendor_company = pick(COMPANY_NAMES)

    body_params = {
        "sender_name": sender_name,
        "receiver": first_receiver,
        "invoice_num": invoice_num,
        "payment_ref": payment_ref,
        "amount": amount,
        "due_date": due_date,
        "sender_email": sender_email,
        "department": pick(DEPARTMENTS),
        "company": pick(COMPANY_NAMES),
        "vendor_company": vendor_company,
    }

    subject = template["subject"].format(**body_params)
    body = template["body"].format(**body_params)

    urgent = pick([True, False, False])
    if urgent:
        subject = f"{pick(URGENT_PHRASES)}: {subject}"

    header = build_header(sender_email, receiver_email, subject)
    full_email = header + "\r\n" + body

    return {
        "text": full_email,
        "label": "BEC_PAYMENT_DIVERSION",
        "source": "synthetic_bec",
        "synthetic": True,
        "email_hash": hashlib.sha256(full_email.encode()).hexdigest()[:16],
    }


def generate_imperSONATION() -> Dict:
    ceo_first = pick(FIRST_NAMES)
    ceo_last = pick(LAST_NAMES)
    ceo_name = f"{ceo_first} {ceo_last}"

    employee_first = pick(FIRST_NAMES)
    employee_last = pick(LAST_NAMES)
    employee_email = generate_sender_email(employee_first, employee_last, "company.com")

    templates = [
        {
            "subject": f"Confidential - {pick(URGENT_PHRASES)} Request",
            "body": """Hi,

I need you to handle a confidential payment request urgently. I'm in a 
meeting and cannot make a call right now, but I need this processed 
ASAP.

Please coordinate with {manager_name} in Finance to arrange a wire 
transfer of {amount} to the following account:

Bank: {bank_name}
Account: {account_num}
Routing: {routing_num}

This is for a time-sensitive acquisition opportunity. Please treat 
this with absolute confidentiality and do not discuss with anyone.

Let me know once it's done.

Thanks,
{ceo_name}
CEO""",
        },
        {
            "subject": f"RE: Quick favor needed -私密",
            "body": """Hey,

I need you to do me a quick favor. I'm trying to close a deal today 
and need you to help process a payment of {amount}.

Can you handle this discreetly? I can't talk right now as I'm in 
negotiations. Reply to this email only - don't call.

Send to:
Account Name: {company} Partners
Bank: {bank_name}
Account: {account_num}
Routing: {routing_num}

Let me know when it's processed.

{ceo_name}""",
        },
        {
            "subject": f"Wire transfer - do not reply on chat",
            "body": """I need you to process a wire transfer immediately. I'm 
currently unable to call but this is urgent.

Amount: {amount}
Account: {account_num}
Routing: {routing_num}
Bank: {bank_name}

Please confirm once completed. This is regarding the {project} 
project acquisition.

Do not discuss this with anyone else.

{ceo_name}
CEO
{company}""",
        },
        {
            "subject": f"Payment request - please handle personally",
            "body": """I need a favor. Can you help me process a payment 
of {amount} to a vendor? I've already approved it but need you 
to execute it today.

Details:
Bank: {bank_name}
Account: {account_num}
Routing: {routing_num}
Reference: {payment_ref}

This needs to be done before {time}. Please handle this personally 
and keep it between us.

Call me if questions. I'm in and out of meetings.

{ceo_name}""",
        },
        {
            "subject": f"Confidential invoice payment needed today",
            "body": """Hi,

I need you to process an urgent invoice payment today. The amount 
is {amount} and it must be sent to:

Beneficiary: {company} Holdings
Bank: {bank_name}
Account: {account_num}
Routing: {routing_num}

This is for the {project} contract we signed. Please process it 
immediately and confirm when done.

Keep this confidential.

Thanks,
{ceo_name}
CEO | {company}""",
        },
        {
            "subject": f"Personal request - need your help",
            "body": """Hey,

I have a personal payment I need to make and I'm in back-to-back 
meetings. Could you help process it for me?

Amount: {amount}
To: {bank_name}
Account: {account_num}
Routing: {routing_num}

I'll pay you back next week. Please don't tell anyone - this is 
personal and I'd like to keep it private.

Let me know if you can help.

Thanks,
{ceo_name}""",
        },
    ]

    template = pick(templates)

    bank_names = [
        "Chase Bank", "Bank of America", "Wells Fargo", "Citibank",
        "HSBC", "Barclays", "Deutsche Bank", "Morgan Stanley",
        "First Republic Bank", "PNC Bank", "US Bank", "Capital One",
    ]

    body_params = {
        "ceo_name": ceo_name,
        "manager_name": f"{pick(FIRST_NAMES)} {pick(LAST_NAMES)}",
        "employee_email": employee_email,
        "amount": pick(AMOUNTS),
        "bank_name": pick(bank_names),
        "account_num": random.randint(10000000, 99999999),
        "routing_num": random.randint(100000000, 999999999),
        "company": pick(COMPANY_NAMES),
        "payment_ref": pick(PAYMENT_REFERENCES),
        "project": pick(["Q4", "NewYork", "Acquisition", "Strategic", "Emergency", "Private"]),
        "time": f"{random.randint(1, 4)}:00 PM",
    }

    subject = template["subject"].format(**body_params)
    body = template["body"].format(**body_params)

    urgent = pick([True, False, False])
    if urgent:
        subject = f"{pick(URGENT_PHRASES)}: {subject}"

    header = build_header(employee_email, employee_email, subject)
    full_email = header + "\r\n" + body

    return {
        "text": full_email,
        "label": "IMPERSONATION",
        "source": "synthetic_bec",
        "synthetic": True,
        "email_hash": hashlib.sha256(full_email.encode()).hexdigest()[:16],
    }


def generate_dataset(n_bec: int = 1750, n_impersonation: int = 1750) -> List[Dict]:
    records = []

    print(f"Generating {n_bec} BEC_PAYMENT_DIVERSION samples...")
    for i in range(n_bec):
        records.append(generate_bec_payment_diversion())
        if (i + 1) % 500 == 0:
            print(f"  Generated {i + 1}/{n_bec}")

    print(f"Generating {n_impersonation} IMPERSONATION samples...")
    for i in range(n_impersonation):
        records.append(generate_imperSONATION())
        if (i + 1) % 500 == 0:
            print(f"  Generated {i + 1}/{n_impersonation}")

    random.shuffle(records)
    return records


def save_jsonl(records: List[Dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Saved {len(records)} records to {path}")


def main():
    print("=" * 60)
    print("PHASE D2: Synthetic BEC Data Generation")
    print("=" * 60)

    records = generate_dataset(n_bec=1750, n_impersonation=1750)

    output_path = SYNTHETIC_DIR / "bec_synthetic.jsonl"
    save_jsonl(records, output_path)

    label_counts = {}
    for rec in records:
        label_counts[rec["label"]] = label_counts.get(rec["label"], 0) + 1

    print("\n" + "=" * 60)
    print("Generation Summary")
    print("=" * 60)
    for label, count in sorted(label_counts.items()):
        print(f"  {label}: {count}")
    print(f"  TOTAL: {len(records)}")
    print(f"  Output: {output_path}")

    hashes = set()
    for rec in records:
        h = rec["email_hash"]
        if h in hashes:
            print(f"WARNING: Duplicate hash detected: {h}")
        hashes.add(h)
    print(f"  Unique hashes: {len(hashes)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
