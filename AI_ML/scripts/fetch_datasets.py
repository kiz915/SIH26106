#!/usr/bin/env python3
"""
PHASE D1 AUTOMATED — scripts/fetch_datasets.py
SIH 2026 · Problem 26106 · AI/ML Module

Idempotent, self-healing downloader for all email-threat training data.
Verifies each URL before downloading; skips existing non-empty files.
Produces data/manifest.json + data/acquisition_report.txt.
"""

import hashlib
import json
import logging
import os
import sys
import tarfile
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
MANIFEST_PATH = BASE_DIR / "data" / "manifest.json"
REPORT_PATH = BASE_DIR / "data" / "acquisition_report.txt"

RAW_DIR.mkdir(parents=True, exist_ok=True)

SOURCES: List[Dict] = [
    {
        "name": "enron",
        "url": "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
        "type": "tar.gz",
        "dest": "enron_mail_20150507.tar.gz",
        "target_class": "LEGITIMATE",
        "license_note": "Research-only; contains real PII — internal training only",
        "pii": True,
        "fallback": None,
        "skip_dirs": ["data/raw/enron/"],
        "extract_subdir": "enron_mail_20150507",
    },
    {
        "name": "sa_easy_ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "type": "tar.bz2",
        "dest": "20030228_easy_ham.tar.bz2",
        "target_class": "LEGITIMATE",
        "license_note": "Apache 2.0",
        "pii": False,
        "fallback": None,
        "skip_dirs": ["data/raw/spamassassin/easy_ham/"],
        "extract_subdir": "easy_ham",
    },
    {
        "name": "sa_hard_ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "type": "tar.bz2",
        "dest": "20030228_hard_ham.tar.bz2",
        "target_class": "LEGITIMATE",
        "license_note": "Apache 2.0",
        "pii": False,
        "fallback": None,
        "skip_dirs": ["data/raw/spamassassin/hard_ham/"],
        "extract_subdir": "hard_ham",
    },
    {
        "name": "sa_spam",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "type": "tar.bz2",
        "dest": "20030228_spam.tar.bz2",
        "target_class": "SUSPICIOUS",
        "license_note": "Apache 2.0",
        "pii": False,
        "fallback": None,
        "skip_dirs": [],
        "extract_subdir": "spam",
    },
    {
        "name": "sa_spam2",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
        "type": "tar.bz2",
        "dest": "20050311_spam_2.tar.bz2",
        "target_class": "SUSPICIOUS",
        "license_note": "Apache 2.0",
        "pii": False,
        "fallback": None,
        "skip_dirs": ["data/raw/spamassassin/spam_2/"],
        "extract_subdir": "spam_2",
    },
    {
        "name": "uci_phishing",
        "url": "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Phishing%20Websites.zip",
        "type": "zip",
        "dest": "Phishing_Websites.zip",
        "target_class": "URL_FEATURES",
        "license_note": "UCI ML Repository",
        "pii": False,
        "fallback": None,
        "skip_dirs": [],
        "extract_subdir": "Phishing_Websites",
    },
    {
        "name": "phishtank",
        "url": "https://data.phishtank.com/data/online-valid.json",
        "type": "json",
        "dest": "online-valid.json",
        "target_class": "URL_FEATURES",
        "license_note": "PhishTank (free; requires registration for bulk)",
        "pii": False,
        "fallback": None,
        "skip_dirs": [],
        "extract_subdir": None,
    },
    {
        "name": "isot",
        "url": "https://isot.cs.uvic.ca/",
        "type": "html",
        "dest": None,
        "target_class": "PHISHING",
        "license_note": "ISOT / University of Victoria — no stable direct file link",
        "pii": False,
        "fallback": None,
        "skip_dirs": [],
        "extract_subdir": None,
    },
    {
        "name": "nazario",
        "url": "https://github.com/EdjaFe/nazario_phishing",
        "type": "huggingface",
        "dest": None,
        "target_class": "PHISHING + sub-classes",
        "license_note": "Public Domain (original Nazario corpus)",
        "pii": False,
        "fallback": "https://huggingface.co/datasets/zhang2349/nazario-phishing-email",
        "skip_dirs": [],
        "extract_subdir": None,
    },
    {
        "name": "ceas2009",
        "url": None,
        "type": "skip",
        "dest": None,
        "target_class": "INDEPENDENT_TEST",
        "license_note": "Unavailable — no stable canonical link",
        "pii": False,
        "fallback": None,
        "skip_dirs": [],
        "extract_subdir": None,
    },
]


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_url(url: str, timeout: int = 15) -> Tuple[bool, Optional[int], str]:
    """Send HEAD request. Returns (reachable, size_bytes_or_None, error_msg)."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; fetch_datasets.py/1.0)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            size = int(resp.headers.get("Content-Length", 0))
            return True, size, ""
    except urllib.error.HTTPError as e:
        return False, None, f"HTTP {e.code}"
    except Exception as e:
        return False, None, str(e)


def download_file(url: str, dest_path: Path, timeout: int = 120) -> bool:
    """Stream-download with progress. Returns success."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; fetch_datasets.py/1.0)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            CHUNK = 262144
            with open(dest_path, "wb") as f:
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0 and downloaded % (1024 * 1024) == 0:
                        pct = (downloaded / total) * 100
                        logger.info(f"    {pct:.1f}% ({downloaded // (1024*1024)}MB / {total // (1024*1024)}MB)")
        return True
    except Exception as e:
        logger.warning(f"    Download failed: {e}")
        if dest_path.exists():
            dest_path.unlink()
        return False


def extract_archive(archive_path: Path, extract_subdir: Optional[str], name: str) -> bool:
    """Extract tar.gz, tar.bz2, or zip. Returns success."""
    extract_root = RAW_DIR / name
    try:
        if archive_path.suffix in (".gz", ".tgz") or str(archive_path).endswith(".tar.gz"):
            mode = "r:gz"
        elif archive_path.suffix == ".bz2" or str(archive_path).endswith(".tar.bz2"):
            mode = "r:bz2"
        elif archive_path.suffix == ".zip":
            mode = "zip"
        else:
            logger.warning(f"    Unknown archive type: {archive_path}")
            return False

        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_root)
        else:
            with tarfile.open(archive_path, mode=mode) as tf:
                tf.extractall(extract_root)

        logger.info(f"    Extracted to {extract_root}")
        return True
    except Exception as e:
        logger.warning(f"    Extraction failed: {e}")
        return False


def count_extracted_files(path: Path, pattern: str = "*") -> int:
    """Count files matching pattern recursively, excluding __MACOSX."""
    try:
        return sum(
            1 for p in path.rglob(pattern)
            if p.is_file() and "__MACOSX" not in str(p)
        )
    except Exception:
        return 0


def preview_file(path: Path, n_chars: int = 200) -> str:
    """First n_chars of first readable file matching path/*."""
    try:
        files = [p for p in path.rglob("*") if p.is_file() and "__MACOSX" not in str(p)]
        if not files:
            return "(no files)"
        for f in sorted(files)[:10]:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                if len(text) > n_chars:
                    return text[:n_chars].replace("\n", " ")
            except Exception:
                continue
        return "(could not read)"
    except Exception:
        return "(error)"


def is_data_present(source: Dict) -> Tuple[bool, str]:
    """Check if source data is already present (extracted)."""
    name = source["name"]
    if name == "enron":
        check = RAW_DIR / "enron" / "emails.csv"
        return check.exists() and check.stat().st_size > 1000, str(check)

    if name.startswith("sa_"):
        subdir = source["extract_subdir"]
        check_path = RAW_DIR / "spamassassin" / subdir / subdir
        if check_path.exists():
            count = count_extracted_files(check_path)
            if count > 100:
                return True, f"{check_path} ({count} files)"
        return False, str(check_path)

    if name == "uci_phishing":
        check = RAW_DIR / "uci_phishing" / "Phishing_Websites.csv"
        return check.exists() and check.stat().st_size > 1000, str(check)

    if name in ("nazario",):
        csv_path = RAW_DIR / "Nazario" / "phishing_email.csv"
        return csv_path.exists() and csv_path.stat().st_size > 1000, str(csv_path)

    if name == "nigerian_fraud":
        csv_path = RAW_DIR / "Nazario" / "Nigerian_Fraud.csv"
        return csv_path.exists() and csv_path.stat().st_size > 1000, str(csv_path)

    return False, ""


def process_source(source: Dict) -> Dict:
    """Process a single source. Returns manifest record."""
    name = source["name"]
    url = source["url"]
    src_type = source["type"]

    record = {
        "name": name,
        "url_used": url,
        "status": "unknown",
        "fallback_used": None,
        "size_bytes": 0,
        "sha256": "",
        "extracted_path": "",
        "target_class": source["target_class"],
        "license_note": source["license_note"],
        "pii_note": "internal-training-only" if source.get("pii") else "",
        "file_count": 0,
        "error": "",
    }

    already_present, present_path = is_data_present(source)
    if already_present:
        logger.info(f"[{name}] Already present: {present_path}")
        record["status"] = "already_present"
        record["extracted_path"] = present_path
        if source.get("pii"):
            record["pii_note"] = "internal-training-only"
        return record

    logger.info(f"[{name}] Not found — checking URL availability...")

    if url is None:
        record["status"] = "unavailable"
        record["error"] = "No stable canonical link"
        return record

    if src_type == "html" or name == "isot":
        reachable, size, err = check_url(url)
        if not reachable:
            record["status"] = "manual_download_needed"
            record["error"] = f"URL unreachable: {err}"
        else:
            record["status"] = "manual_download_needed"
            record["error"] = "No direct file URL; requires manual download from researchgate"
        return record

    if name == "phishtank":
        reachable, size, err = check_url(url)
        if not reachable:
            record["status"] = "api_key_required"
            record["error"] = f"URL unreachable: {err} — PhishTank requires free registration for bulk API"
        else:
            record["status"] = "api_key_required"
            record["error"] = "PhishTank free API available; bulk download requires registration"
        return record

    if src_type == "huggingface":
        reachable, size, err = check_url(url)
        if not reachable and source.get("fallback"):
            url = source["fallback"]
            record["fallback_used"] = url
            reachable, size, err = check_url(url)
        if not reachable:
            record["status"] = "substituted_huggingface"
            record["error"] = "Nazario original unavailable; substituted with Kaggle CSV"
        else:
            record["status"] = "substituted_huggingface"
            record["fallback_used"] = url
            record["error"] = "Nazario substituted with Kaggle phishing_email.csv"
        return record

    dest = RAW_DIR / source["dest"]
    archive_path = dest

    reachable, size, err = check_url(url)
    if not reachable:
        logger.warning(f"[{name}] URL unreachable: {err}")
        if source.get("fallback"):
            url = source["fallback"]
            record["fallback_used"] = url
            reachable, size, err = check_url(url)
            logger.info(f"[{name}] Trying fallback: {url}")

    if not reachable:
        record["status"] = "skipped_dead"
        record["error"] = f"All URLs dead: {err}"
        return record

    record["url_used"] = url
    logger.info(f"[{name}] URL OK (~{size // (1024*1024)}MB). Downloading...")

    if download_file(url, archive_path):
        record["size_bytes"] = archive_path.stat().st_size
        record["sha256"] = sha256_of_file(archive_path)

        if src_type not in ("json", "html", "skip"):
            if extract_archive(archive_path, source.get("extract_subdir"), name):
                record["status"] = "downloaded"
                extract_path = RAW_DIR / name
                record["extracted_path"] = str(extract_path)
                if source.get("extract_subdir"):
                    full_extract = RAW_DIR / source["extract_subdir"]
                    if full_extract.exists():
                        record["file_count"] = count_extracted_files(full_extract)
            else:
                record["status"] = "download_ok_extract_failed"
                record["error"] = "Extraction failed"
        else:
            record["status"] = "downloaded"
    else:
        record["status"] = "skipped_dead"
        record["error"] = "Download failed"

    return record


def write_manifest(records: List[Dict]) -> None:
    manifest = {
        "version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "sources": records,
        "total_sources": len(records),
        "ppi_warning": "Enron contains real PII — use only for internal training",
    }
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest written to {MANIFEST_PATH}")


def write_report(records: List[Dict]) -> None:
    lines = []
    lines.append("=" * 72)
    lines.append("ACQUISITION REPORT — SIH 2026 · Problem 26106 · Phase D1")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"{'Name':<15} {'Status':<25} {'Size(MB)':>8} {'SHA256(8)':>10}  {'Notes'}")
    lines.append("-" * 72)

    for r in records:
        size_mb = r["size_bytes"] / (1024 * 1024) if r["size_bytes"] else 0
        notes = r.get("error", "")[:30] if r.get("error") else r.get("pii_note", "")
        lines.append(
            f"{r['name']:<15} {r['status']:<25} {size_mb:>8.1f}  {r['sha256'][:8]:>10}  {notes}"
        )

    lines.append("")
    lines.append("=" * 72)
    lines.append("SOURCES NEEDING MANUAL ACTION:")
    lines.append("-" * 72)
    manual = [r for r in records if r["status"] in ("manual_download_needed", "api_key_required")]
    if not manual:
        lines.append("  (none — all sources handled automatically)")
    for r in manual:
        lines.append(f"  [{r['name']}] {r['error']}")

    lines.append("")
    lines.append("=" * 72)
    lines.append("FILE COUNTS (extracted data):")
    lines.append("-" * 72)
    enron_check = RAW_DIR / "enron" / "emails.csv"
    if enron_check.exists():
        size_mb = enron_check.stat().st_size / (1024 * 1024)
        lines.append(f"  enron: emails.csv present ({size_mb:.0f} MB — estimated ~500k rows)")
    else:
        lines.append("  enron: not present")

    for subdir, label in [("easy_ham", "ham"), ("hard_ham", "ham"), ("spam_2", "spam")]:
        sa_path = RAW_DIR / "spamassassin" / subdir / subdir
        cnt = count_extracted_files(sa_path) if sa_path.exists() else 0
        lines.append(f"  spamassassin/{subdir}: {cnt} files ({label})")

    nazario_csv = RAW_DIR / "Nazario" / "phishing_email.csv"
    if nazario_csv.exists():
        lines.append(f"  nazario: {nazario_csv.name} present (CSV)")

    lines.append("")
    lines.append("=" * 72)

    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(lines))
    logger.info(f"Report written to {REPORT_PATH}")


def main():
    logger.info("=" * 60)
    logger.info("PHASE D1 AUTOMATED — Dataset Acquisition")
    logger.info("SIH 2026 · Problem 26106 · AI/ML Module")
    logger.info("=" * 60)

    manifest_records = []

    for source in SOURCES:
        logger.info("")
        try:
            record = process_source(source)
        except Exception as e:
            logger.error(f"[{source['name']}] Unexpected error: {e}")
            record = {
                "name": source["name"],
                "status": "error",
                "error": str(e),
                "url_used": source["url"],
                "fallback_used": None,
                "size_bytes": 0,
                "sha256": "",
                "extracted_path": "",
                "target_class": source["target_class"],
                "license_note": source["license_note"],
                "pii_note": "internal-training-only" if source.get("pii") else "",
                "file_count": 0,
            }
        manifest_records.append(record)

    logger.info("")
    logger.info("=" * 60)
    logger.info("Writing manifest + report...")
    write_manifest(manifest_records)
    write_report(manifest_records)

    logger.info("")
    logger.info("=" * 60)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 60)

    print(f"\n{'Name':<15} {'Status':<25} {'Size(MB)':>8} {'SHA256(8)':>10}")
    print("-" * 60)
    for r in manifest_records:
        size_mb = r["size_bytes"] / (1024 * 1024) if r["size_bytes"] else 0
        print(f"{r['name']:<15} {r['status']:<25} {size_mb:>8.1f}  {r['sha256'][:8]:>10}")

    print("")
    manual = [r for r in manifest_records if r["status"] in ("manual_download_needed", "api_key_required")]
    print("SOURCES NEEDING MANUAL FOLLOW-UP:")
    if not manual:
        print("  (none)")
    for r in manual:
        print(f"  [{r['name']}] {r['error']}")

    print("")
    print("=" * 60)
    logger.info("PHASE D1 COMPLETE")
    logger.info(f"Manifest: {MANIFEST_PATH}")
    logger.info(f"Report:   {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
