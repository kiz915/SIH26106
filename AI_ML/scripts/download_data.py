#!/usr/bin/env python3
"""
Dataset downloader for email threat detection training data.

Downloads publicly available email datasets:
- SpamAssassin Public Corpus (ham + spam)
- ISOT Phishing Corpus
- Nazario Phishing Corpus (via HuggingFace or direct mirrors)

Falls back to synthetic data generation if all downloads fail.
"""

import hashlib
import json
import logging
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
MANIFEST_PATH = DATA_DIR / "manifest.json"

SOURCES = {
    "spamassassin": {
        "name": "SpamAssassin Public Corpus",
        "url": "https://spamassassin.apache.org/old/publiccorpus/",
        "files": {
            "spam_2.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/spam_2.tar.bz2",
            "hard_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/hard_ham.tar.bz2",
            "easy_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/easy_ham.tar.bz2",
        },
        "license": "Apache 2.0",
        "description": "Ham (legitimate) and spam emails from Apache SpamAssassin project",
    },
    "isot": {
        "name": "ISOT Phishing Dataset",
        "url": "https://www.researchgate.net.net/publication/321115452",
        "files": {},
        "license": "Research-only",
        "description": "Phishing emails collected by ISOT Lab, University of Victoria",
    },
    "nazario": {
        "name": "Nazario Phishing Corpus",
        "url": "https://github.com/EdjaFe/nazario_phishing",
        "files": {},
        "license": "Public Domain",
        "description": "Curated phishing emails from Jose Nazario",
    },
}

TIMEOUT_SECONDS = 120
CHUNK_SIZE = 8192


def get_file_md5(filepath: Path) -> str:
    """Calculate MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            md5.update(chunk)
    return md5.hexdigest()


def download_file(url: str, dest: Path, timeout: int = TIMEOUT_SECONDS) -> bool:
    """Download a file with progress reporting."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        logger.info(f"Downloading {url}")
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        
        with open(dest, "wb") as f:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        pct = (downloaded / total_size) * 100
                        if downloaded % (1024 * 1024) == 0:  # Log every MB
                            logger.info(f"  Progress: {pct:.1f}% ({downloaded // (1024*1024)}MB)")
        
        logger.info(f"  Downloaded to {dest}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"  Download failed: {e}")
        if dest.exists():
            dest.unlink()
        return False


def extract_archive(archive_path: Path, dest_dir: Path) -> bool:
    """Extract tar.bz2, tar.gz, or zip archive."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        if archive_path.suffix == ".bz2":
            with tarfile.open(archive_path, "r:bz2") as tar:
                tar.extractall(dest_dir)
        elif archive_path.suffix == ".gz":
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(dest_dir)
        elif archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest_dir)
        else:
            logger.warning(f"  Unknown archive format: {archive_path}")
            return False
        
        logger.info(f"  Extracted to {dest_dir}")
        return True
    except Exception as e:
        logger.warning(f"  Extraction failed: {e}")
        return False


def download_spamassassin() -> dict:
    """Download SpamAssassin Public Corpus."""
    logger.info("=" * 60)
    logger.info("Downloading SpamAssassin Public Corpus")
    logger.info("=" * 60)
    
    source_key = "spamassassin"
    source_info = SOURCES[source_key]
    source_dir = RAW_DIR / source_key
    
    results = {
        "name": source_info["name"],
        "url": source_info["url"],
        "license": source_info["license"],
        "status": "not_started",
        "files": [],
        "samples_ham": 0,
        "samples_spam": 0,
    }
    
    all_success = True
    
    for filename, url in source_info["files"].items():
        dest = RAW_DIR / source_key / filename
        
        if dest.exists():
            logger.info(f"File exists: {dest}")
            results["files"].append({
                "filename": filename,
                "path": str(dest),
                "size_bytes": dest.stat().st_size,
                "md5": get_file_md5(dest),
                "status": "already_exists"
            })
            continue
        
        success = download_file(url, dest)
        
        if success:
            extract_dir = source_dir / filename.replace(".tar.bz2", "").replace(".tar.gz", "")
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            
            if extract_archive(dest, source_dir):
                results["files"].append({
                    "filename": filename,
                    "path": str(dest),
                    "size_bytes": dest.stat().st_size,
                    "md5": get_file_md5(dest),
                    "status": "downloaded_and_extracted"
                })
            else:
                results["files"].append({
                    "filename": filename,
                    "status": "download_ok_extract_failed"
                })
        else:
            results["files"].append({
                "filename": filename,
                "status": "download_failed"
            })
            all_success = False
    
    # Count samples
    ham_dir = source_dir / "hard_ham"
    easy_ham_dir = source_dir / "easy_ham"
    
    for d in [ham_dir, easy_ham_dir]:
        if d.exists():
            results["samples_ham"] += len(list(d.glob("*.txt")))
    
    spam_dir = source_dir / "spam_2"
    if spam_dir.exists():
        results["samples_spam"] = len(list(spam_dir.glob("*.txt")))
    
    results["status"] = "complete" if all_success else "partial"
    
    return results


def download_nazario_from_huggingface() -> dict:
    """Try to download Nazario corpus from HuggingFace."""
    logger.info("=" * 60)
    logger.info("Attempting Nazario download via HuggingFace datasets")
    logger.info("=" * 60)
    
    source_key = "nazario"
    source_info = SOURCES[source_key]
    source_dir = RAW_DIR / source_key
    
    results = {
        "name": source_info["name"],
        "url": source_info["url"],
        "license": source_info["license"],
        "status": "not_started",
        "error": None,
        "samples": 0,
    }
    
    try:
        from datasets import load_dataset
        
        logger.info("  Trying HuggingFace datasets library...")
        ds = load_dataset("stjordanis/nazario_phishing_corpus", split="train")
        
        text_samples = []
        for item in ds:
            text = item.get("text", "") or item.get("email", "")
            if text and len(text) > 50:
                text_samples.append(text)
        
        if text_samples:
            dest_dir = source_dir / "nazario_texts"
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for i, text in enumerate(text_samples):
                out_file = dest_dir / f"email_{i:05d}.txt"
                out_file.write_text(text, encoding="utf-8", errors="replace")
            
            results["samples"] = len(text_samples)
            results["status"] = "complete"
            results["path"] = str(dest_dir)
            logger.info(f"  Downloaded {len(text_samples)} emails")
        else:
            results["status"] = "no_samples"
            
    except Exception as e:
        logger.warning(f"  HuggingFace download failed: {e}")
        results["status"] = "failed"
        results["error"] = str(e)
    
    return results


def generate_manifest_status() -> dict:
    """Generate initial manifest structure."""
    return {
        "version": "1.0",
        "generated_at": str(Path(__file__).stat().st_mtime),
        "sources": {},
        "total_samples": 0,
        "ppi_warning": "Enron contains real PII - use only for internal training",
    }


def main():
    logger.info("=" * 60)
    logger.info("Email Threat Detection Dataset Downloader")
    logger.info("=" * 60)
    
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    manifest = generate_manifest_status()
    
    # Try SpamAssassin (most reliable source)
    logger.info("\n[DOWNLOAD] Attempting SpamAssassin...")
    sa_results = download_spamassassin()
    manifest["sources"]["spamassassin"] = sa_results
    logger.info(f"  SpamAssassin: {sa_results['status']}")
    logger.info(f"  Ham samples: {sa_results.get('samples_ham', 0)}")
    logger.info(f"  Spam samples: {sa_results.get('samples_spam', 0)}")
    
    # Try Nazario via HuggingFace
    logger.info("\n[DOWNLOAD] Attempting Nazario...")
    naz_results = download_nazario_from_huggingface()
    manifest["sources"]["nazario"] = naz_results
    logger.info(f"  Nazario: {naz_results['status']}")
    logger.info(f"  Samples: {naz_results.get('samples', 0)}")
    
    # ISOT - typically requires research gate, may fail
    logger.info("\n[DOWNLOAD] Attempting ISOT (may require manual download)...")
    manifest["sources"]["isot"] = {
        "name": "ISOT Phishing Dataset",
        "status": "manual_required",
        "url": "https://www.researchgate.net/publication/321115452",
        "error": "ISOT typically requires manual download from ResearchGate. Set up manual download or use alternative source.",
    }
    
    # Calculate totals
    total = 0
    for source_key, source_data in manifest["sources"].items():
        if source_data.get("status") == "complete":
            if source_key == "spamassassin":
                total += source_data.get("samples_ham", 0)
                total += source_data.get("samples_spam", 0)
            elif source_key == "nazario":
                total += source_data.get("samples", 0)
    
    manifest["total_samples"] = total
    
    # Check if we have enough data
    if total < 1000:
        logger.warning(f"\nWARNING: Only {total} samples downloaded. Will need synthetic augmentation.")
        manifest["needs_synthetic"] = True
    else:
        manifest["needs_synthetic"] = False
    
    # Save manifest
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    
    logger.info("\n" + "=" * 60)
    logger.info("Download Summary")
    logger.info("=" * 60)
    logger.info(f"Total samples downloaded: {total}")
    logger.info(f"Manifest saved to: {MANIFEST_PATH}")
    logger.info(f"Raw data directory: {RAW_DIR}")
    
    for source_key, source_data in manifest["sources"].items():
        status = source_data.get("status", "unknown")
        logger.info(f"  {source_key}: {status}")
    
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
