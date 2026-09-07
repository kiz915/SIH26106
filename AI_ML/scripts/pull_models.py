#!/usr/bin/env python3
"""
Pull and cache ML models for offline use.

This script downloads the required transformer models and caches them locally
so they can be used without network access (HF_HUB_OFFLINE=1).

Usage:
    python scripts/pull_models.py

Environment:
    HF_TOKEN: Optional HuggingFace token for faster downloads and private models
    TRANSFORMERS_OFFLINE: Will be set to 0 during download, then restored
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


MODELS_TO_PULL = [
    {
        "name": "typeform/distilbert-base-uncased-mnli",
        "description": "Zero-shot NLI model for email classification",
        "size_mb": 260,
    },
]


def get_cache_dir() -> Path:
    """Get the HuggingFace cache directory."""
    if "HF_HOME" in os.environ:
        return Path(os.environ["HF_HOME"])
    if "TRANSFORMERS_CACHE" in os.environ:
        return Path(os.environ["TRANSFORMERS_CACHE"])
    return Path.home() / ".cache" / "huggingface"


def print_download_progress(model_name: str, hook):
    """Create a progress callback for model downloads."""
    from tqdm import tqdm
    
    class ProgressCallback:
        def __init__(self):
            self.pbar = None
            
        def __call__(self, chunk_size: int, chunk_num: int, max_depth: int):
            if self.pbar is None:
                self.pbar = tqdm(total=max_depth, unit="layer", desc=model_name[:40])
            self.pbar.update(1)
            
        def close(self):
            if self.pbar:
                self.pbar.close()
                
    return ProgressCallback()


def pull_model(model_info: dict, force: bool = False) -> bool:
    """Download and cache a single model."""
    model_name = model_info["name"]
    print(f"\n{'='*60}")
    print(f"Downloading: {model_name}")
    print(f"Description: {model_info.get('description', 'N/A')}")
    print(f"Estimated size: {model_info.get('size_mb', 'N/A')} MB")
    print(f"{'='*60}")
    
    cache_dir = get_cache_dir()
    print(f"Cache directory: {cache_dir}")
    
    os.environ["TRANSFORMERS_OFFLINE"] = "0"
    os.environ["HF_HUB_OFFLINE"] = "0"
    
    try:
        print("Downloading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print("  Tokenizer downloaded successfully")
        
        print("Downloading model weights...")
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        print("  Model weights downloaded successfully")
        
        model_path = cache_dir / "hub" / f"models--{model_name.replace('/', '--')}"
        if model_path.exists():
            size_mb = sum(f.stat().st_size for f in model_path.rglob("*") if f.is_file()) / (1024 * 1024)
            print(f"  Cached model size: {size_mb:.1f} MB")
        
        print(f"\nSUCCESS: {model_name} is now cached for offline use")
        print(f"  To use in offline mode, set HF_HUB_OFFLINE=1 before running your code")
        
        del model
        del tokenizer
        
        return True
        
    except Exception as e:
        print(f"\nERROR downloading {model_name}: {e}")
        return False


def verify_model_cached(model_name: str) -> bool:
    """Check if a model is cached locally."""
    cache_dir = get_cache_dir()
    model_path = cache_dir / "hub" / f"models--{model_name.replace('/', '--')}"
    return model_path.exists()


def verify_offline_mode(model_name: str) -> bool:
    """Verify that a model works in offline mode."""
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"
    
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, local_files_only=True)
        del model
        del tokenizer
        return True
    except Exception as e:
        print(f"  Offline verification failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Pull and cache ML models for offline use")
    parser.add_argument("--force", "-f", action="store_true", help="Force re-download even if cached")
    parser.add_argument("--verify", "-v", action="store_true", help="Verify offline mode after download")
    parser.add_argument("--list", "-l", action="store_true", help="List available models")
    args = parser.parse_args()
    
    print("=" * 60)
    print("ML Model Downloader for Email Threat Analysis")
    print("=" * 60)
    
    if args.list:
        print("\nModels available for download:")
        for i, model in enumerate(MODELS_TO_PULL, 1):
            status = "cached" if verify_model_cached(model["name"]) else "not cached"
            print(f"  {i}. {model['name']}")
            print(f"     {model.get('description', 'N/A')}")
            print(f"     Status: {status}")
        return
    
    success_count = 0
    fail_count = 0
    
    for model in MODELS_TO_PULL:
        if not args.force and verify_model_cached(model["name"]):
            print(f"\n{model['name']} is already cached, skipping (use --force to re-download)")
            if args.verify:
                print("  Verifying offline mode...")
                if verify_offline_mode(model["name"]):
                    print("  Offline verification: PASSED")
                else:
                    print("  Offline verification: FAILED")
                    fail_count += 1
                    success_count -= 1
            success_count += 1
            continue
        
        if pull_model(model, force=args.force):
            success_count += 1
            if args.verify:
                print("  Verifying offline mode...")
                if verify_offline_mode(model["name"]):
                    print("  Offline verification: PASSED")
                else:
                    print("  Offline verification: FAILED")
                    fail_count += 1
        else:
            fail_count += 1
    
    print("\n" + "=" * 60)
    print("Download Summary")
    print("=" * 60)
    print(f"  Total models: {len(MODELS_TO_PULL)}")
    print(f"  Successful: {success_count}")
    print(f"  Failed: {fail_count}")
    
    if success_count > 0:
        print(f"\nTo use in offline mode, set environment variables:")
        print(f"  export HF_HUB_OFFLINE=1")
        print(f"  export TRANSFORMERS_OFFLINE=1")
        print(f"\nOr in Windows PowerShell:")
        print(f"  $env:HF_HUB_OFFLINE=1")
        print(f"  $env:TRANSFORMERS_OFFLINE=1")
    
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
