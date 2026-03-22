"""
Download CICIDS2017 Dataset
Downloads from Kaggle using kagglehub (primary) or UNB website (fallback).
"""

import os
import sys
import shutil
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR  = BASE_DIR / "data" / "raw" / "cicids2017"


def download_kagglehub():
    """Download via kagglehub (auto-authenticates)."""
    import kagglehub
    print("Downloading CICIDS2017 via kagglehub...")
    print("(This may prompt for Kaggle credentials on first use)\n")
    
    path = kagglehub.dataset_download("cicdataset/cicids2017")
    print(f"\n✅ Downloaded to: {path}")
    return Path(path)


def copy_csvs(src_dir: Path, dst_dir: Path):
    """Copy CSV files from download location to our data directory."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all CSVs (may be in subdirectories)
    csv_files = list(src_dir.rglob("*.csv"))
    if not csv_files:
        print(f"❌ No CSV files found in {src_dir}")
        return False
    
    print(f"\nCopying {len(csv_files)} CSV files to {dst_dir}...")
    for csv_file in csv_files:
        dest = dst_dir / csv_file.name
        if not dest.exists():
            print(f"  Copying {csv_file.name} ({csv_file.stat().st_size / (1024*1024):.1f} MB)...")
            shutil.copy2(csv_file, dest)
        else:
            print(f"  ✅ Already exists: {csv_file.name}")
    
    return True


def main():
    print("=" * 60)
    print("CICIDS2017 DATASET DOWNLOAD")
    print("=" * 60)
    
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check if CSVs already exist
    existing_csvs = list(RAW_DIR.glob("*.csv"))
    if len(existing_csvs) >= 8:
        print(f"\n✅ Dataset already downloaded — {len(existing_csvs)} CSV files found:")
        total_size = 0
        for f in sorted(existing_csvs):
            size = f.stat().st_size / (1024*1024)
            total_size += size
            print(f"   • {f.name} ({size:.1f} MB)")
        print(f"   Total: {total_size:.0f} MB")
        return
    
    # Method 1: kagglehub
    try:
        download_path = download_kagglehub()
        if copy_csvs(download_path, RAW_DIR):
            final_csvs = list(RAW_DIR.glob("*.csv"))
            print(f"\n{'='*60}")
            print(f"DOWNLOAD COMPLETE — {len(final_csvs)} CSV files")
            print(f"{'='*60}")
            for f in sorted(final_csvs):
                print(f"  • {f.name} ({f.stat().st_size / (1024*1024):.1f} MB)")
            return
    except Exception as e:
        print(f"\n⚠️  kagglehub download failed: {e}")
    
    # Fallback: manual instructions
    print(f"""
{'='*60}
MANUAL DOWNLOAD REQUIRED
{'='*60}

The automatic download couldn't complete. Please download the CICIDS2017 
dataset manually and place the CSV files in:

  {RAW_DIR}

Download options:
  1. Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017
     → Download the "MachineLearningCSV" files
  
  2. UNB: https://www.unb.ca/cic/datasets/ids-2017.html
     → Download "MachineLearningCSV.zip"

Expected files (8 CSVs):
  • Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  • Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  • Friday-WorkingHours-Morning.pcap_ISCX.csv
  • Monday-WorkingHours.pcap_ISCX.csv
  • Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
  • Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
  • Tuesday-WorkingHours.pcap_ISCX.csv
  • Wednesday-workingHours.pcap_ISCX.csv

After placing the files, run:
  python scripts/preprocess_cicids2017.py
""")


if __name__ == "__main__":
    main()
