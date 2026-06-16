"""
data_ingestion.py — Load and merge CICIDS2017 raw CSV files.

Scans data/raw/ for CSV files, loads each with proper encoding,
strips whitespace from column names, merges into a single DataFrame,
and saves a checkpoint to data/processed/merged_raw.csv.
"""

import os
import glob
import time
import pandas as pd
from src.config import RAW_DATA_DIR, MERGED_RAW_FILE, PROCESSED_DATA_DIR


def discover_csv_files(data_dir: str) -> list[str]:
    """Find all CSV files in the raw data directory."""
    pattern = os.path.join(data_dir, "*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}.\n"
            f"Please download the CICIDS2017 MachineLearningCSV files and place them in:\n"
            f"  {data_dir}\n\n"
            f"Download from: https://www.kaggle.com/datasets/cicdataset/cicids2017\n"
            f"or: https://www.unb.ca/cic/datasets/ids-2017.html"
        )
    return files


def load_single_csv(filepath: str) -> pd.DataFrame:
    """
    Load a single CICIDS2017 CSV file with proper encoding handling.

    The original files sometimes use cp1252 encoding and have leading
    spaces in column names (e.g. ' Label' instead of 'Label').
    """
    filename = os.path.basename(filepath)

    # Try UTF-8 first, fall back to cp1252 (common in CICIDS2017)
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            df = pd.read_csv(filepath, encoding=encoding, low_memory=False)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    else:
        raise ValueError(f"Could not decode {filename} with any supported encoding.")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Add source file tracking column
    df["source_file"] = filename

    return df


def ingest_data(data_dir: str = None, save_checkpoint: bool = True) -> pd.DataFrame:
    """
    Main ingestion function: discover, load, merge all CICIDS2017 CSVs.

    Parameters
    ----------
    data_dir : str, optional
        Path to raw CSV directory. Defaults to config.RAW_DATA_DIR.
    save_checkpoint : bool
        If True, save merged DataFrame to data/processed/merged_raw.csv.

    Returns
    -------
    pd.DataFrame
        Merged DataFrame with all traffic flows and a source_file column.
    """
    if data_dir is None:
        data_dir = RAW_DATA_DIR

    print("=" * 60)
    print("STEP 1: DATA INGESTION")
    print("=" * 60)
    print(f"Scanning directory: {data_dir}\n")

    csv_files = discover_csv_files(data_dir)
    print(f"Found {len(csv_files)} CSV file(s):\n")

    frames = []
    total_start = time.time()

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        file_start = time.time()

        df = load_single_csv(filepath)
        frames.append(df)

        elapsed = time.time() - file_start
        print(f"  ✓ {filename:<60} {len(df):>10,} rows  ({elapsed:.1f}s)")

    # Merge all DataFrames
    print(f"\nMerging {len(frames)} files...")
    merged = pd.concat(frames, ignore_index=True)

    total_elapsed = time.time() - total_start
    print(f"\n{'─' * 60}")
    print(f"Total rows loaded:   {len(merged):>12,}")
    print(f"Total columns:       {len(merged.columns):>12}")
    print(f"Memory usage:        {merged.memory_usage(deep=True).sum() / 1e6:>10.1f} MB")
    print(f"Time elapsed:        {total_elapsed:>10.1f}s")
    print(f"{'─' * 60}")

    # Print column names
    print(f"\nColumns ({len(merged.columns)}):")
    for i, col in enumerate(merged.columns, 1):
        print(f"  {i:>3}. {col}")

    # Print label distribution preview
    if "Label" in merged.columns:
        print(f"\nLabel distribution:")
        label_counts = merged["Label"].value_counts()
        for label, count in label_counts.items():
            pct = count / len(merged) * 100
            print(f"  {label:<35} {count:>10,}  ({pct:>5.1f}%)")

    # Save checkpoint
    if save_checkpoint:
        os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
        print(f"\nSaving checkpoint to: {MERGED_RAW_FILE}")
        merged.to_csv(MERGED_RAW_FILE, index=False)
        file_size = os.path.getsize(MERGED_RAW_FILE) / 1e6
        print(f"Checkpoint saved ({file_size:.1f} MB)")

    print()
    return merged


if __name__ == "__main__":
    df = ingest_data()
    print(f"\nIngestion complete. Shape: {df.shape}")
