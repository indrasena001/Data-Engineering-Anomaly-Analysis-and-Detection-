"""
data_cleaning.py — Clean and validate the merged CICIDS2017 dataset.

Handles infinity values, NaN imputation, duplicate removal,
data type enforcement, label standardization, and constant-column removal.
Produces a detailed cleaning report.
"""

import os
import time
import numpy as np
import pandas as pd
from src.config import CLEANED_FILE, PROCESSED_DATA_DIR


def replace_infinities(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Replace inf/-inf with NaN. Returns modified df and count of replacements."""
    inf_mask = np.isinf(df.select_dtypes(include=[np.number]))
    inf_count = inf_mask.sum().sum()
    df = df.replace([np.inf, -np.inf], np.nan)
    return df, int(inf_count)


def handle_missing_values(df: pd.DataFrame, strategy: str = "drop") -> tuple[pd.DataFrame, int]:
    """
    Handle missing values in the DataFrame.

    Parameters
    ----------
    strategy : str
        'drop' — drop rows with any NaN in numeric columns
        'median' — impute with column median
    """
    rows_before = len(df)
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    if strategy == "drop":
        df = df.dropna(subset=numeric_cols)
    elif strategy == "median":
        for col in numeric_cols:
            if df[col].isna().any():
                df[col] = df[col].fillna(df[col].median())

    rows_dropped = rows_before - len(df)
    return df, rows_dropped


def remove_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove exact duplicate rows (excluding source_file column)."""
    feature_cols = [c for c in df.columns if c != "source_file"]
    rows_before = len(df)
    df = df.drop_duplicates(subset=feature_cols, keep="first")
    return df, rows_before - len(df)


def fix_data_types(df: pd.DataFrame) -> pd.DataFrame:
    """Enforce correct data types on known columns."""
    # Attempt to convert all numeric-looking columns
    for col in df.columns:
        if col in ("Label", "source_file"):
            continue
        if df[col].dtype == object:
            try:
                df[col] = pd.to_numeric(df[col], errors="coerce")
            except (ValueError, TypeError):
                pass
    return df


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace and standardize the Label column."""
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()
        # Fix known label variations
        df["Label"] = df["Label"].replace({
            "Web Attack – Brute Force": "Web Attack Brute Force",
            "Web Attack – XSS": "Web Attack XSS",
            "Web Attack – Sql Injection": "Web Attack Sql Injection",
            "Web Attack \x96 Brute Force": "Web Attack Brute Force",
            "Web Attack \x96 XSS": "Web Attack XSS",
            "Web Attack \x96 Sql Injection": "Web Attack Sql Injection",
        })
    return df


def drop_constant_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Remove columns with zero variance (all same value)."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    constant_cols = [col for col in numeric_cols if df[col].nunique() <= 1]
    df = df.drop(columns=constant_cols)
    return df, constant_cols


def clean_data(df: pd.DataFrame, save: bool = True) -> pd.DataFrame:
    """
    Main cleaning function: runs all cleaning steps in sequence.

    Parameters
    ----------
    df : pd.DataFrame
        Raw merged DataFrame from data ingestion.
    save : bool
        If True, save cleaned data to data/processed/cleaned_traffic.csv.

    Returns
    -------
    pd.DataFrame
        Cleaned DataFrame.
    """
    print("=" * 60)
    print("STEP 2: DATA CLEANING")
    print("=" * 60)

    start_time = time.time()
    rows_initial = len(df)
    cols_initial = len(df.columns)
    print(f"Input shape: {df.shape}")

    report = {}

    # 1. Fix data types
    print("\n  [1/6] Fixing data types...")
    df = fix_data_types(df)
    print("        ✓ Numeric columns cast to float64")

    # 2. Replace infinities
    print("  [2/6] Replacing infinity values...")
    df, inf_count = replace_infinities(df)
    report["infinity_values_replaced"] = inf_count
    print(f"        ✓ {inf_count:,} infinity values → NaN")

    # 3. Handle missing values
    print("  [3/6] Handling missing values...")
    nan_before = df.isna().sum().sum()
    df, rows_dropped_nan = handle_missing_values(df, strategy="drop")
    report["nan_values_found"] = int(nan_before)
    report["rows_dropped_nan"] = rows_dropped_nan
    print(f"        ✓ {nan_before:,} NaN values found")
    print(f"        ✓ {rows_dropped_nan:,} rows dropped")

    # 4. Remove duplicates
    print("  [4/6] Removing duplicates...")
    df, dups_removed = remove_duplicates(df)
    report["duplicates_removed"] = dups_removed
    print(f"        ✓ {dups_removed:,} duplicate rows removed")

    # 5. Clean labels
    print("  [5/6] Standardizing labels...")
    df = clean_labels(df)
    if "Label" in df.columns:
        unique_labels = df["Label"].nunique()
        print(f"        ✓ {unique_labels} unique labels")

    # 6. Drop constant columns
    print("  [6/6] Removing constant columns...")
    df, dropped_cols = drop_constant_columns(df)
    report["constant_columns_dropped"] = dropped_cols
    print(f"        ✓ {len(dropped_cols)} constant columns dropped")
    if dropped_cols:
        for col in dropped_cols:
            print(f"          - {col}")

    # Reset index
    df = df.reset_index(drop=True)

    elapsed = time.time() - start_time

    # Summary
    print(f"\n{'─' * 60}")
    print(f"Rows:    {rows_initial:>10,}  →  {len(df):>10,}  (removed {rows_initial - len(df):,})")
    print(f"Columns: {cols_initial:>10}  →  {len(df.columns):>10}  (removed {cols_initial - len(df.columns)})")
    print(f"Time elapsed: {elapsed:.1f}s")
    print(f"{'─' * 60}")

    # Final label distribution
    if "Label" in df.columns:
        print(f"\nCleaned label distribution:")
        label_counts = df["Label"].value_counts()
        for label, count in label_counts.items():
            pct = count / len(df) * 100
            print(f"  {label:<35} {count:>10,}  ({pct:>5.1f}%)")

    # Save
    if save:
        os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
        print(f"\nSaving cleaned data to: {CLEANED_FILE}")
        df.to_csv(CLEANED_FILE, index=False)
        file_size = os.path.getsize(CLEANED_FILE) / 1e6
        print(f"Saved ({file_size:.1f} MB)")

    print()
    return df


if __name__ == "__main__":
    from src.data_ingestion import ingest_data
    raw_df = ingest_data(save_checkpoint=False)
    cleaned_df = clean_data(raw_df)
    print(f"Cleaning complete. Shape: {cleaned_df.shape}")
