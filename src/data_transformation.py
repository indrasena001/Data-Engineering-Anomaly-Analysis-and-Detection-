"""
data_transformation.py — Feature engineering, encoding, and train/test splitting.

Creates binary and categorical attack labels, selects relevant features,
applies StandardScaler normalization, and produces a stratified train/test split.
"""

import os
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from src.config import (
    ATTACK_CATEGORY_MAP,
    SELECTED_FEATURES,
    FEATURES_FILE,
    SCALER_FILE,
    PROCESSED_DATA_DIR,
    RESULTS_DIR,
    TEST_SIZE,
    RANDOM_STATE,
    MAX_SAMPLE_SIZE,
)


def create_attack_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived label columns:
      - is_attack: binary (0 = BENIGN, 1 = attack)
      - attack_category: broad category (DoS, DDoS, Brute Force, etc.)
    """
    df = df.copy()
    df["is_attack"] = (df["Label"] != "BENIGN").astype(int)
    df["attack_category"] = df["Label"].map(ATTACK_CATEGORY_MAP).fillna("Unknown")
    return df


def select_features(df: pd.DataFrame, feature_list: list[str] = None) -> list[str]:
    """
    Select features that exist in the DataFrame from the configured list.
    Falls back to auto-selection if too few configured features are found.
    """
    if feature_list is None:
        feature_list = SELECTED_FEATURES

    available = [f for f in feature_list if f in df.columns]

    if len(available) < 10:
        # Fallback: auto-select top numeric features by variance
        print(f"  ⚠ Only {len(available)} configured features found.")
        print(f"    Falling back to auto-selection by variance...")
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude = {"is_attack", "source_file"}
        numeric_cols = [c for c in numeric_cols if c not in exclude]
        variances = df[numeric_cols].var().sort_values(ascending=False)
        available = variances.head(40).index.tolist()
        print(f"    Selected {len(available)} features by variance.")

    return available


def subsample_if_needed(df: pd.DataFrame, max_size: int) -> pd.DataFrame:
    """Subsample the DataFrame if it exceeds max_size for faster ML training."""
    if len(df) > max_size:
        print(f"  Subsampling: {len(df):,} → {max_size:,} rows (stratified by attack_category)")
        df = df.groupby("attack_category", group_keys=False).apply(
            lambda x: x.sample(
                n=min(len(x), max(1, int(max_size * len(x) / len(df)))),
                random_state=RANDOM_STATE,
            )
        ).reset_index(drop=True)
        print(f"  Actual subsample size: {len(df):,}")
    return df


def transform_data(
    df: pd.DataFrame,
    save: bool = True,
) -> dict:
    """
    Main transformation function.

    Parameters
    ----------
    df : pd.DataFrame
        Cleaned DataFrame from data_cleaning.
    save : bool
        If True, save feature data and scaler.

    Returns
    -------
    dict with keys:
        'X_train', 'X_test', 'y_train', 'y_test' — split data
        'feature_names' — list of selected feature column names
        'label_encoder' — fitted LabelEncoder for attack_category
        'scaler' — fitted StandardScaler
        'df_full' — full DataFrame with labels for analysis
    """
    print("=" * 60)
    print("STEP 3: FEATURE ENGINEERING")
    print("=" * 60)

    start_time = time.time()

    # 1. Create attack labels
    print("\n  [1/5] Creating attack labels...")
    df = create_attack_labels(df)

    attack_dist = df["attack_category"].value_counts()
    print(f"        Attack categories:")
    for cat, count in attack_dist.items():
        pct = count / len(df) * 100
        print(f"          {cat:<20} {count:>10,}  ({pct:.1f}%)")

    # 2. Select features
    print("\n  [2/5] Selecting features...")
    feature_names = select_features(df)
    print(f"        {len(feature_names)} features selected:")
    for i, f in enumerate(feature_names, 1):
        print(f"          {i:>3}. {f}")

    # 3. Prepare feature matrix
    print("\n  [3/5] Preparing feature matrix...")
    df_ml = df[feature_names + ["is_attack", "attack_category", "Label"]].copy()

    # Drop any remaining NaN in feature columns
    nan_rows = df_ml[feature_names].isna().any(axis=1).sum()
    if nan_rows > 0:
        print(f"        Dropping {nan_rows:,} rows with remaining NaN values")
        df_ml = df_ml.dropna(subset=feature_names).reset_index(drop=True)

    # Subsample for performance
    df_ml = subsample_if_needed(df_ml, MAX_SAMPLE_SIZE)

    # 4. Scale features
    print("\n  [4/5] Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_ml[feature_names])
    X_scaled = pd.DataFrame(X_scaled, columns=feature_names)

    # Encode attack categories
    le = LabelEncoder()
    y_category = le.fit_transform(df_ml["attack_category"])
    y_binary = df_ml["is_attack"].values

    print(f"        Classes: {list(le.classes_)}")

    # 5. Train/test split
    print(f"\n  [5/5] Splitting into train/test ({int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled,
        y_category,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_category,
    )

    # Also split binary labels for Isolation Forest evaluation
    _, _, y_train_bin, y_test_bin = train_test_split(
        X_scaled,
        y_binary,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_category,
    )

    print(f"        Train: {len(X_train):>10,} samples")
    print(f"        Test:  {len(X_test):>10,} samples")

    elapsed = time.time() - start_time

    print(f"\n{'─' * 60}")
    print(f"Features:     {len(feature_names)}")
    print(f"Train/Test:   {len(X_train):,} / {len(X_test):,}")
    print(f"Classes:      {len(le.classes_)}")
    print(f"Time elapsed: {elapsed:.1f}s")
    print(f"{'─' * 60}\n")

    # Save artifacts
    if save:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

        joblib.dump(scaler, SCALER_FILE)
        print(f"Scaler saved to: {SCALER_FILE}")

        # Save features CSV for reference
        df_features = df_ml.copy()
        df_features.to_csv(FEATURES_FILE, index=False)
        print(f"Features saved to: {FEATURES_FILE}")

    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "y_train_binary": y_train_bin,
        "y_test_binary": y_test_bin,
        "feature_names": feature_names,
        "label_encoder": le,
        "scaler": scaler,
        "df_full": df_ml,
    }


if __name__ == "__main__":
    from src.data_ingestion import ingest_data
    from src.data_cleaning import clean_data

    raw = ingest_data(save_checkpoint=False)
    cleaned = clean_data(raw, save=False)
    result = transform_data(cleaned)
    print(f"Transformation complete. Train shape: {result['X_train'].shape}")
