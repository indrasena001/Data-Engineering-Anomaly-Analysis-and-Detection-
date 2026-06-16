"""
analysis.py — Statistical analysis and summary generation.

Produces descriptive statistics, attack distribution breakdowns,
temporal patterns, protocol analysis, and top feature correlations.
"""

import numpy as np
import pandas as pd
from src.config import SEVERITY_MAP


def compute_summary_stats(df: pd.DataFrame) -> dict:
    """Compute high-level summary statistics for the dataset."""
    total = len(df)
    attack_count = int((df["is_attack"] == 1).sum()) if "is_attack" in df.columns else 0
    benign_count = total - attack_count

    summary = {
        "total_events": total,
        "total_anomalies": attack_count,
        "benign_count": benign_count,
        "attack_ratio": round(attack_count / total * 100, 2) if total > 0 else 0,
        "unique_labels": int(df["Label"].nunique()) if "Label" in df.columns else 0,
    }
    return summary


def compute_attack_distribution(df: pd.DataFrame) -> dict:
    """Count flows per attack category."""
    if "attack_category" not in df.columns:
        return {}

    dist = df["attack_category"].value_counts().to_dict()
    return {k: int(v) for k, v in dist.items()}


def compute_severity_breakdown(df: pd.DataFrame) -> dict:
    """Map attack categories to severity levels and count."""
    if "attack_category" not in df.columns:
        return {}

    df_copy = df.copy()
    df_copy["severity"] = df_copy["attack_category"].map(SEVERITY_MAP).fillna("unknown")
    breakdown = df_copy["severity"].value_counts().to_dict()
    return {k: int(v) for k, v in breakdown.items()}


def compute_feature_stats(df: pd.DataFrame, feature_names: list[str]) -> dict:
    """Compute descriptive statistics for selected features."""
    available = [f for f in feature_names if f in df.columns]
    if not available:
        return {}

    stats = {}
    for feat in available:
        col = df[feat]
        stats[feat] = {
            "mean": round(float(col.mean()), 4),
            "std": round(float(col.std()), 4),
            "min": round(float(col.min()), 4),
            "max": round(float(col.max()), 4),
            "median": round(float(col.median()), 4),
        }
    return stats


def compute_top_correlations(df: pd.DataFrame, feature_names: list[str],
                             top_n: int = 20) -> list[dict]:
    """Find the top N most correlated feature pairs."""
    available = [f for f in feature_names if f in df.columns]
    if len(available) < 2:
        return []

    corr_matrix = df[available].corr().abs()

    # Get upper triangle pairs
    pairs = []
    for i in range(len(available)):
        for j in range(i + 1, len(available)):
            pairs.append({
                "feature_1": available[i],
                "feature_2": available[j],
                "correlation": round(float(corr_matrix.iloc[i, j]), 4),
            })

    pairs.sort(key=lambda x: x["correlation"], reverse=True)
    return pairs[:top_n]


def compute_label_flow_stats(df: pd.DataFrame, feature_names: list[str]) -> dict:
    """Compute mean feature values grouped by attack category."""
    if "attack_category" not in df.columns:
        return {}

    available = [f for f in feature_names if f in df.columns]
    if not available:
        return {}

    grouped = df.groupby("attack_category")[available].mean()
    result = {}
    for cat in grouped.index:
        result[cat] = {
            feat: round(float(grouped.loc[cat, feat]), 4)
            for feat in available[:10]  # Limit to top 10 features for readability
        }
    return result


def run_analysis(df: pd.DataFrame, feature_names: list[str]) -> dict:
    """
    Run all statistical analyses and return aggregated results.

    Parameters
    ----------
    df : pd.DataFrame
        Transformed DataFrame with labels and features.
    feature_names : list[str]
        List of selected feature column names.

    Returns
    -------
    dict with all analysis results.
    """
    print("=" * 60)
    print("STEP 5: STATISTICAL ANALYSIS")
    print("=" * 60)

    results = {}

    print("\n  [1/5] Computing summary statistics...")
    results["summary"] = compute_summary_stats(df)
    for k, v in results["summary"].items():
        print(f"        {k}: {v:,}" if isinstance(v, int) else f"        {k}: {v}")

    print("\n  [2/5] Computing attack distribution...")
    results["attack_distribution"] = compute_attack_distribution(df)
    for cat, count in sorted(results["attack_distribution"].items(), key=lambda x: -x[1]):
        print(f"        {cat:<20} {count:>10,}")

    print("\n  [3/5] Computing severity breakdown...")
    results["severity_breakdown"] = compute_severity_breakdown(df)
    for sev, count in results["severity_breakdown"].items():
        print(f"        {sev:<15} {count:>10,}")

    print("\n  [4/5] Computing feature statistics...")
    results["feature_stats"] = compute_feature_stats(df, feature_names)
    print(f"        Stats computed for {len(results['feature_stats'])} features")

    print("\n  [5/5] Computing top correlations...")
    results["top_correlations"] = compute_top_correlations(df, feature_names)
    print(f"        Top {len(results['top_correlations'])} feature correlations computed")
    for pair in results["top_correlations"][:5]:
        print(f"        {pair['feature_1']} ↔ {pair['feature_2']}: {pair['correlation']}")

    print(f"\n{'─' * 60}")
    print(f"Analysis complete — {len(results)} sections generated")
    print(f"{'─' * 60}\n")

    return results


if __name__ == "__main__":
    from src.data_ingestion import ingest_data
    from src.data_cleaning import clean_data
    from src.data_transformation import transform_data

    raw = ingest_data(save_checkpoint=False)
    cleaned = clean_data(raw, save=False)
    transformed = transform_data(cleaned, save=False)
    analysis = run_analysis(transformed["df_full"], transformed["feature_names"])
