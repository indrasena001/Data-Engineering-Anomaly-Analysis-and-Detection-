"""
visualization.py — Generate and save charts for the anomaly detection pipeline.

Produces 8 publication-quality charts using Matplotlib and Seaborn,
saved as PNG images in output/charts/.
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/headless use
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import ConfusionMatrixDisplay, RocCurveDisplay, roc_curve, auc
from sklearn.preprocessing import label_binarize
from src.config import CHARTS_DIR, SEVERITY_MAP


# ── Style Configuration ──────────────────────────────────────────────────────
DARK_BG = "#0d1117"
CARD_BG = "#161b22"
TEXT_COLOR = "#e2e8f0"
GRID_COLOR = "#21262d"
ACCENT_COLORS = [
    "#00f0ff", "#7c3aed", "#ff3366", "#f59e0b", "#10b981",
    "#3b82f6", "#f97316", "#ec4899", "#6366f1", "#14b8a6",
]


def _apply_dark_style():
    """Apply dark cybersecurity-themed style to matplotlib."""
    plt.rcParams.update({
        "figure.facecolor": DARK_BG,
        "axes.facecolor": CARD_BG,
        "axes.edgecolor": GRID_COLOR,
        "axes.labelcolor": TEXT_COLOR,
        "text.color": TEXT_COLOR,
        "xtick.color": TEXT_COLOR,
        "ytick.color": TEXT_COLOR,
        "grid.color": GRID_COLOR,
        "grid.alpha": 0.3,
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
    })


def _save_chart(fig, name: str):
    """Save figure to charts directory."""
    os.makedirs(CHARTS_DIR, exist_ok=True)
    filepath = os.path.join(CHARTS_DIR, name)
    fig.savefig(filepath, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    print(f"    ✓ Saved: {name}")


def plot_attack_distribution(df: pd.DataFrame):
    """Bar chart of attack type counts."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(12, 6))

    counts = df["attack_category"].value_counts()
    colors = ACCENT_COLORS[:len(counts)]

    bars = ax.barh(counts.index, counts.values, color=colors, edgecolor="none", height=0.6)
    ax.set_xlabel("Number of Flows")
    ax.set_title("Attack Type Distribution")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.2)

    # Add value labels
    for bar, val in zip(bars, counts.values):
        ax.text(val + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", ha="left", fontsize=9, color=TEXT_COLOR)

    _save_chart(fig, "attack_distribution.png")


def plot_correlation_heatmap(df: pd.DataFrame, feature_names: list[str]):
    """Feature correlation matrix heatmap."""
    _apply_dark_style()
    available = [f for f in feature_names if f in df.columns][:20]  # Top 20 for readability

    corr = df[available].corr()
    fig, ax = plt.subplots(figsize=(14, 12))
    sns.heatmap(
        corr, ax=ax, cmap="coolwarm", center=0,
        square=True, linewidths=0.5, linecolor=GRID_COLOR,
        cbar_kws={"shrink": 0.8, "label": "Correlation"},
        xticklabels=True, yticklabels=True,
        annot=False,
    )
    ax.set_title("Feature Correlation Matrix")
    plt.xticks(rotation=45, ha="right", fontsize=7)
    plt.yticks(fontsize=7)
    _save_chart(fig, "correlation_heatmap.png")


def plot_feature_importance(feature_importance: list[tuple], top_n: int = 20):
    """Horizontal bar chart of top N features by Random Forest importance."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(10, 8))

    top = feature_importance[:top_n]
    names = [f[0] for f in reversed(top)]
    values = [f[1] for f in reversed(top)]

    colors = [ACCENT_COLORS[i % len(ACCENT_COLORS)] for i in range(len(names))]
    ax.barh(names, values, color=list(reversed(colors)), edgecolor="none", height=0.6)
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top {top_n} Feature Importances (Random Forest)")
    ax.grid(axis="x", alpha=0.2)

    _save_chart(fig, "feature_importance.png")


def plot_confusion_matrix(cm: np.ndarray, class_names: list[str]):
    """Multi-class confusion matrix heatmap."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(10, 8))

    sns.heatmap(
        cm, ax=ax, annot=True, fmt="d", cmap="YlOrRd",
        xticklabels=class_names, yticklabels=class_names,
        linewidths=0.5, linecolor=GRID_COLOR,
        cbar_kws={"shrink": 0.8},
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix (Random Forest)")
    plt.xticks(rotation=45, ha="right", fontsize=8)
    plt.yticks(fontsize=8)
    _save_chart(fig, "confusion_matrix.png")


def plot_roc_curve(y_test: np.ndarray, y_proba: np.ndarray,
                   class_names: list[str]):
    """ROC curves for multi-class classification (one-vs-rest)."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(10, 8))

    # Binarize labels for OvR
    y_bin = label_binarize(y_test, classes=range(len(class_names)))

    for i, cls in enumerate(class_names):
        if y_bin.shape[1] <= i:
            continue
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_proba[:, i])
        roc_auc = auc(fpr, tpr)
        color = ACCENT_COLORS[i % len(ACCENT_COLORS)]
        ax.plot(fpr, tpr, color=color, lw=1.5, alpha=0.8,
                label=f"{cls} (AUC={roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "w--", alpha=0.3, lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves (One-vs-Rest)")
    ax.legend(loc="lower right", fontsize=8, framealpha=0.3)
    ax.grid(alpha=0.15)
    _save_chart(fig, "roc_curve.png")


def plot_anomaly_scores(scores: np.ndarray, y_true_binary: np.ndarray):
    """Distribution of Isolation Forest anomaly scores by class."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    normal_scores = scores[y_true_binary == 0]
    attack_scores = scores[y_true_binary == 1]

    ax.hist(normal_scores, bins=80, alpha=0.6, color="#10b981", label="Benign", density=True)
    ax.hist(attack_scores, bins=80, alpha=0.6, color="#ff3366", label="Attack", density=True)
    ax.axvline(x=0, color="#f59e0b", linestyle="--", lw=1.5, alpha=0.8, label="Decision Boundary")
    ax.set_xlabel("Anomaly Score")
    ax.set_ylabel("Density")
    ax.set_title("Isolation Forest Anomaly Score Distribution")
    ax.legend(framealpha=0.3)
    ax.grid(alpha=0.15)
    _save_chart(fig, "anomaly_scores.png")


def plot_severity_distribution(df: pd.DataFrame):
    """Pie chart of attack severity levels."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(8, 8))

    df_copy = df.copy()
    df_copy["severity"] = df_copy["attack_category"].map(SEVERITY_MAP).fillna("unknown")
    sev_counts = df_copy[df_copy["severity"] != "none"]["severity"].value_counts()

    severity_colors = {
        "critical": "#ff3366",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#3b82f6",
        "unknown": "#64748b",
    }
    colors = [severity_colors.get(s, "#64748b") for s in sev_counts.index]

    wedges, texts, autotexts = ax.pie(
        sev_counts.values, labels=sev_counts.index, colors=colors,
        autopct="%1.1f%%", pctdistance=0.85, startangle=90,
        wedgeprops={"edgecolor": DARK_BG, "linewidth": 2},
    )
    for text in texts + autotexts:
        text.set_color(TEXT_COLOR)
        text.set_fontsize(10)
    ax.set_title("Attack Severity Distribution")
    _save_chart(fig, "severity_distribution.png")


def plot_protocol_distribution(df: pd.DataFrame):
    """Bar chart of protocol distribution (if protocol column exists)."""
    _apply_dark_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    # Use attack_category as a proxy for protocol distribution
    if "attack_category" in df.columns:
        attack_only = df[df["attack_category"] != "BENIGN"]
        counts = attack_only["attack_category"].value_counts().head(8)

        colors = ACCENT_COLORS[:len(counts)]
        ax.bar(range(len(counts)), counts.values, color=colors, edgecolor="none", width=0.6)
        ax.set_xticks(range(len(counts)))
        ax.set_xticklabels(counts.index, rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("Number of Flows")
        ax.set_title("Attack Category Breakdown (Attacks Only)")
        ax.grid(axis="y", alpha=0.2)

        for i, val in enumerate(counts.values):
            ax.text(i, val + max(counts) * 0.01, f"{val:,}",
                    ha="center", va="bottom", fontsize=8, color=TEXT_COLOR)

    _save_chart(fig, "protocol_distribution.png")


def generate_all_charts(
    df: pd.DataFrame,
    feature_names: list[str],
    detection_results: dict,
    transform_result: dict,
) -> list[str]:
    """
    Generate all visualization charts.

    Parameters
    ----------
    df : pd.DataFrame
        Full transformed DataFrame with labels.
    feature_names : list[str]
        Selected feature column names.
    detection_results : dict
        Output from anomaly_detection.run_anomaly_detection().
    transform_result : dict
        Output from data_transformation.transform_data().

    Returns
    -------
    list of saved chart filenames.
    """
    print("=" * 60)
    print("STEP 6: VISUALIZATION")
    print("=" * 60)
    print(f"  Saving charts to: {CHARTS_DIR}\n")

    saved = []

    # 1. Attack distribution
    print("  [1/8] Attack distribution...")
    plot_attack_distribution(df)
    saved.append("attack_distribution.png")

    # 2. Correlation heatmap
    print("  [2/8] Correlation heatmap...")
    plot_correlation_heatmap(df, feature_names)
    saved.append("correlation_heatmap.png")

    # 3. Feature importance
    print("  [3/8] Feature importance...")
    rf_result = detection_results["random_forest"]
    plot_feature_importance(rf_result["feature_importance"])
    saved.append("feature_importance.png")

    # 4. Confusion matrix
    print("  [4/8] Confusion matrix...")
    class_names = list(detection_results["label_encoder"].classes_)
    plot_confusion_matrix(rf_result["confusion_matrix"], class_names)
    saved.append("confusion_matrix.png")

    # 5. ROC curves
    print("  [5/8] ROC curves...")
    y_test = transform_result["y_test"]
    y_proba = rf_result["probabilities"]
    plot_roc_curve(y_test, y_proba, class_names)
    saved.append("roc_curve.png")

    # 6. Anomaly scores
    print("  [6/8] Anomaly score distribution...")
    if_result = detection_results["isolation_forest"]
    y_test_binary = transform_result["y_test_binary"]
    plot_anomaly_scores(if_result["scores"], y_test_binary)
    saved.append("anomaly_scores.png")

    # 7. Severity distribution
    print("  [7/8] Severity distribution...")
    plot_severity_distribution(df)
    saved.append("severity_distribution.png")

    # 8. Protocol distribution
    print("  [8/8] Protocol/attack breakdown...")
    plot_protocol_distribution(df)
    saved.append("protocol_distribution.png")

    print(f"\n{'─' * 60}")
    print(f"{len(saved)} charts generated successfully")
    print(f"{'─' * 60}\n")

    return saved


if __name__ == "__main__":
    print("Run via main.py or import generate_all_charts()")
