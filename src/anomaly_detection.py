"""
anomaly_detection.py — ML-based anomaly and intrusion detection.

Trains two complementary models:
  1. Isolation Forest (unsupervised) — detects statistical outliers
  2. Random Forest Classifier (supervised) — multi-class attack classification

Evaluates both models and saves metrics, predictions, and trained models.
"""

import os
import json
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from src.config import (
    ISOLATION_FOREST_PARAMS,
    RANDOM_FOREST_PARAMS,
    ANOMALY_RESULTS_FILE,
    MODEL_METRICS_FILE,
    RF_MODEL_FILE,
    IF_MODEL_FILE,
    RESULTS_DIR,
)


def train_isolation_forest(X_train: pd.DataFrame, X_test: pd.DataFrame,
                           y_test_binary: np.ndarray) -> dict:
    """
    Train an Isolation Forest for unsupervised anomaly detection.

    Returns dict with model, predictions, and evaluation metrics.
    """
    print("\n  ── Isolation Forest (Unsupervised) ──")
    start = time.time()

    model = IsolationForest(**ISOLATION_FOREST_PARAMS)
    model.fit(X_train)

    # Predict: -1 = anomaly, 1 = normal
    y_pred_raw = model.predict(X_test)
    y_pred = (y_pred_raw == -1).astype(int)  # Convert to 0=normal, 1=anomaly

    # Anomaly scores (lower = more anomalous)
    scores = model.decision_function(X_test)

    elapsed = time.time() - start

    # Evaluate against ground truth binary labels
    acc = accuracy_score(y_test_binary, y_pred)
    prec = precision_score(y_test_binary, y_pred, zero_division=0)
    rec = recall_score(y_test_binary, y_pred, zero_division=0)
    f1 = f1_score(y_test_binary, y_pred, zero_division=0)

    print(f"    Training time:  {elapsed:.1f}s")
    print(f"    Accuracy:       {acc:.4f}")
    print(f"    Precision:      {prec:.4f}")
    print(f"    Recall:         {rec:.4f}")
    print(f"    F1-Score:       {f1:.4f}")
    print(f"    Anomalies found: {y_pred.sum():,} / {len(y_pred):,}")

    return {
        "model": model,
        "predictions": y_pred,
        "scores": scores,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "anomalies_detected": int(y_pred.sum()),
            "training_time_seconds": round(elapsed, 2),
        },
    }


def train_random_forest(X_train: pd.DataFrame, y_train: np.ndarray,
                        X_test: pd.DataFrame, y_test: np.ndarray,
                        label_encoder) -> dict:
    """
    Train a Random Forest Classifier for supervised multi-class detection.

    Returns dict with model, predictions, feature importance, and metrics.
    """
    print("\n  ── Random Forest Classifier (Supervised) ──")
    start = time.time()

    model = RandomForestClassifier(**RANDOM_FOREST_PARAMS)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    elapsed = time.time() - start

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)

    # Per-class report
    class_names = list(label_encoder.classes_)
    report = classification_report(
        y_test, y_pred,
        labels=list(range(len(class_names))),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    # Feature importance
    importances = model.feature_importances_
    feature_importance = sorted(
        zip(X_train.columns, importances),
        key=lambda x: x[1],
        reverse=True,
    )

    # ROC-AUC (one-vs-rest)
    try:
        if len(class_names) == 2:
            roc_auc = roc_auc_score(y_test, y_proba[:, 1])
        else:
            roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
        roc_auc = round(roc_auc, 4)
    except ValueError:
        roc_auc = None

    print(f"    Training time:      {elapsed:.1f}s")
    print(f"    Accuracy:           {acc:.4f}")
    print(f"    F1 (weighted):      {f1_weighted:.4f}")
    print(f"    F1 (macro):         {f1_macro:.4f}")
    if roc_auc is not None:
        print(f"    ROC-AUC (weighted): {roc_auc:.4f}")

    print(f"\n    Per-class results:")
    print(f"    {'Class':<22} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"    {'─' * 62}")
    for cls in class_names:
        if cls in report:
            r = report[cls]
            print(f"    {cls:<22} {r['precision']:>10.3f} {r['recall']:>10.3f} {r['f1-score']:>10.3f} {r['support']:>10.0f}")

    print(f"\n    Top 10 features by importance:")
    for i, (feat, imp) in enumerate(feature_importance[:10], 1):
        bar = "█" * int(imp * 100)
        print(f"      {i:>2}. {feat:<35} {imp:.4f} {bar}")

    return {
        "model": model,
        "predictions": y_pred,
        "probabilities": y_proba,
        "confusion_matrix": cm,
        "classification_report": report,
        "feature_importance": feature_importance,
        "metrics": {
            "accuracy": round(acc, 4),
            "f1_weighted": round(f1_weighted, 4),
            "f1_macro": round(f1_macro, 4),
            "roc_auc": roc_auc,
            "training_time_seconds": round(elapsed, 2),
            "per_class": {
                cls: {
                    "precision": round(report[cls]["precision"], 4),
                    "recall": round(report[cls]["recall"], 4),
                    "f1": round(report[cls]["f1-score"], 4),
                    "support": int(report[cls]["support"]),
                }
                for cls in class_names if cls in report
            },
        },
    }


def run_anomaly_detection(transform_result: dict, save: bool = True) -> dict:
    """
    Main anomaly detection function: trains both models and aggregates results.

    Parameters
    ----------
    transform_result : dict
        Output from data_transformation.transform_data().
    save : bool
        If True, save models, metrics, and predictions.

    Returns
    -------
    dict with 'isolation_forest' and 'random_forest' result dicts.
    """
    print("=" * 60)
    print("STEP 4: ANOMALY DETECTION")
    print("=" * 60)

    start_time = time.time()

    X_train = transform_result["X_train"]
    X_test = transform_result["X_test"]
    y_train = transform_result["y_train"]
    y_test = transform_result["y_test"]
    y_test_binary = transform_result["y_test_binary"]
    label_encoder = transform_result["label_encoder"]

    # Train Isolation Forest
    if_result = train_isolation_forest(X_train, X_test, y_test_binary)

    # Train Random Forest
    rf_result = train_random_forest(X_train, y_train, X_test, y_test, label_encoder)

    total_elapsed = time.time() - start_time

    print(f"\n{'─' * 60}")
    print(f"Both models trained in {total_elapsed:.1f}s")
    print(f"{'─' * 60}\n")

    # Save artifacts
    if save:
        os.makedirs(RESULTS_DIR, exist_ok=True)

        # Save models
        joblib.dump(if_result["model"], IF_MODEL_FILE)
        print(f"Isolation Forest model saved to: {IF_MODEL_FILE}")

        joblib.dump(rf_result["model"], RF_MODEL_FILE)
        print(f"Random Forest model saved to: {RF_MODEL_FILE}")

        # Save metrics
        metrics = {
            "isolation_forest": if_result["metrics"],
            "random_forest": rf_result["metrics"],
        }
        with open(MODEL_METRICS_FILE, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"Model metrics saved to: {MODEL_METRICS_FILE}")

        # Save predictions
        class_names = list(label_encoder.classes_)
        results_df = X_test.copy()
        results_df["true_label"] = label_encoder.inverse_transform(y_test)
        results_df["rf_predicted"] = label_encoder.inverse_transform(rf_result["predictions"])
        results_df["if_anomaly"] = if_result["predictions"]
        results_df["if_score"] = if_result["scores"]
        results_df.to_csv(ANOMALY_RESULTS_FILE, index=False)
        print(f"Anomaly results saved to: {ANOMALY_RESULTS_FILE}")

    return {
        "isolation_forest": if_result,
        "random_forest": rf_result,
        "label_encoder": label_encoder,
    }


if __name__ == "__main__":
    from src.data_ingestion import ingest_data
    from src.data_cleaning import clean_data
    from src.data_transformation import transform_data

    raw = ingest_data(save_checkpoint=False)
    cleaned = clean_data(raw, save=False)
    transformed = transform_data(cleaned, save=False)
    results = run_anomaly_detection(transformed)
