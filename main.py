"""
main.py — Pipeline orchestrator for the Network Intrusion & Log Anomaly Detector.

Runs the complete data engineering pipeline end-to-end:
  1. Data Ingestion     — Load & merge CICIDS2017 CSV files
  2. Data Cleaning      — Handle inf, NaN, duplicates, types
  3. Feature Engineering — Labels, selection, scaling, split
  4. Anomaly Detection  — Isolation Forest + Random Forest
  5. Statistical Analysis
  6. Visualization      — 8 charts saved as PNGs
  7. Dashboard Export   — Generate dashboard_data.json

Usage:
    python main.py
"""

import os
import sys
import time

# Ensure stdout and stderr support UTF-8 encoding for unicode terminal graphics
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Ensure the project root is on the path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from src.data_ingestion import ingest_data
from src.data_cleaning import clean_data
from src.data_transformation import transform_data
from src.anomaly_detection import run_anomaly_detection
from src.analysis import run_analysis
from src.visualization import generate_all_charts
from src.export_dashboard import export_dashboard_data


def print_banner():
    """Print the pipeline startup banner."""
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                                                        ║")
    print("║   ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗║")
    print("║   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║║")
    print("║   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║║")
    print("║   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║║")
    print("║   ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║║")
    print("║   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝║")
    print("║                                                        ║")
    print("║   Network Intrusion & Log Anomaly Detector              ║")
    print("║   Data Engineering Pipeline v1.0                        ║")
    print("║                                                        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def run_pipeline():
    """Execute the full pipeline with timing and progress tracking."""
    print_banner()

    pipeline_start = time.time()
    step_times = {}

    # ── Step 1: Data Ingestion ────────────────────────────────────────────
    t0 = time.time()
    raw_df = ingest_data()
    step_times["Data Ingestion"] = time.time() - t0

    # ── Step 2: Data Cleaning ─────────────────────────────────────────────
    t0 = time.time()
    cleaned_df = clean_data(raw_df)
    step_times["Data Cleaning"] = time.time() - t0

    # Free memory
    del raw_df

    # ── Step 3: Feature Engineering ───────────────────────────────────────
    t0 = time.time()
    transform_result = transform_data(cleaned_df)
    step_times["Feature Engineering"] = time.time() - t0

    # ── Step 4: Anomaly Detection ─────────────────────────────────────────
    t0 = time.time()
    detection_results = run_anomaly_detection(transform_result)
    step_times["Anomaly Detection"] = time.time() - t0

    # ── Step 5: Statistical Analysis ──────────────────────────────────────
    t0 = time.time()
    analysis_results = run_analysis(
        transform_result["df_full"],
        transform_result["feature_names"],
    )
    step_times["Statistical Analysis"] = time.time() - t0

    # ── Step 6: Visualization ─────────────────────────────────────────────
    t0 = time.time()
    charts = generate_all_charts(
        df=transform_result["df_full"],
        feature_names=transform_result["feature_names"],
        detection_results=detection_results,
        transform_result=transform_result,
    )
    step_times["Visualization"] = time.time() - t0

    # ── Step 7: Dashboard Export ──────────────────────────────────────────
    t0 = time.time()
    dashboard_path = export_dashboard_data(
        df=transform_result["df_full"],
        analysis=analysis_results,
        detection_results=detection_results,
    )
    step_times["Dashboard Export"] = time.time() - t0

    # ── Final Summary ─────────────────────────────────────────────────────
    total_elapsed = time.time() - pipeline_start
    minutes = int(total_elapsed // 60)
    seconds = int(total_elapsed % 60)

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║               PIPELINE COMPLETE                        ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║                                                        ║")

    for i, (step_name, elapsed) in enumerate(step_times.items(), 1):
        status = "✓"
        time_str = f"{elapsed:.1f}s"
        line = f"  Step {i}/7: {step_name:<25} {status} ({time_str:>8})"
        print(f"║{line:<56}║")

    print("║                                                        ║")
    print(f"║  Total time: {minutes}m {seconds}s{' ' * (40 - len(f'{minutes}m {seconds}s'))}║")
    print("║                                                        ║")
    print("║  Output files:                                         ║")
    print("║    • data/results/dashboard_data.json                  ║")
    print("║    • data/results/anomaly_results.csv                  ║")
    print("║    • data/results/model_metrics.json                   ║")
    print(f"║    • output/charts/ ({len(charts)} charts)                       ║")
    print("║                                                        ║")
    print("║  Open dashboard/index.html to view results.            ║")
    print("║                                                        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    run_pipeline()
