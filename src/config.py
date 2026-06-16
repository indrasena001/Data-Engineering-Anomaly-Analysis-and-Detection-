"""
config.py — Centralized configuration for the anomaly detection pipeline.

All paths, constants, hyperparameters, and column definitions live here
so every other module imports from a single source of truth.
"""

import os

# ── Project Root ──────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Directory Paths ───────────────────────────────────────────────────────────
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "data", "results")
CHARTS_DIR = os.path.join(PROJECT_ROOT, "output", "charts")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "output", "reports")
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")

# ── File Paths ────────────────────────────────────────────────────────────────
MERGED_RAW_FILE = os.path.join(PROCESSED_DATA_DIR, "merged_raw.csv")
CLEANED_FILE = os.path.join(PROCESSED_DATA_DIR, "cleaned_traffic.csv")
FEATURES_FILE = os.path.join(PROCESSED_DATA_DIR, "features.csv")
ANOMALY_RESULTS_FILE = os.path.join(RESULTS_DIR, "anomaly_results.csv")
MODEL_METRICS_FILE = os.path.join(RESULTS_DIR, "model_metrics.json")
DASHBOARD_DATA_FILE = os.path.join(RESULTS_DIR, "dashboard_data.json")
SCALER_FILE = os.path.join(RESULTS_DIR, "scaler.pkl")
RF_MODEL_FILE = os.path.join(RESULTS_DIR, "random_forest_model.pkl")
IF_MODEL_FILE = os.path.join(RESULTS_DIR, "isolation_forest_model.pkl")

# ── CICIDS2017 Expected Files ─────────────────────────────────────────────────
CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# ── Attack Category Mapping ──────────────────────────────────────────────────
# Maps fine-grained CICIDS2017 labels → broader attack categories
ATTACK_CATEGORY_MAP = {
    "BENIGN": "BENIGN",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "Heartbleed": "Heartbleed",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack Brute Force": "Web Attack",
    "Web Attack XSS": "Web Attack",
    "Web Attack Sql Injection": "Web Attack",
    "Infiltration": "Infiltration",
    "Bot": "Botnet",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
}

# ── Severity Mapping ──────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "BENIGN": "none",
    "Brute Force": "medium",
    "DoS": "high",
    "DDoS": "critical",
    "Heartbleed": "critical",
    "Web Attack": "high",
    "Infiltration": "critical",
    "Botnet": "high",
    "PortScan": "low",
}

# ── Feature Selection ─────────────────────────────────────────────────────────
# Key numeric features to use for ML models (subset of the 78 available).
# Chosen based on literature and correlation analysis relevance.
SELECTED_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
]

# ── Model Hyperparameters ─────────────────────────────────────────────────────
ISOLATION_FOREST_PARAMS = {
    "n_estimators": 100,
    "contamination": 0.2,       # Approximate attack ratio in CICIDS2017
    "max_samples": "auto",
    "random_state": 42,
    "n_jobs": -1,
}

RANDOM_FOREST_PARAMS = {
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "random_state": 42,
    "n_jobs": -1,
    "class_weight": "balanced",  # Handle class imbalance
}

# ── Pipeline Settings ─────────────────────────────────────────────────────────
TEST_SIZE = 0.2
RANDOM_STATE = 42
MAX_SAMPLE_SIZE = 500_000  # Subsample for faster training if dataset is huge
