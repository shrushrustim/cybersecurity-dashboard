"""
ml_service/trainer.py — Trains all ML models from MongoDB data and saves them.
Run this once you have 500+ events in the database.

Usage:
    python ml_service/trainer.py
OR via the API endpoint:
    POST https://your-ml-service.onrender.com/model/train
"""

import logging
import sys, os
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, mean_squared_error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logger = logging.getLogger(__name__)
MODEL_DIR = Path(__file__).parent / "models"

ATTACK_TYPE_ENCODING = {
    "DDoS": 0, "Ransomware": 1, "Malware": 2, "Phishing": 3,
    "Port Scan": 4, "Brute Force": 5, "Exploit": 6, "Botnet": 7,
    "Data Breach": 8, "Unknown": 9,
}
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "UA", "NG", "PK"}
HIGH_RISK_PORTS     = {22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}


def load_training_data() -> pd.DataFrame:
    """Load threat events from MongoDB for training."""
    from config.database import get_db
    from config.settings import COLLECTION_EVENTS

    db         = get_db()
    collection = db[COLLECTION_EVENTS]
    docs       = list(collection.find({}, {
        "attack_type": 1, "severity_score": 1, "confidence": 1,
        "source_geo": 1, "port": 1, "protocol": 1,
        "is_known_bad_ip": 1, "timestamp": 1, "_id": 0
    }).limit(10000))

    if not docs:
        raise ValueError("No training data in MongoDB. Run ingestion first.")

    df = pd.DataFrame(docs)
    logger.info(f"Loaded {len(df)} events for training")
    return df


def build_feature_matrix(df: pd.DataFrame):
    """Convert raw event records into ML feature matrix."""
    features = []

    for _, row in df.iterrows():
        geo          = row.get("source_geo") or {}
        if isinstance(geo, dict):
            country_code = geo.get("country_code", "")
        else:
            country_code = ""

        attack_type  = str(row.get("attack_type", "Unknown"))
        port_raw     = row.get("port")
        port         = 443 if pd.isna(port_raw) else int(port_raw)
        confidence   = float(row.get("confidence") or 50.0)
        hour         = 12  # default

        try:
            ts   = pd.to_datetime(row.get("timestamp"))
            hour = ts.hour
        except Exception:
            pass

        attack_enc          = ATTACK_TYPE_ENCODING.get(attack_type, 9)
        is_high_risk_country= 1 if country_code in HIGH_RISK_COUNTRIES else 0
        is_high_risk_port   = 1 if port in HIGH_RISK_PORTS else 0
        hour_sin            = np.sin(2 * np.pi * hour / 24)
        hour_cos            = np.cos(2 * np.pi * hour / 24)

        features.append([
            attack_enc,
            confidence / 100.0,
            is_high_risk_country,
            is_high_risk_port,
            0,          # is_known_bad_ip (not in stored data)
            0,          # has_cvss
            0.0,        # cvss_score
            hour_sin,
            hour_cos,
        ])

    return np.array(features)


def train_all_models() -> dict:
    """Train all 3 models and save to disk."""
    MODEL_DIR.mkdir(exist_ok=True)
    results = {}

    df = load_training_data()

    if len(df) < 50:
        raise ValueError(f"Need at least 50 events, got {len(df)}. Run ingestion first.")

    X = build_feature_matrix(df)

    # ── Scaler ────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
    logger.info("Scaler saved")

    # ── Model 1: Severity Regressor ───────────────────────────────────────────
    if "severity_score" in df.columns:
        y_sev = df["severity_score"].fillna(5.0).values
        X_tr, X_te, y_tr, y_te = train_test_split(X_scaled, y_sev, test_size=0.2, random_state=42)

        sev_model = GradientBoostingRegressor(
            n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42
        )
        sev_model.fit(X_tr, y_tr)
        mse  = mean_squared_error(y_te, sev_model.predict(X_te))
        rmse = np.sqrt(mse)
        joblib.dump(sev_model, MODEL_DIR / "severity_model.pkl")
        results["severity_model"] = {"rmse": round(rmse, 3), "samples": len(y_sev)}
        logger.info(f"Severity model saved — RMSE: {rmse:.3f}")

    # ── Model 2: Attack Type Classifier ───────────────────────────────────────
    if "attack_type" in df.columns:
        # Only keep classes with enough samples
        type_counts = df["attack_type"].value_counts()
        valid_types = type_counts[type_counts >= 5].index
        df_cls      = df[df["attack_type"].isin(valid_types)]

        if len(df_cls) >= 50:
            X_cls  = build_feature_matrix(df_cls)
            X_cls  = scaler.transform(X_cls)
            y_cls  = df_cls["attack_type"].values

            le  = LabelEncoder()
            y_enc = le.fit_transform(y_cls)

            X_tr, X_te, y_tr, y_te = train_test_split(X_cls, y_enc, test_size=0.2, random_state=42)
            clf = RandomForestClassifier(
                n_estimators=150, max_depth=8, min_samples_leaf=3,
                class_weight="balanced", random_state=42
            )
            clf.fit(X_tr, y_tr)
            clf.classes_ = le.classes_   # attach string labels

            acc = clf.score(X_te, y_te)
            joblib.dump(clf, MODEL_DIR / "classifier_model.pkl")
            results["classifier_model"] = {"accuracy": round(acc, 3), "classes": list(le.classes_)}
            logger.info(f"Classifier saved — Accuracy: {acc:.3f}")

    # ── Model 3: Anomaly Detector (Isolation Forest) ───────────────────────────
    # Trained on hourly count data — no labels needed (unsupervised)
    from config.database import get_hourly_counts
    hourly = get_hourly_counts(hours_back=720)   # last 30 days

    if len(hourly) >= 20:
        counts = np.array([[h["count"]] for h in hourly], dtype=float)
        iso    = IsolationForest(
            contamination = 0.05,   # expect ~5% of hours to be anomalous
            n_estimators  = 100,
            random_state  = 42,
        )
        iso.fit(counts)
        joblib.dump(iso, MODEL_DIR / "anomaly_model.pkl")
        results["anomaly_model"] = {"samples": len(counts), "contamination": 0.05}
        logger.info(f"Isolation Forest saved — trained on {len(counts)} hourly points")
    else:
        logger.warning("Not enough hourly data for Isolation Forest — need 20+ hours")
        results["anomaly_model"] = {"skipped": "insufficient hourly data"}

    logger.info(f"Training complete: {results}")
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    result = train_all_models()
    print(f"\n✅ Training complete:\n{result}")
