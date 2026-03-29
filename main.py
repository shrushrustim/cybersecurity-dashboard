"""
ml_service/main.py — ML Microservice (FastAPI)
Deployed as a SEPARATE service on Render (cloud).
The Dash dashboard and backend call this via HTTP — that's the cloud microservice pattern.

Endpoints:
  POST /predict        — severity score + risk label for a single event
  POST /classify       — attack type classification
  POST /anomaly/batch  — anomaly detection on a batch of hourly counts
  GET  /health         — health check for Render
  GET  /model/info     — model metadata
"""

import os
import asyncio
import logging
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title       = "Cyber Threat ML Service",
    description = "Anomaly detection + attack classification for the Cyber Threat Dashboard",
    version     = "1.0.0",
)

# Allow dashboard (Render) to call this service
app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],   # tighten this to your dashboard URL in production
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── Model Loading ──────────────────────────────────────────────────────────────

MODEL_DIR = Path(__file__).parent / "models"

_severity_model   = None
_classifier_model = None
_anomaly_model    = None
_scaler           = None

def load_models():
    """Load trained models from disk. Called at startup."""
    global _severity_model, _classifier_model, _anomaly_model, _scaler

    MODEL_DIR.mkdir(exist_ok=True)

    # Try loading saved models — fall back to default rules if not trained yet
    try:
        _severity_model   = joblib.load(MODEL_DIR / "severity_model.pkl")
        logger.info("Severity model loaded")
    except FileNotFoundError:
        logger.warning("severity_model.pkl not found — using rule-based fallback")
        _severity_model = None

    try:
        _classifier_model = joblib.load(MODEL_DIR / "classifier_model.pkl")
        logger.info("Classifier model loaded")
    except FileNotFoundError:
        logger.warning("classifier_model.pkl not found — using rule-based fallback")
        _classifier_model = None

    try:
        _anomaly_model = joblib.load(MODEL_DIR / "anomaly_model.pkl")
        logger.info("Anomaly model loaded")
    except FileNotFoundError:
        logger.warning("anomaly_model.pkl not found — using statistical fallback")
        _anomaly_model = None

    try:
        _scaler = joblib.load(MODEL_DIR / "scaler.pkl")
        logger.info("Scaler loaded")
    except FileNotFoundError:
        _scaler = None


# ── Pydantic Request/Response Schemas ─────────────────────────────────────────

class ThreatFeatures(BaseModel):
    """Input features for severity scoring and classification."""
    source_ip:       Optional[str]  = None
    attack_type:     Optional[str]  = "Unknown"
    port:            Optional[int]  = 443
    protocol:        Optional[str]  = "TCP"
    confidence:      float          = Field(default=50.0, ge=0, le=100)
    country_code:    Optional[str]  = None
    hour_of_day:     Optional[int]  = None   # 0-23
    is_known_bad_ip: bool           = False
    cvss_score:      Optional[float]= None   # if CVE-based


class SeverityPrediction(BaseModel):
    risk_score:   float   # 0.0 - 10.0
    label:        str     # "Critical" / "High" / "Medium" / "Low"
    confidence:   float   # model confidence 0.0 - 1.0
    method:       str     # "model" or "rule_based"


class ClassificationPrediction(BaseModel):
    attack_type:  str
    confidence:   float
    alternatives: List[dict]   # top-3 other possible types
    method:       str


class HourlyPoint(BaseModel):
    hour:  str    # "2026-02-24T10"
    count: int
    avg_severity: Optional[float] = None


class AnomalyResult(BaseModel):
    hour:         str
    count:        int
    is_anomaly:   bool
    anomaly_score:float      # higher = more anomalous
    z_score:      float      # standard deviations from mean
    reason:       Optional[str] = None


class AnomalyBatchResponse(BaseModel):
    results:         List[AnomalyResult]
    anomaly_hours:   List[str]     # just the hours flagged as anomalies
    total_anomalies: int
    threshold_used:  float


# ── Feature Engineering ────────────────────────────────────────────────────────

ATTACK_TYPE_ENCODING = {
    "DDoS":        0,
    "Ransomware":  1,
    "Malware":     2,
    "Phishing":    3,
    "Port Scan":   4,
    "Brute Force": 5,
    "Exploit":     6,
    "Botnet":      7,
    "Data Breach": 8,
    "Unknown":     9,
}

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "UA", "NG", "PK"}  # based on threat intel
HIGH_RISK_PORTS     = {22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}

def extract_features(f: ThreatFeatures) -> np.ndarray:
    """Convert ThreatFeatures into a numerical feature vector for the ML model."""
    attack_enc   = ATTACK_TYPE_ENCODING.get(f.attack_type or "Unknown", 9)
    is_high_risk_country = 1 if f.country_code in HIGH_RISK_COUNTRIES else 0
    is_high_risk_port    = 1 if f.port in HIGH_RISK_PORTS else 0
    has_cvss     = 1 if f.cvss_score else 0
    cvss_val     = f.cvss_score or 0.0
    hour_sin     = np.sin(2 * np.pi * (f.hour_of_day or 12) / 24)  # cyclical hour encoding
    hour_cos     = np.cos(2 * np.pi * (f.hour_of_day or 12) / 24)

    return np.array([[
        attack_enc,
        f.confidence / 100.0,
        is_high_risk_country,
        is_high_risk_port,
        int(f.is_known_bad_ip),
        has_cvss,
        cvss_val / 10.0,
        hour_sin,
        hour_cos,
    ]])


# ── Rule-Based Fallbacks (used when models aren't trained yet) ─────────────────

def rule_based_severity(f: ThreatFeatures) -> SeverityPrediction:
    """
    Deterministic rule-based severity scoring.
    Used as fallback before ML model is trained, and as a sanity check.
    """
    score = 3.0  # baseline

    # Attack type risk
    type_scores = {
        "Ransomware": 9.0, "Exploit": 7.5, "Malware": 7.0,
        "DDoS": 6.5, "Data Breach": 6.5, "Botnet": 5.5,
        "Brute Force": 5.0, "Phishing": 4.5, "Port Scan": 3.0,
    }
    score = max(score, type_scores.get(f.attack_type or "", 3.0))

    # Modifiers
    if f.country_code in HIGH_RISK_COUNTRIES: score = min(score + 1.5, 10)
    if f.port in HIGH_RISK_PORTS:             score = min(score + 0.5, 10)
    if f.is_known_bad_ip:                     score = min(score + 1.0, 10)
    if f.cvss_score and f.cvss_score > 8:     score = min(f.cvss_score, score + 1.5)
    if f.confidence > 85:                     score = min(score + 0.5, 10)

    score = round(score, 1)

    if score >= 8.0:    label = "Critical"
    elif score >= 6.0:  label = "High"
    elif score >= 4.0:  label = "Medium"
    else:               label = "Low"

    return SeverityPrediction(
        risk_score=score, label=label, confidence=0.75, method="rule_based"
    )


def rule_based_classify(f: ThreatFeatures) -> ClassificationPrediction:
    """Rule-based attack type classification (fallback)."""
    port_map = {
        22: "Brute Force", 3389: "Brute Force", 21: "Brute Force",
        80: "Exploit",     443: "Exploit",      8080: "Exploit",
        25: "Phishing",    465: "Phishing",
    }
    attack = f.attack_type or port_map.get(f.port or 0, "Unknown")
    return ClassificationPrediction(
        attack_type  = attack,
        confidence   = 0.65,
        alternatives = [],
        method       = "rule_based",
    )


def statistical_anomaly_detection(
    hourly_data: List[HourlyPoint],
    z_threshold: float = 2.5,
) -> AnomalyBatchResponse:
    """
    Z-score based anomaly detection.
    Flags hours where attack count is z_threshold standard deviations above mean.
    Used as fallback when Isolation Forest model isn't trained.
    """
    if len(hourly_data) < 5:
        return AnomalyBatchResponse(
            results=[], anomaly_hours=[], total_anomalies=0, threshold_used=z_threshold
        )

    counts = np.array([h.count for h in hourly_data], dtype=float)
    mean   = counts.mean()
    std    = counts.std() if counts.std() > 0 else 1.0

    results       = []
    anomaly_hours = []

    for point in hourly_data:
        z     = (point.count - mean) / std
        is_an = z > z_threshold

        reason = None
        if is_an:
            reason = f"Count {point.count} is {z:.1f}σ above mean ({mean:.0f})"
            anomaly_hours.append(point.hour)

        results.append(AnomalyResult(
            hour          = point.hour,
            count         = point.count,
            is_anomaly    = is_an,
            anomaly_score = float(max(z, 0)),
            z_score       = float(z),
            reason        = reason,
        ))

    return AnomalyBatchResponse(
        results         = results,
        anomaly_hours   = anomaly_hours,
        total_anomalies = len(anomaly_hours),
        threshold_used  = z_threshold,
    )


# ── WebSocket Alert Broadcasting ───────────────────────────────────────────────

class _ConnectionManager:
    """Manages active WebSocket connections for real-time alert push."""
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info(f"WebSocket client connected — {len(self.active)} total")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)
        logger.info(f"WebSocket client disconnected — {len(self.active)} remaining")

    async def broadcast(self, message: dict):
        dead = set()
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        self.active -= dead

_manager = _ConnectionManager()
_last_alert_ts: Optional[str] = None   # tracks watermark so we don't replay old alerts


async def _poll_and_broadcast():
    """Background task: polls MongoDB every 10s and pushes new alerts to WebSocket clients."""
    global _last_alert_ts

    # Seed the watermark with the latest existing alert so we only push NEW ones
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), ".."))
        from pymongo import MongoClient
        import certifi
        from config.settings import MONGO_URI, MONGO_DB_NAME, COLLECTION_ALERTS
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000,
                              tls=True, tlsAllowInvalidCertificates=True,
                              tlsCAFile=certifi.where())
        latest = _client[MONGO_DB_NAME][COLLECTION_ALERTS].find_one(
            {}, {"created_at": 1}, sort=[("created_at", -1)]
        )
        if latest:
            _last_alert_ts = latest["created_at"]
        logger.info(f"Alert poller seeded — watermark: {_last_alert_ts}")
    except Exception as e:
        logger.warning(f"Alert poller seed failed (will pick up all alerts): {e}")

    while True:
        await asyncio.sleep(10)
        if not _manager.active:
            continue    # no clients — skip DB query
        try:
            from pymongo import MongoClient
            import certifi
            from config.settings import MONGO_URI, MONGO_DB_NAME, COLLECTION_ALERTS

            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000,
                                  tls=True, tlsAllowInvalidCertificates=True,
                                  tlsCAFile=certifi.where())
            query = {"resolved": False}
            if _last_alert_ts:
                query["created_at"] = {"$gt": _last_alert_ts}

            new_alerts = list(
                _client[MONGO_DB_NAME][COLLECTION_ALERTS]
                .find(query, {"_id": 0})
                .sort("created_at", 1)
                .limit(10)
            )

            for alert in new_alerts:
                await _manager.broadcast({
                    "type":       "alert",
                    "title":      alert.get("title", "Threat Alert"),
                    "severity":   alert.get("severity", "High"),
                    "message":    (alert.get("message") or "")[:200],
                    "alert_type": alert.get("alert_type", ""),
                    "created_at": alert.get("created_at", ""),
                })
                _last_alert_ts = alert["created_at"]
                logger.info(f"Broadcast alert: {alert.get('title')}")

        except Exception as e:
            logger.error(f"Alert poller error: {e}")


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    load_models()
    asyncio.create_task(_poll_and_broadcast())
    logger.info("ML Service ready — alert poller running")


@app.get("/health")
def health():
    """Render calls this to check the service is alive."""
    return {
        "status":  "healthy",
        "time":    datetime.utcnow().isoformat(),
        "models":  {
            "severity_model":   _severity_model is not None,
            "classifier_model": _classifier_model is not None,
            "anomaly_model":    _anomaly_model is not None,
        }
    }


@app.get("/model/info")
def model_info():
    return {
        "severity_model":   str(type(_severity_model).__name__) if _severity_model else "rule_based_fallback",
        "classifier_model": str(type(_classifier_model).__name__) if _classifier_model else "rule_based_fallback",
        "anomaly_model":    str(type(_anomaly_model).__name__) if _anomaly_model else "statistical_zscore",
        "feature_count":    9,
        "attack_types":     list(ATTACK_TYPE_ENCODING.keys()),
    }


@app.post("/predict", response_model=SeverityPrediction)
def predict_severity(features: ThreatFeatures):
    """
    Predict severity score (0-10) and risk label for a threat event.
    Called by the dashboard when displaying individual event details.
    """
    if _severity_model is None:
        return rule_based_severity(features)

    try:
        X = extract_features(features)
        if _scaler:
            X = _scaler.transform(X)
        score = float(_severity_model.predict(X)[0])
        score = max(0.0, min(10.0, round(score, 1)))

        # Try to get model confidence (works for tree-based models)
        conf = 0.85
        try:
            proba = _severity_model.predict_proba(X)
            conf  = float(np.max(proba))
        except Exception:
            pass

        if score >= 8.0:    label = "Critical"
        elif score >= 6.0:  label = "High"
        elif score >= 4.0:  label = "Medium"
        else:               label = "Low"

        return SeverityPrediction(
            risk_score=score, label=label, confidence=conf, method="model"
        )
    except Exception as e:
        logger.error(f"Prediction error: {e} — falling back to rules")
        return rule_based_severity(features)


@app.post("/classify", response_model=ClassificationPrediction)
def classify_attack(features: ThreatFeatures):
    """
    Classify the attack type from features.
    Returns primary type + top alternatives with confidence scores.
    """
    if _classifier_model is None:
        return rule_based_classify(features)

    try:
        X = extract_features(features)
        if _scaler:
            X = _scaler.transform(X)

        pred  = _classifier_model.predict(X)[0]
        proba = _classifier_model.predict_proba(X)[0]
        classes = _classifier_model.classes_

        # Top 3 alternatives
        top3_idx  = np.argsort(proba)[::-1][:3]
        alternatives = [
            {"attack_type": classes[i], "confidence": round(float(proba[i]), 3)}
            for i in top3_idx if classes[i] != pred
        ][:2]

        return ClassificationPrediction(
            attack_type  = pred,
            confidence   = round(float(max(proba)), 3),
            alternatives = alternatives,
            method       = "model",
        )
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return rule_based_classify(features)


@app.post("/anomaly/batch", response_model=AnomalyBatchResponse)
def detect_anomalies(
    hourly_data: List[HourlyPoint],
    z_threshold: float = 2.5,
):
    """
    Detect anomalous hours in a time series of hourly attack counts.
    Used by the dashboard to highlight spike markers on the time-series chart.
    Called with the last 24-48 hours of data on each dashboard refresh.
    """
    if not hourly_data:
        raise HTTPException(status_code=400, detail="No hourly data provided")

    # Isolation Forest path
    if _anomaly_model is not None:
        try:
            counts = np.array([[h.count] for h in hourly_data], dtype=float)
            preds  = _anomaly_model.predict(counts)   # -1 = anomaly, 1 = normal
            scores = _anomaly_model.score_samples(counts)
            # Normalize scores to 0-1 range (higher = more anomalous)
            norm_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

            results       = []
            anomaly_hours = []
            mean_count    = float(np.mean([h.count for h in hourly_data]))
            std_count     = float(np.std([h.count for h in hourly_data])) or 1.0

            for i, point in enumerate(hourly_data):
                is_an = preds[i] == -1
                z     = (point.count - mean_count) / std_count
                if is_an:
                    anomaly_hours.append(point.hour)

                results.append(AnomalyResult(
                    hour          = point.hour,
                    count         = point.count,
                    is_anomaly    = is_an,
                    anomaly_score = round(float(norm_scores[i]), 3),
                    z_score       = round(float(z), 2),
                    reason        = f"Isolation Forest flagged: score={norm_scores[i]:.2f}" if is_an else None,
                ))

            return AnomalyBatchResponse(
                results         = results,
                anomaly_hours   = anomaly_hours,
                total_anomalies = len(anomaly_hours),
                threshold_used  = z_threshold,
            )
        except Exception as e:
            logger.error(f"Isolation Forest error: {e} — falling back to z-score")

    # Statistical fallback
    return statistical_anomaly_detection(hourly_data, z_threshold)


# ── WebSocket Endpoint ─────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def alerts_websocket(ws: WebSocket):
    """
    WebSocket endpoint for real-time alert push to the dashboard.
    The dashboard JS connects here and receives alert JSON messages.
    """
    await _manager.connect(ws)
    try:
        while True:
            # Keep connection alive — client may send pings, we just ignore them
            await ws.receive_text()
    except WebSocketDisconnect:
        _manager.disconnect(ws)
    except Exception:
        _manager.disconnect(ws)


# ── Model Training Endpoint (call once to train from DB data) ──────────────────

@app.post("/model/train")
def train_models():
    """
    Train models from data currently in MongoDB.
    Call this endpoint once after you have enough data (500+ events).
    POST to: https://your-ml-service.onrender.com/model/train
    """
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from ml_service.trainer import train_all_models
        result = train_all_models()
        load_models()  # reload after training
        return {"status": "success", "result": result}
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
