"""
cloud_client.py — All cloud service calls in one place.
The dashboard imports from here instead of calling services directly.
This makes it easy to swap cloud providers without touching chart code.

Services wrapped:
  - MongoDB Atlas  (via pymongo — already in database.py)
  - ML Service API (Render — HTTP calls)
  - Redis Cache    (Upstash — key/value caching)
  - GCS / Cloud Storage (optional — for CSV exports)
"""

import json
import logging
import os
from typing import Any, Optional, List
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)

# ── ML Service Client ──────────────────────────────────────────────────────────

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://localhost:8001")
_ML_TIMEOUT    = 8   # seconds — Render free tier can be slow to wake


def ml_predict_severity(
    attack_type:     str,
    confidence:      float = 50.0,
    country_code:    str   = "",
    port:            int   = 443,
    is_known_bad_ip: bool  = False,
    cvss_score:      float = None,
) -> dict:
    """
    Call the ML microservice to score a single threat event.
    Falls back to a simple rule if the ML service is unavailable
    (Render free tier sleeps after 15 min inactivity).
    """
    payload = {
        "attack_type":     attack_type,
        "confidence":      confidence,
        "country_code":    country_code,
        "port":            port,
        "is_known_bad_ip": is_known_bad_ip,
        "cvss_score":      cvss_score,
    }
    try:
        resp = requests.post(
            f"{ML_SERVICE_URL}/predict",
            json    = payload,
            timeout = _ML_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        logger.warning("ML service unavailable (may be sleeping on Render free tier)")
        return _local_severity_fallback(attack_type, confidence, country_code)
    except Exception as e:
        logger.warning(f"ML predict failed: {e}")
        return _local_severity_fallback(attack_type, confidence, country_code)


def ml_detect_anomalies(hourly_data: List[dict], z_threshold: float = 2.5) -> dict:
    """
    Send hourly counts to ML service for anomaly detection.
    Returns dict with anomaly_hours list for chart highlighting.
    """
    try:
        resp = requests.post(
            f"{ML_SERVICE_URL}/anomaly/batch",
            json    = hourly_data,
            params  = {"z_threshold": z_threshold},
            timeout = _ML_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"Anomaly detection failed: {e} — using local z-score")
        return _local_anomaly_fallback(hourly_data, z_threshold)


def ml_health_check() -> bool:
    """Returns True if the ML service is reachable."""
    try:
        resp = requests.get(f"{ML_SERVICE_URL}/health", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def _local_severity_fallback(attack_type: str, confidence: float, country_code: str) -> dict:
    """Minimal local fallback so dashboard never breaks if ML service is down."""
    HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "UA"}
    base = {"Ransomware": 9, "Exploit": 7.5, "Malware": 7, "DDoS": 6.5,
            "Brute Force": 5, "Phishing": 4.5, "Port Scan": 3}.get(attack_type, 4.0)
    score = min(base + (1.5 if country_code in HIGH_RISK_COUNTRIES else 0), 10)
    label = "Critical" if score >= 8 else "High" if score >= 6 else "Medium" if score >= 4 else "Low"
    return {"risk_score": score, "label": label, "confidence": 0.6, "method": "local_fallback"}


def _local_anomaly_fallback(hourly_data: List[dict], z_threshold: float) -> dict:
    """Z-score anomaly detection run locally as fallback."""
    import numpy as np
    counts = [h.get("count", 0) for h in hourly_data]
    if len(counts) < 3:
        return {"anomaly_hours": [], "total_anomalies": 0}
    arr    = np.array(counts, dtype=float)
    mean, std = arr.mean(), arr.std() or 1.0
    anomaly_hours = [
        hourly_data[i]["hour"]
        for i, c in enumerate(counts)
        if (c - mean) / std > z_threshold
    ]
    return {"anomaly_hours": anomaly_hours, "total_anomalies": len(anomaly_hours)}


# ── Redis Cache Client (Upstash) ───────────────────────────────────────────────

_redis_client = None

def _get_redis():
    """Lazy Redis connection — only connects when first used."""
    global _redis_client
    if _redis_client is None:
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            try:
                import redis
                _redis_client = redis.from_url(redis_url, decode_responses=True)
                _redis_client.ping()
                logger.info("Redis (Upstash) connected")
            except Exception as e:
                logger.warning(f"Redis unavailable: {e} — caching disabled")
                _redis_client = None
    return _redis_client


def cache_set(key: str, value: Any, ttl_seconds: int = 60) -> bool:
    """Store a JSON-serializable value in Redis with TTL."""
    r = _get_redis()
    if r is None:
        return False
    try:
        r.setex(key, ttl_seconds, json.dumps(value, default=str))
        return True
    except Exception as e:
        logger.warning(f"Cache set failed: {e}")
        return False


def cache_get(key: str) -> Optional[Any]:
    """Retrieve a cached value. Returns None if miss or Redis unavailable."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def cache_delete(key: str) -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        r.delete(key)
        return True
    except Exception:
        return False


def cache_dashboard_data(
    key: str,
    fetch_fn,
    ttl_seconds: int = 25,
    *args, **kwargs,
) -> Any:
    """
    Cache-aside pattern for dashboard queries.
    Tries Redis first — on miss, calls fetch_fn and caches result.

    Usage:
        data = cache_dashboard_data(
            "country_counts_24h",
            get_country_counts,
            ttl_seconds=25,
            hours_back=24,
        )
    """
    cached = cache_get(key)
    if cached is not None:
        return cached

    data = fetch_fn(*args, **kwargs)
    cache_set(key, data, ttl_seconds)
    return data


# ── Cloud Storage Client (GCP GCS — optional, for CSV/report exports) ──────────

GCS_BUCKET = os.getenv("GCS_BUCKET_NAME", "")

def upload_to_gcs(local_path: str, blob_name: str) -> Optional[str]:
    """
    Upload a file to Google Cloud Storage.
    Only used for exporting PDF reports and CSV datasets.
    Requires: pip install google-cloud-storage
    GCS_BUCKET env var set to your bucket name.
    """
    if not GCS_BUCKET:
        logger.info("GCS_BUCKET_NAME not set — skipping cloud upload")
        return None
    try:
        from google.cloud import storage
        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob   = bucket.blob(blob_name)
        blob.upload_from_filename(local_path)
        url = f"https://storage.googleapis.com/{GCS_BUCKET}/{blob_name}"
        logger.info(f"Uploaded to GCS: {url}")
        return url
    except ImportError:
        logger.warning("google-cloud-storage not installed — run: pip install google-cloud-storage")
        return None
    except Exception as e:
        logger.error(f"GCS upload failed: {e}")
        return None


def generate_signed_url(blob_name: str, expiry_minutes: int = 60) -> Optional[str]:
    """Generate a temporary signed URL for a GCS file (for report sharing)."""
    if not GCS_BUCKET:
        return None
    try:
        from google.cloud import storage
        client  = storage.Client()
        bucket  = client.bucket(GCS_BUCKET)
        blob    = bucket.blob(blob_name)
        url     = blob.generate_signed_url(
            expiration=timedelta(minutes=expiry_minutes),
            method="GET",
        )
        return url
    except Exception as e:
        logger.error(f"Signed URL generation failed: {e}")
        return None
