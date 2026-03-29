"""
data_loader.py — Cached data fetching layer for the dashboard.
Sits between dashboard callbacks and MongoDB/ML service.
Uses Redis (Upstash, cloud) to cache query results so the dashboard
loads fast and doesn't hammer MongoDB on every 30-second refresh.

Cache TTLs:
  - Live events:      25s  (near real-time)
  - Hourly counts:    60s  (slightly stale is fine)
  - Country counts:   60s
  - MITRE data:      120s  (changes slowly)
  - CVE data:        300s  (changes rarely)
"""

import logging
from typing import List, Optional

from config.database import (
    get_recent_events, get_attack_type_counts,
    get_hourly_counts, get_country_counts,
    get_mitre_technique_counts, get_top_cves,
    get_severity_distribution,
)
from config.cloud_client import (
    cache_dashboard_data,
    ml_detect_anomalies,
    ml_health_check,
)

logger = logging.getLogger(__name__)


def load_dashboard_data(hours_back: int = 24) -> dict:
    """
    Load all data needed for a full dashboard refresh.
    Results are served from Redis cache where possible.
    On cache miss, queries MongoDB and stores result in Redis.

    This is what the Dash callback calls on every auto-refresh.
    """
    h = hours_back

    # ── Fetch from MongoDB (via Redis cache) ────────────────────────────────
    events = cache_dashboard_data(
        key         = f"events_{h}h",
        fetch_fn    = get_recent_events,
        ttl_seconds = 25,
        limit       = 500,
        hours_back  = h,
    )

    hourly = cache_dashboard_data(
        key         = f"hourly_{h}h",
        fetch_fn    = get_hourly_counts,
        ttl_seconds = 60,
        hours_back  = h,
    )

    country = cache_dashboard_data(
        key         = f"country_{h}h",
        fetch_fn    = get_country_counts,
        ttl_seconds = 60,
        hours_back  = h,
    )

    attack_counts = cache_dashboard_data(
        key         = f"attack_counts_{h}h",
        fetch_fn    = get_attack_type_counts,
        ttl_seconds = 60,
        hours_back  = h,
    )

    severity = cache_dashboard_data(
        key         = f"severity_{h}h",
        fetch_fn    = get_severity_distribution,
        ttl_seconds = 60,
        hours_back  = h,
    )

    mitre = cache_dashboard_data(
        key         = f"mitre_{h}h",
        fetch_fn    = get_mitre_technique_counts,
        ttl_seconds = 120,
        hours_back  = h,
    )

    cves = cache_dashboard_data(
        key         = "cves_top25",
        fetch_fn    = get_top_cves,
        ttl_seconds = 300,
        limit       = 25,
    )

    # ── Anomaly Detection via ML Cloud Service ──────────────────────────────
    anomaly_hours = []
    if hourly:
        # Cache anomaly results too — no need to call ML service every 30s
        anomaly_cache_key = f"anomalies_{h}h_{len(hourly)}"
        cached_anomalies  = cache_dashboard_data(
            key         = anomaly_cache_key,
            fetch_fn    = _fetch_anomalies,
            ttl_seconds = 120,
            hourly_data = hourly,
        )
        anomaly_hours = cached_anomalies.get("anomaly_hours", []) if cached_anomalies else []

    return {
        "events":        events        or [],
        "hourly":        hourly        or [],
        "country":       country       or [],
        "attack_counts": attack_counts or [],
        "severity":      severity      or [],
        "mitre":         mitre         or [],
        "cves":          cves          or [],
        "anomaly_hours": anomaly_hours,
    }


def _fetch_anomalies(hourly_data: list) -> dict:
    """Helper that calls ML cloud service for anomaly detection."""
    if not hourly_data:
        return {"anomaly_hours": []}
    result = ml_detect_anomalies(hourly_data)
    return result


def get_ml_status() -> dict:
    """Check if the ML cloud service is reachable — shown in dashboard header."""
    is_up = ml_health_check()
    return {
        "online":  is_up,
        "label":   "ML ● ONLINE" if is_up else "ML ● STANDBY",
        "color":   "#00ff88" if is_up else "#ffd700",
        "tooltip": "ML microservice is running" if is_up else "ML service sleeping (Render free tier — first request may take 30s to wake)",
    }
