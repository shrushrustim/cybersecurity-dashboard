"""
alert_engine.py — Alert Engine (Module 3)
Monitors incoming threat events and fires Telegram / Email alerts
when severity spikes or thresholds are crossed.

How it works:
  - Called at the end of every ingestion run (fetch_all.py calls it)
  - Checks MongoDB for recent spike patterns
  - Sends Telegram message and/or email if threshold crossed
  - Stores alert records in MongoDB so dashboard can show them
  - Deduplication: won't re-fire the same alert within a cooldown window

Setup (all free):
  Telegram: Create a bot via @BotFather → get token + chat_id
  Email:    Use SendGrid free tier (100 emails/day) or Gmail SMTP
"""

import logging
import smtplib
import hashlib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional
from enum import Enum

import requests
from pymongo import MongoClient

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import (
    MONGO_URI, MONGO_DB_NAME, COLLECTION_ALERTS, COLLECTION_EVENTS,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    ALERT_SEVERITY_THRESHOLD, ALERT_SPIKE_WINDOW_MINS, ALERT_SPIKE_COUNT,
)

logger = logging.getLogger(__name__)


# ── Additional settings (add these to settings.py / .env) ─────────────────────
SMTP_HOST        = os.getenv("SMTP_HOST",        "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT",    "587"))
SMTP_USER        = os.getenv("SMTP_USER",        "")   # your Gmail address
SMTP_PASS        = os.getenv("SMTP_PASS",        "")   # Gmail App Password
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO",   "")   # recipient email
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")   # optional: SendGrid

ALERT_COOLDOWN_MINUTES = int(os.getenv("ALERT_COOLDOWN_MINUTES", "30"))  # min gap between same alert type


# ── Alert Types ────────────────────────────────────────────────────────────────

class AlertType(str, Enum):
    SEVERITY_SPIKE    = "severity_spike"      # single event with very high severity
    VOLUME_SPIKE      = "volume_spike"        # too many events in short window
    CRITICAL_CVE      = "critical_cve"        # new CVE with CVSS >= 9.0
    RANSOMWARE        = "ransomware_detected" # any ransomware event
    NEW_COUNTRY       = "new_country"         # attack from previously unseen country
    ANOMALY_DETECTED  = "anomaly_detected"    # ML flagged an anomaly hour


# ── Alert Record (stored in MongoDB) ──────────────────────────────────────────

def _create_alert_record(
    alert_type:  AlertType,
    title:       str,
    message:     str,
    severity:    str   = "High",
    event_count: int   = 1,
    metadata:    dict  = None,
) -> dict:
    return {
        "alert_type":  alert_type.value,
        "title":       title,
        "message":     message,
        "severity":    severity,
        "event_count": event_count,
        "metadata":    metadata or {},
        "created_at":  datetime.now(timezone.utc).isoformat(),
        "resolved":    False,
        "notified":    False,
    }


def _store_alert(alert: dict) -> str:
    """Store alert in MongoDB and return its ID."""
    try:
        db     = MongoClient(MONGO_URI)[MONGO_DB_NAME]
        result = db[COLLECTION_ALERTS].insert_one(alert)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Failed to store alert: {e}")
        return ""


def _is_in_cooldown(alert_type: AlertType) -> bool:
    """
    Check if we already fired this alert type recently.
    Prevents alert flooding — same type won't fire more than once per cooldown window.
    """
    try:
        db       = MongoClient(MONGO_URI)[MONGO_DB_NAME]
        cutoff   = (datetime.now(timezone.utc) - timedelta(minutes=ALERT_COOLDOWN_MINUTES)).isoformat()
        existing = db[COLLECTION_ALERTS].find_one({
            "alert_type": alert_type.value,
            "created_at": {"$gte": cutoff},
        })
        return existing is not None
    except Exception:
        return False


# ── Telegram Sender ────────────────────────────────────────────────────────────

def send_telegram(title: str, message: str, severity: str = "High") -> bool:
    """
    Send a Telegram message via Bot API (completely free).

    Setup:
      1. Message @BotFather on Telegram → /newbot → get TOKEN
      2. Start a chat with your bot, then visit:
         https://api.telegram.org/bot<TOKEN>/getUpdates
         to find your chat_id
      3. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.debug("Telegram not configured — skipping")
        return False

    # Severity emoji
    emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")

    text = (
        f"{emoji} *CYBER THREAT ALERT*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"*{title}*\n\n"
        f"{message}\n\n"
        f"_Severity: {severity}_\n"
        f"_Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"Cyber Threat Dashboard"
    )

    url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Telegram alert sent: {title}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Telegram send failed: {e}")
        return False


# ── Email Sender ───────────────────────────────────────────────────────────────

def send_email(title: str, message: str, severity: str = "High") -> bool:
    """
    Send an HTML email alert.
    Supports two methods:
      A) Gmail SMTP (set SMTP_USER + SMTP_PASS as Gmail App Password)
      B) SendGrid API (set SENDGRID_API_KEY — 100 emails/day free)
    """
    if not ALERT_EMAIL_TO:
        logger.debug("ALERT_EMAIL_TO not set — skipping email")
        return False

    # ── Method A: SendGrid (preferred — more reliable) ─────────────────────
    if SENDGRID_API_KEY:
        return _send_via_sendgrid(title, message, severity)

    # ── Method B: Gmail SMTP ────────────────────────────────────────────────
    if SMTP_USER and SMTP_PASS:
        return _send_via_smtp(title, message, severity)

    logger.debug("No email provider configured (set SENDGRID_API_KEY or SMTP_USER+SMTP_PASS)")
    return False


def _build_email_html(title: str, message: str, severity: str) -> str:
    """Build a clean HTML email body."""
    color_map = {
        "Critical": "#ff3355",
        "High":     "#ff6b35",
        "Medium":   "#ffd700",
        "Low":      "#00ff88",
    }
    color = color_map.get(severity, "#00d4ff")
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#050a0f;color:#c8e6f5;padding:20px;">
      <div style="max-width:600px;margin:0 auto;background:#0a1520;border-radius:8px;
                  border-left:4px solid {color};padding:24px;">
        <div style="font-size:11px;color:#527a99;letter-spacing:3px;
                    text-transform:uppercase;margin-bottom:8px;">
          CYBER THREAT DASHBOARD — ALERT
        </div>
        <h2 style="color:{color};margin:0 0 16px;">{title}</h2>
        <p style="color:#c8e6f5;line-height:1.6;white-space:pre-line;">{message}</p>
        <hr style="border:none;border-top:1px solid #0f3a5c;margin:16px 0;">
        <div style="display:flex;justify-content:space-between;">
          <span style="color:#527a99;font-size:12px;">Severity: 
            <strong style="color:{color};">{severity}</strong>
          </span>
          <span style="color:#527a99;font-size:12px;">{ts}</span>
        </div>
      </div>
    </body></html>
    """


def _send_via_sendgrid(title: str, message: str, severity: str) -> bool:
    """Send email via SendGrid HTTP API (free tier: 100/day)."""
    html_body = _build_email_html(title, message, severity)
    payload   = {
        "personalizations": [{"to": [{"email": ALERT_EMAIL_TO}]}],
        "from":    {"email": SMTP_USER or "alerts@cyberthreat.dashboard"},
        "subject": f"[{severity}] Cyber Threat Alert: {title}",
        "content": [
            {"type": "text/plain", "value": f"{title}\n\n{message}"},
            {"type": "text/html",  "value": html_body},
        ],
    }
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type":  "application/json",
    }
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json    = payload,
            headers = headers,
            timeout = 10,
        )
        resp.raise_for_status()
        logger.info(f"SendGrid alert sent: {title}")
        return True
    except Exception as e:
        logger.error(f"SendGrid failed: {e}")
        return False


def _send_via_smtp(title: str, message: str, severity: str) -> bool:
    """Send email via Gmail SMTP."""
    html_body = _build_email_html(title, message, severity)
    msg       = MIMEMultipart("alternative")
    msg["Subject"] = f"[{severity}] Cyber Threat Alert: {title}"
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_EMAIL_TO
    msg.attach(MIMEText(f"{title}\n\n{message}", "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        logger.info(f"Email alert sent via SMTP: {title}")
        return True
    except Exception as e:
        logger.error(f"SMTP send failed: {e}")
        return False


# ── Notification Dispatcher ────────────────────────────────────────────────────

def _dispatch(alert: dict) -> bool:
    """Send alert via all configured channels."""
    title    = alert["title"]
    message  = alert["message"]
    severity = alert["severity"]

    telegram_ok = send_telegram(title, message, severity)
    email_ok    = send_email(title, message, severity)

    if telegram_ok or email_ok:
        # Mark as notified in MongoDB
        try:
            db = MongoClient(MONGO_URI)[MONGO_DB_NAME]
            db[COLLECTION_ALERTS].update_many(
                {"title": title, "notified": False},
                {"$set": {"notified": True}},
            )
        except Exception:
            pass

    return telegram_ok or email_ok


# ══════════════════════════════════════════════════════════════════════════════
# ALERT CHECKS — called after each ingestion run
# ══════════════════════════════════════════════════════════════════════════════

def check_severity_spike(new_events: List[dict]) -> Optional[dict]:
    """
    Alert if any single new event has severity_score above threshold.
    Threshold set by ALERT_SEVERITY_THRESHOLD in settings (default 7.5).
    """
    critical_events = [
        e for e in new_events
        if float(e.get("severity_score", 0)) >= ALERT_SEVERITY_THRESHOLD
    ]
    if not critical_events:
        return None

    if _is_in_cooldown(AlertType.SEVERITY_SPIKE):
        logger.debug("Severity spike alert in cooldown — skipping")
        return None

    worst  = max(critical_events, key=lambda e: e.get("severity_score", 0))
    score  = worst.get("severity_score", 0)
    atype  = worst.get("attack_type", "Unknown")
    geo    = worst.get("source_geo") or {}
    country= geo.get("country", "Unknown") if isinstance(geo, dict) else "Unknown"

    title   = f"High Severity {atype} Detected"
    message = (
        f"{len(critical_events)} critical event(s) detected in the latest ingestion run.\n\n"
        f"Worst event:\n"
        f"  • Attack Type: {atype}\n"
        f"  • Severity Score: {score:.1f}/10\n"
        f"  • Source Country: {country}\n"
        f"  • Description: {(worst.get('description') or '')[:120]}\n\n"
        f"Total events above threshold {ALERT_SEVERITY_THRESHOLD}: {len(critical_events)}"
    )
    severity = "Critical" if score >= 9.0 else "High"

    alert = _create_alert_record(
        AlertType.SEVERITY_SPIKE, title, message, severity,
        len(critical_events),
        {"worst_score": score, "attack_type": atype, "country": country},
    )
    _store_alert(alert)
    _dispatch(alert)
    return alert


def check_volume_spike(new_events: List[dict]) -> Optional[dict]:
    """
    Alert if volume of new events in this ingestion run exceeds ALERT_SPIKE_COUNT.
    Indicates a large-scale attack wave.
    """
    count = len(new_events)
    if count < ALERT_SPIKE_COUNT:
        return None

    if _is_in_cooldown(AlertType.VOLUME_SPIKE):
        return None

    # Count by attack type
    from collections import Counter
    type_counts = Counter(e.get("attack_type", "Unknown") for e in new_events)
    top_type, top_count = type_counts.most_common(1)[0]

    title   = f"Attack Volume Spike: {count} Events"
    message = (
        f"Unusual spike in attack volume detected.\n\n"
        f"  • Total new events: {count} (threshold: {ALERT_SPIKE_COUNT})\n"
        f"  • Dominant attack type: {top_type} ({top_count} events)\n\n"
        f"Top attack types this wave:\n"
        + "\n".join(f"  • {t}: {c}" for t, c in type_counts.most_common(5))
    )

    alert = _create_alert_record(
        AlertType.VOLUME_SPIKE, title, message, "High", count,
        {"top_type": top_type, "type_breakdown": dict(type_counts.most_common(5))},
    )
    _store_alert(alert)
    _dispatch(alert)
    return alert


def check_ransomware(new_events: List[dict]) -> Optional[dict]:
    """
    Ransomware events always trigger an immediate alert — no cooldown check.
    These are high-priority regardless of volume.
    """
    ransomware_events = [
        e for e in new_events
        if e.get("attack_type") == "Ransomware"
    ]
    if not ransomware_events:
        return None

    # Ransomware gets a shorter cooldown (10 min) applied separately
    try:
        db     = MongoClient(MONGO_URI)[MONGO_DB_NAME]
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        if db[COLLECTION_ALERTS].find_one({
            "alert_type": AlertType.RANSOMWARE.value,
            "created_at": {"$gte": cutoff},
        }):
            return None
    except Exception:
        pass

    geo     = ransomware_events[0].get("source_geo") or {}
    country = geo.get("country", "Unknown") if isinstance(geo, dict) else "Unknown"

    title   = f"🚨 Ransomware Activity Detected ({len(ransomware_events)} events)"
    message = (
        f"RANSOMWARE INDICATORS DETECTED — Immediate attention required.\n\n"
        f"  • Events detected: {len(ransomware_events)}\n"
        f"  • Primary source country: {country}\n"
        f"  • Description: {(ransomware_events[0].get('description') or '')[:150]}\n\n"
        f"Recommended actions:\n"
        f"  1. Verify endpoint protection is active\n"
        f"  2. Check for unusual file encryption activity\n"
        f"  3. Isolate affected systems if confirmed\n"
        f"  4. Review backup integrity"
    )

    alert = _create_alert_record(
        AlertType.RANSOMWARE, title, message, "Critical",
        len(ransomware_events), {"source_country": country},
    )
    _store_alert(alert)
    _dispatch(alert)
    return alert


def check_critical_cves(new_cves: List[dict]) -> Optional[dict]:
    """
    Alert when new CVEs with CVSS >= 9.0 are ingested.
    """
    critical_cves = [
        c for c in new_cves
        if float(c.get("cvss_score") or 0) >= 9.0
    ]
    if not critical_cves:
        return None

    if _is_in_cooldown(AlertType.CRITICAL_CVE):
        return None

    cve_list = "\n".join(
        f"  • {c['cve_id']} (CVSS {c.get('cvss_score', '?')}) — "
        f"{c.get('affected_vendor', '?')}/{c.get('affected_product', '?')}"
        for c in critical_cves[:5]
    )

    title   = f"{len(critical_cves)} Critical CVE(s) Published"
    message = (
        f"New critical vulnerabilities detected in NVD feed.\n\n"
        f"{cve_list}\n\n"
        f"Recommended actions:\n"
        f"  1. Review affected systems in your environment\n"
        f"  2. Apply patches if available\n"
        f"  3. Implement compensating controls if no patch exists"
    )

    alert = _create_alert_record(
        AlertType.CRITICAL_CVE, title, message, "Critical",
        len(critical_cves),
        {"cve_ids": [c["cve_id"] for c in critical_cves[:10]]},
    )
    _store_alert(alert)
    _dispatch(alert)
    return alert


def check_anomaly_alert(anomaly_hours: List[str]) -> Optional[dict]:
    """
    Alert when ML service flags anomalous hours.
    Called after anomaly detection runs on the dashboard.
    """
    if not anomaly_hours:
        return None

    if _is_in_cooldown(AlertType.ANOMALY_DETECTED):
        return None

    title   = f"ML Anomaly Detected: {len(anomaly_hours)} Unusual Hour(s)"
    message = (
        f"The anomaly detection model flagged unusual attack patterns.\n\n"
        f"  • Anomalous hours: {', '.join(anomaly_hours[:5])}\n"
        f"  • This indicates attack volume significantly above normal baseline.\n\n"
        f"Review the time-series chart in the dashboard for details."
    )

    alert = _create_alert_record(
        AlertType.ANOMALY_DETECTED, title, message, "High",
        len(anomaly_hours), {"anomaly_hours": anomaly_hours},
    )
    _store_alert(alert)
    _dispatch(alert)
    return alert


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT — called by fetch_all.py after each ingestion run
# ══════════════════════════════════════════════════════════════════════════════

def run_alert_checks(
    new_events: List[dict] = None,
    new_cves:   List[dict] = None,
    anomaly_hours: List[str] = None,
) -> dict:
    """
    Run all alert checks after an ingestion run.
    Pass in the newly ingested events/CVEs so we don't re-query the DB.

    Called from fetch_all.py like:
        from alert_engine import run_alert_checks
        run_alert_checks(new_events=events, new_cves=cves)
    """
    results = {
        "severity_spike":   None,
        "volume_spike":     None,
        "ransomware":       None,
        "critical_cves":    None,
        "anomaly":          None,
        "alerts_fired":     0,
    }

    events = new_events or []
    cves   = new_cves   or []

    logger.info(f"Running alert checks on {len(events)} events, {len(cves)} CVEs")

    checks = [
        ("severity_spike",  lambda: check_severity_spike(events)),
        ("volume_spike",    lambda: check_volume_spike(events)),
        ("ransomware",      lambda: check_ransomware(events)),
        ("critical_cves",   lambda: check_critical_cves(cves)),
        ("anomaly",         lambda: check_anomaly_alert(anomaly_hours or [])),
    ]

    for key, check_fn in checks:
        try:
            result = check_fn()
            results[key] = result
            if result:
                results["alerts_fired"] += 1
                logger.info(f"Alert fired: {key} — {result['title']}")
        except Exception as e:
            logger.error(f"Alert check '{key}' failed: {e}")

    logger.info(f"Alert checks complete — {results['alerts_fired']} alert(s) fired")
    return results


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # Test with a fake critical event
    test_events = [{
        "attack_type":    "Ransomware",
        "severity_score": 9.5,
        "description":    "Test ransomware event for alert engine verification",
        "source_geo":     {"country": "Russia", "country_code": "RU"},
    }]

    print("Testing alert engine...")
    print("(Check your Telegram/email for notifications)")
    result = run_alert_checks(new_events=test_events)
    print(f"\nResult: {result}")
