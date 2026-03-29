"""
settings.py — All configuration, API keys, and constants loaded from environment.
Uses python-dotenv so you can have a .env file locally and env vars in production (Render).
"""

import os
from dotenv import load_dotenv

load_dotenv()  # loads .env file if present (ignored in production)


# ── MongoDB ────────────────────────────────────────────────────────────────────
MONGO_URI        = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME    = os.getenv("MONGO_DB_NAME", "cyber_threats")
COLLECTION_EVENTS = "threat_events"
COLLECTION_CVES   = "cve_events"
COLLECTION_ALERTS = "alerts"


# ── Redis (Upstash free tier) ──────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# ── MongoDB TLS (local false, Atlas true) ──────────────────────────────────────
MONGO_TLS = os.getenv("MONGO_TLS", "false").lower() == "true"

# ── Threat Feed API Keys ───────────────────────────────────────────────────────
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")        # AlienVault OTX
ABUSEIPDB_KEY     = os.getenv("ABUSEIPDB_KEY", "")      # AbuseIPDB
VIRUSTOTAL_KEY    = os.getenv("VIRUSTOTAL_KEY", "")      # VirusTotal (optional)


# ── NVD (No API key required, but optional key removes rate limits) ─────────────
NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── AlienVault OTX ─────────────────────────────────────────────────────────────
OTX_BASE_URL      = "https://otx.alienvault.com/api/v1"

# ── AbuseIPDB ──────────────────────────────────────────────────────────────────
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# ── GeoIP (ip-api.com — free, no key needed) ────────────────────────────────────
GEOIP_BASE_URL    = "http://ip-api.com/json"


# ── Ingestion Settings ─────────────────────────────────────────────────────────
INGEST_INTERVAL_MINUTES = int(os.getenv("INGEST_INTERVAL_MINUTES", "15"))
NVD_FETCH_DAYS_BACK     = int(os.getenv("NVD_FETCH_DAYS_BACK", "2"))    # how many days of CVEs to pull
OTX_PULSE_LIMIT         = int(os.getenv("OTX_PULSE_LIMIT", "20"))       # max OTX pulses per run
ABUSEIPDB_CONFIDENCE_MIN= int(os.getenv("ABUSEIPDB_CONFIDENCE_MIN", "50"))  # min % confidence


# ── ML Service ─────────────────────────────────────────────────────────────────
ML_SERVICE_URL    = os.getenv("ML_SERVICE_URL", "http://localhost:8001")


# ── Backend ────────────────────────────────────────────────────────────────────
BACKEND_URL       = os.getenv("BACKEND_URL", "http://localhost:8000")
BACKEND_HOST      = os.getenv("BACKEND_HOST", "0.0.0.0")
BACKEND_PORT      = int(os.getenv("BACKEND_PORT", "8000"))


# ── Alert Thresholds ────────────────────────────────────────────────────────────
ALERT_SEVERITY_THRESHOLD  = float(os.getenv("ALERT_SEVERITY_THRESHOLD", "7.5"))
ALERT_SPIKE_WINDOW_MINS   = int(os.getenv("ALERT_SPIKE_WINDOW_MINS", "5"))
ALERT_SPIKE_COUNT         = int(os.getenv("ALERT_SPIKE_COUNT", "20"))


# ── Telegram Alerts (optional) ─────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")

# ── Email Alerts (optional) ────────────────────────────────────────────────────
SMTP_HOST        = os.getenv("SMTP_HOST",        "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT",    "587"))
SMTP_USER        = os.getenv("SMTP_USER",        "")   # your Gmail address
SMTP_PASS        = os.getenv("SMTP_PASS",        "")   # Gmail App Password (not regular password)
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO",   "")   # recipient email
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")   # sendgrid.com free: 100/day
ALERT_COOLDOWN_MINUTES = int(os.getenv("ALERT_COOLDOWN_MINUTES", "30"))


# ── Dashboard ──────────────────────────────────────────────────────────────────
DASH_HOST         = os.getenv("DASH_HOST", "0.0.0.0")
DASH_PORT         = int(os.getenv("PORT", os.getenv("DASH_PORT", "8050")))
DASH_DEBUG        = os.getenv("DASH_DEBUG", "false").lower() == "true"
REFRESH_INTERVAL_MS = int(os.getenv("REFRESH_INTERVAL_MS", "30000"))  # 30 seconds
