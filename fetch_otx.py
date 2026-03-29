"""
fetch_otx.py — Module 1: AlienVault OTX Threat Feed Ingestion
Fetches threat pulses (indicators of compromise) from OTX free API.
Normalizes into ThreatEvent objects and stores in MongoDB.
"""

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import requests

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import OTX_API_KEY, OTX_BASE_URL, OTX_PULSE_LIMIT
from config.schema import (
    ThreatEvent, GeoLocation, MitreMapping,
    AttackType, SeverityLevel, DataSource
)
from config.database import upsert_threat_events

logger = logging.getLogger(__name__)


# ── OTX Indicator type → AttackType mapping ────────────────────────────────────

OTX_TYPE_MAP = {
    "IPv4":         AttackType.SCAN,
    "IPv6":         AttackType.SCAN,
    "domain":       AttackType.PHISHING,
    "hostname":     AttackType.PHISHING,
    "URL":          AttackType.PHISHING,
    "URI":          AttackType.PHISHING,
    "FileHash-MD5": AttackType.MALWARE,
    "FileHash-SHA1":AttackType.MALWARE,
    "FileHash-SHA256":AttackType.MALWARE,
    "email":        AttackType.PHISHING,
    "CVE":          AttackType.EXPLOIT,
    "CIDR":         AttackType.SCAN,
}

# OTX tag keywords → AttackType override
TAG_TO_ATTACK = {
    "ransomware":    AttackType.RANSOMWARE,
    "ddos":          AttackType.DDOS,
    "phishing":      AttackType.PHISHING,
    "malware":       AttackType.MALWARE,
    "botnet":        AttackType.BOTNET,
    "brute":         AttackType.BRUTE_FORCE,
    "breach":        AttackType.DATA_BREACH,
    "data leak":     AttackType.DATA_BREACH,
    "exploit":       AttackType.EXPLOIT,
    "scan":          AttackType.SCAN,
}

# OTX adversary/tag → MITRE tactic hint
TAG_TO_MITRE = {
    "phishing":      ("Initial Access",     "T1566", "Phishing"),
    "ransomware":    ("Impact",             "T1486", "Data Encrypted for Impact"),
    "ddos":          ("Impact",             "T1499", "Endpoint Denial of Service"),
    "botnet":        ("Command and Control","T1071", "Application Layer Protocol"),
    "brute":         ("Credential Access",  "T1110", "Brute Force"),
    "exploit":       ("Execution",          "T1203", "Exploitation for Client Execution"),
    "scan":          ("Discovery",          "T1046", "Network Service Discovery"),
    "c2":            ("Command and Control","T1071", "Application Layer Protocol"),
    "c&c":           ("Command and Control","T1071", "Application Layer Protocol"),
    "lateral":       ("Lateral Movement",   "T1021", "Remote Services"),
    "exfil":         ("Exfiltration",       "T1041", "Exfiltration Over C2 Channel"),
}


def _score_from_pulse(pulse: dict) -> Tuple[float, float]:
    """
    Heuristically derive a severity_score (0–10) and confidence (0–100)
    from OTX pulse metadata.
    """
    score = 3.0   # baseline
    conf  = 60.0

    # More indicators → higher confidence
    indicator_count = pulse.get("indicator_count", 0)
    if indicator_count > 100:  conf  = min(conf + 20, 95)
    elif indicator_count > 20: conf  = min(conf + 10, 90)

    # Subscriber count = community validation
    subscriber_count = pulse.get("subscriber_count", 0)
    if subscriber_count > 1000: score += 2.0; conf = min(conf + 15, 95)
    elif subscriber_count > 100: score += 1.0; conf = min(conf + 10, 90)

    # Tags give content signals
    tags = [t.lower() for t in pulse.get("tags", [])]
    if any(t in tags for t in ["ransomware", "apt", "nation-state"]): score += 3.0
    if any(t in tags for t in ["malware", "exploit", "ddos"]):        score += 2.0
    if any(t in tags for t in ["phishing", "scan", "botnet"]):        score += 1.0

    return round(min(score, 10.0), 1), round(conf, 1)


def _severity_from_score(score: float) -> SeverityLevel:
    if score >= 8.0: return SeverityLevel.CRITICAL
    if score >= 6.0: return SeverityLevel.HIGH
    if score >= 4.0: return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _attack_type_from_pulse(pulse: dict) -> AttackType:
    """Determine attack type from tags and adversary fields."""
    tags = [t.lower() for t in pulse.get("tags", [])]
    name = pulse.get("name", "").lower()
    adversary = pulse.get("adversary", "").lower()

    combined = " ".join(tags + [name, adversary])
    for keyword, atype in TAG_TO_ATTACK.items():
        if keyword in combined:
            return atype

    # Fallback: use indicator types in the pulse
    indicators = pulse.get("indicators", [])
    if indicators:
        first_type = indicators[0].get("type", "")
        return OTX_TYPE_MAP.get(first_type, AttackType.UNKNOWN)

    return AttackType.UNKNOWN


def _mitre_from_pulse(pulse: dict) -> Optional[MitreMapping]:
    """Extract MITRE ATT&CK mapping from pulse tags."""
    tags = [t.lower() for t in pulse.get("tags", [])]
    for tag, (tactic, tid, technique) in TAG_TO_MITRE.items():
        if tag in tags:
            return MitreMapping(tactic=tactic, technique_id=tid, technique=technique)
    return None


def _parse_pulse_to_events(pulse: dict) -> List[ThreatEvent]:
    """
    One OTX pulse can have many indicators.
    We create one ThreatEvent per indicator (up to 50 per pulse to avoid flooding).
    """
    events: List[ThreatEvent] = []

    severity_score, confidence = _score_from_pulse(pulse)
    severity    = _severity_from_score(severity_score)
    attack_type = _attack_type_from_pulse(pulse)
    mitre       = _mitre_from_pulse(pulse)
    tags        = pulse.get("tags", [])[:10]

    # Parse pulse creation time
    created_str = pulse.get("created", "")
    try:
        timestamp = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
    except Exception:
        timestamp = datetime.now(timezone.utc)

    indicators = pulse.get("indicators", [])[:50]   # cap per pulse

    for ind in indicators:
        indicator_val = ind.get("indicator", "")
        ind_type      = ind.get("type", "")
        country_code  = ind.get("country_code", "")
        country_name  = ind.get("country_name", "")
        city          = ind.get("city", "")
        lat           = ind.get("latitude")
        lon           = ind.get("longitude")
        asn           = ind.get("asn", "")

        # Build geo if available
        source_geo = None
        if country_code or lat:
            source_geo = GeoLocation(
                country=country_name or None,
                country_code=country_code or None,
                city=city or None,
                latitude=float(lat) if lat else None,
                longitude=float(lon) if lon else None,
                asn=asn or None,
            )

        # Extract source IP if indicator is an IP type
        source_ip = indicator_val if ind_type in ("IPv4", "IPv6") else None

        # Unique event ID = hash of pulse_id + indicator
        raw_id   = f"otx_{pulse.get('id', '')}_{indicator_val}"
        event_id = hashlib.md5(raw_id.encode()).hexdigest()

        event = ThreatEvent(
            event_id       = event_id,
            source         = DataSource.OTX,
            timestamp      = timestamp,
            attack_type    = attack_type,
            indicator      = indicator_val,
            description    = pulse.get("description") or pulse.get("name", "")[:300],
            source_ip      = source_ip,
            severity       = severity,
            severity_score = severity_score,
            confidence     = confidence,
            source_geo     = source_geo,
            mitre          = mitre,
            tags           = tags,
            raw            = {
                "pulse_id":    pulse.get("id"),
                "pulse_name":  pulse.get("name"),
                "ind_type":    ind_type,
                "adversary":   pulse.get("adversary"),
            }
        )
        events.append(event)

    return events


def fetch_otx_pulses(days_back: int = 2) -> List[ThreatEvent]:
    """
    Fetch recent threat pulses from AlienVault OTX subscribed feeds.
    Returns list of ThreatEvent objects.
    """
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX ingestion")
        return []

    modified_since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
    url     = f"{OTX_BASE_URL}/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params  = {
        "modified_since": modified_since,
        "limit": min(OTX_PULSE_LIMIT, 50),
        "page": 1,
    }

    all_events: List[ThreatEvent] = []
    pulses_processed = 0

    logger.info(f"Fetching OTX pulses modified since {modified_since}...")

    while True:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"OTX API error: {e}")
            break

        results = data.get("results", [])
        if not results:
            break

        for pulse in results:
            events = _parse_pulse_to_events(pulse)
            all_events.extend(events)
            pulses_processed += 1

        # Check for more pages
        next_page = data.get("next")
        if not next_page or pulses_processed >= OTX_PULSE_LIMIT:
            break

        params["page"] += 1
        time.sleep(1.0)

    logger.info(f"OTX: processed {pulses_processed} pulses → {len(all_events)} events")
    return all_events


def run_otx_ingestion() -> dict:
    """Full OTX ingestion pipeline."""
    logger.info("=== OTX Ingestion Started ===")
    events = fetch_otx_pulses()
    if not events:
        return {"events_stored": 0}
    result = upsert_threat_events(events)
    logger.info(f"=== OTX Ingestion Complete === {result}")
    return {"events_stored": result["inserted"]}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from config.database import ensure_indexes
    ensure_indexes()
    result = run_otx_ingestion()
    print(f"\n✅ Done: {result}")
