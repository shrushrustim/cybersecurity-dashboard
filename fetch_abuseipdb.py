"""
fetch_abuseipdb.py — Module 1: AbuseIPDB Malicious IP Feed + GeoIP Enrichment
Fetches top reported malicious IPs, enriches with geo data, stores as ThreatEvents.
Also contains the GeoEnricher class used by all other ingestors.
"""

import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict

import requests

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import ABUSEIPDB_KEY, ABUSEIPDB_BASE_URL, GEOIP_BASE_URL, ABUSEIPDB_CONFIDENCE_MIN
from config.schema import (
    ThreatEvent, GeoLocation, MitreMapping,
    AttackType, SeverityLevel, DataSource
)
from config.database import upsert_threat_events

logger = logging.getLogger(__name__)


# ── GeoIP Enrichment (ip-api.com — completely free, no key) ────────────────────

class GeoEnricher:
    """
    Enriches IP addresses with geolocation data using ip-api.com (free).
    Rate limit: 45 requests/minute on free tier. We batch with small delays.
    """

    BASE_URL  = "http://ip-api.com/batch"   # batch endpoint — up to 100 IPs per call
    CACHE: Dict[str, Optional[GeoLocation]] = {}   # in-memory cache for this run

    @classmethod
    def enrich_batch(cls, ips: List[str]) -> Dict[str, Optional[GeoLocation]]:
        """
        Look up geo data for a batch of IPs.
        Returns dict: {ip: GeoLocation or None}
        """
        # Filter out already-cached and private IPs
        private_prefixes = ("10.", "192.168.", "172.", "127.", "::1", "0.0.0.0")
        to_lookup = [
            ip for ip in ips
            if ip not in cls.CACHE
            and not any(ip.startswith(p) for p in private_prefixes)
        ]

        # Process in batches of 100 (ip-api limit)
        for i in range(0, len(to_lookup), 100):
            batch = to_lookup[i:i + 100]
            payload = [{"query": ip, "fields": "status,country,countryCode,city,lat,lon,org,query"} for ip in batch]
            try:
                resp = requests.post(cls.BASE_URL, json=payload, timeout=10)
                resp.raise_for_status()
                results = resp.json()
                for item in results:
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        cls.CACHE[ip] = GeoLocation(
                            country      = item.get("country"),
                            country_code = item.get("countryCode"),
                            city         = item.get("city"),
                            latitude     = item.get("lat"),
                            longitude    = item.get("lon"),
                            asn          = item.get("org"),
                        )
                    else:
                        cls.CACHE[ip] = None

                # Stay within free rate limit (45 req/min = ~1.3s/req)
                if i + 100 < len(to_lookup):
                    time.sleep(1.5)

            except Exception as e:
                logger.warning(f"GeoIP batch lookup failed: {e}")
                for ip in batch:
                    cls.CACHE[ip] = None

        # Return results for all requested IPs
        return {ip: cls.CACHE.get(ip) for ip in ips}

    @classmethod
    def enrich_single(cls, ip: str) -> Optional[GeoLocation]:
        """Enrich a single IP address."""
        result = cls.enrich_batch([ip])
        return result.get(ip)

    @classmethod
    def enrich_events(cls, events: List[ThreatEvent]) -> List[ThreatEvent]:
        """
        Enrich a list of ThreatEvents with geo data for source IPs
        that don't already have geo information.
        """
        # Collect IPs that need geo lookup
        ips_to_lookup = [
            e.source_ip
            for e in events
            if e.source_ip and not e.source_geo
        ]

        if not ips_to_lookup:
            return events

        geo_map = cls.enrich_batch(ips_to_lookup)

        # Apply geo data to events
        for event in events:
            if event.source_ip and not event.source_geo:
                event.source_geo = geo_map.get(event.source_ip)

        logger.info(f"GeoIP enriched {len(ips_to_lookup)} IPs")
        return events


# ── AbuseIPDB Category → AttackType mapping ────────────────────────────────────

# https://www.abuseipdb.com/categories
ABUSE_CATEGORY_MAP = {
    1:  AttackType.SCAN,          # DNS Compromise
    2:  AttackType.SCAN,          # DNS Poisoning
    3:  AttackType.EXPLOIT,       # Fraud Orders
    4:  AttackType.DDOS,          # DDoS Attack
    5:  AttackType.SCAN,          # FTP Brute-Force
    6:  AttackType.BRUTE_FORCE,   # Ping of Death
    7:  AttackType.MALWARE,       # Phishing
    8:  AttackType.SCAN,          # Fraud VoIP
    9:  AttackType.SCAN,          # Open Proxy
    10: AttackType.DATA_BREACH,   # Web Spam
    11: AttackType.PHISHING,      # Email Spam
    12: AttackType.EXPLOIT,       # Blog Spam
    13: AttackType.BRUTE_FORCE,   # VPN IP
    14: AttackType.SCAN,          # Port Scan
    15: AttackType.SCAN,          # Hacking
    16: AttackType.MALWARE,       # SQL Injection
    17: AttackType.BRUTE_FORCE,   # Spoofing
    18: AttackType.BRUTE_FORCE,   # Brute-Force
    19: AttackType.DDOS,          # Bad Web Bot
    20: AttackType.EXPLOIT,       # Exploited Host
    21: AttackType.DATA_BREACH,   # Web App Attack
    22: AttackType.SCAN,          # SSH
    23: AttackType.BRUTE_FORCE,   # IoT Targeted
}

ABUSE_CATEGORY_TO_MITRE = {
    14: ("Discovery",          "T1046", "Network Service Discovery"),   # Port Scan
    18: ("Credential Access",  "T1110", "Brute Force"),                 # Brute Force
    22: ("Credential Access",  "T1110", "Brute Force"),                 # SSH
    4:  ("Impact",             "T1499", "Endpoint Denial of Service"),  # DDoS
    21: ("Initial Access",     "T1190", "Exploit Public-Facing App"),   # Web App Attack
    16: ("Initial Access",     "T1190", "Exploit Public-Facing App"),   # SQL Injection
    7:  ("Initial Access",     "T1566", "Phishing"),                    # Phishing
    11: ("Initial Access",     "T1566", "Phishing"),                    # Email Spam
}


def _abuse_categories_to_attack_type(categories: List[int]) -> AttackType:
    """Return the most severe attack type from a list of AbuseIPDB categories."""
    priority_order = [
        AttackType.RANSOMWARE, AttackType.DDOS, AttackType.DATA_BREACH,
        AttackType.MALWARE, AttackType.EXPLOIT, AttackType.PHISHING,
        AttackType.BRUTE_FORCE, AttackType.BOTNET, AttackType.SCAN,
    ]
    found_types = {ABUSE_CATEGORY_MAP.get(c) for c in categories if c in ABUSE_CATEGORY_MAP}
    for atype in priority_order:
        if atype in found_types:
            return atype
    return AttackType.SCAN


def _abuse_categories_to_mitre(categories: List[int]) -> Optional[MitreMapping]:
    """Return first matching MITRE mapping from categories."""
    for cat in categories:
        if cat in ABUSE_CATEGORY_TO_MITRE:
            tactic, tid, technique = ABUSE_CATEGORY_TO_MITRE[cat]
            return MitreMapping(tactic=tactic, technique_id=tid, technique=technique)
    return None


def _confidence_to_severity(confidence: int) -> tuple:
    """Map AbuseIPDB confidence score to severity_score and SeverityLevel."""
    if confidence >= 90: return (9.0, SeverityLevel.CRITICAL)
    if confidence >= 70: return (7.5, SeverityLevel.HIGH)
    if confidence >= 50: return (5.0, SeverityLevel.MEDIUM)
    return (3.0, SeverityLevel.LOW)


def _parse_abuseipdb_report(report: dict) -> Optional[ThreatEvent]:
    """Parse a single AbuseIPDB blacklist entry into a ThreatEvent."""
    try:
        ip          = report.get("ipAddress", "")
        confidence  = int(report.get("abuseConfidenceScore", 0))
        total_reps  = int(report.get("totalReports", 0))
        last_seen   = report.get("lastReportedAt", "")
        categories  = report.get("mostRecentReport", {}).get("categories", []) if isinstance(report.get("mostRecentReport"), dict) else []
        country_code= report.get("countryCode", "")
        domain      = report.get("domain", "")
        isp         = report.get("isp", "")
        usage_type  = report.get("usageType", "")

        if not ip or confidence < ABUSEIPDB_CONFIDENCE_MIN:
            return None

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00")) if last_seen else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        severity_score, severity = _confidence_to_severity(confidence)
        attack_type = _abuse_categories_to_attack_type(categories)
        mitre       = _abuse_categories_to_mitre(categories)

        # Build basic geo from what AbuseIPDB gives us (no lat/lon — GeoEnricher adds that)
        source_geo = GeoLocation(
            country_code = country_code or None,
            asn          = isp or None,
        ) if country_code else None

        event_id = hashlib.md5(f"abuse_{ip}".encode()).hexdigest()

        return ThreatEvent(
            event_id       = event_id,
            source         = DataSource.ABUSEIPDB,
            timestamp      = ts,
            attack_type    = attack_type,
            indicator      = ip,
            source_ip      = ip,
            description    = f"Malicious IP reported {total_reps}x. ISP: {isp}. Usage: {usage_type}",
            severity       = severity,
            severity_score = severity_score,
            confidence     = float(confidence),
            source_geo     = source_geo,
            mitre          = mitre,
            tags           = [f"reports:{total_reps}", usage_type, domain][:5],
            raw            = report,
        )

    except Exception as e:
        logger.warning(f"Failed to parse AbuseIPDB entry: {e}")
        return None


def fetch_abuseipdb_blacklist(limit: int = 500) -> List[ThreatEvent]:
    """
    Fetch the AbuseIPDB blacklist (top reported IPs).
    Free tier allows checking, but blacklist endpoint needs a registered key.
    Falls back to checking a set of known-bad IP ranges if key is missing.
    """
    if not ABUSEIPDB_KEY:
        logger.warning("ABUSEIPDB_KEY not set — skipping AbuseIPDB ingestion")
        return []

    url     = f"{ABUSEIPDB_BASE_URL}/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {
        "confidenceMinimum": ABUSEIPDB_CONFIDENCE_MIN,
        "limit": min(limit, 10000),
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB API error: {e}")
        return []

    reports = data.get("data", [])
    logger.info(f"AbuseIPDB: fetched {len(reports)} blacklisted IPs")

    events: List[ThreatEvent] = []
    for report in reports:
        event = _parse_abuseipdb_report(report)
        if event:
            events.append(event)

    # Enrich with full geo data (lat/lon from ip-api.com)
    events = GeoEnricher.enrich_events(events)

    logger.info(f"AbuseIPDB: {len(events)} events after filtering/enrichment")
    return events


def run_abuseipdb_ingestion() -> dict:
    """Full AbuseIPDB ingestion pipeline."""
    logger.info("=== AbuseIPDB Ingestion Started ===")
    events = fetch_abuseipdb_blacklist()
    if not events:
        return {"events_stored": 0}
    result = upsert_threat_events(events)
    logger.info(f"=== AbuseIPDB Ingestion Complete === {result}")
    return {"events_stored": result["inserted"]}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from config.database import ensure_indexes
    ensure_indexes()
    result = run_abuseipdb_ingestion()
    print(f"\n✅ Done: {result}")
