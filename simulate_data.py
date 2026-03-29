"""
simulate_data.py — Realistic simulated threat data generator.
Used when real API keys aren't set up yet, or for testing/demos.
Generates statistically realistic attack patterns with proper geo distribution.
"""

import hashlib
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import List

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.schema import (
    ThreatEvent, GeoLocation, MitreMapping,
    AttackType, SeverityLevel, DataSource
)
from config.database import upsert_threat_events

logger = logging.getLogger(__name__)

random.seed()   # fresh seed every run for realistic variation


# ── Realistic geo distribution (based on real threat landscape) ─────────────────

GEO_DISTRIBUTION = [
    # (country, code, lat, lon, weight)  — higher weight = more attacks from here
    ("China",         "CN",  35.86,  104.19, 20),
    ("Russia",        "RU",  61.52,   105.3, 18),
    ("United States", "US",  37.09,  -95.71, 12),
    ("Brazil",        "BR", -14.23,  -51.93,  8),
    ("India",         "IN",  20.59,   78.96,  7),
    ("Germany",       "DE",  51.16,   10.45,  5),
    ("Netherlands",   "NL",  52.13,    5.29,  5),
    ("Ukraine",       "UA",  48.38,   31.17,  6),
    ("North Korea",   "KP",  40.34,  127.51,  4),
    ("Iran",          "IR",  32.43,   53.69,  4),
    ("Romania",       "RO",  45.94,   24.97,  3),
    ("Vietnam",       "VN",  14.06,  108.28,  3),
    ("Nigeria",       "NG",   9.08,    8.68,  2),
    ("Pakistan",      "PK",  30.37,   69.35,  2),
    ("Turkey",        "TR",  38.96,   35.24,  2),
    ("France",        "FR",  46.23,    2.21,  2),
    ("United Kingdom","GB",  55.38,   -3.44,  2),
    ("Canada",        "CA",  56.13,  -106.3,  1),
    ("Australia",     "AU", -25.27,  133.77,  1),
    ("Japan",         "JP",  36.20,  138.25,  1),
]

# Build weighted country list
_GEO_POOL = []
for country, code, lat, lon, weight in GEO_DISTRIBUTION:
    _GEO_POOL.extend([(country, code, lat, lon)] * weight)


# ── Attack scenario definitions ─────────────────────────────────────────────────

ATTACK_SCENARIOS = [
    {
        "type":         AttackType.DDOS,
        "weight":       15,
        "severity_range": (5.0, 9.5),
        "confidence_range": (75, 95),
        "mitre":        MitreMapping(tactic="Impact", technique_id="T1499", technique="Endpoint Denial of Service"),
        "ports":        [80, 443, 53, 25],
        "protocols":    ["UDP", "TCP", "HTTP"],
        "tags":         ["ddos", "volumetric", "botnet-driven"],
        "descriptions": [
            "High-volume UDP flood detected targeting web infrastructure.",
            "Amplification attack using DNS reflection vectors.",
            "Layer 7 HTTP flood targeting login endpoints.",
            "SYN flood attack from distributed botnet nodes.",
        ]
    },
    {
        "type":         AttackType.PHISHING,
        "weight":       20,
        "severity_range": (3.0, 7.5),
        "confidence_range": (60, 90),
        "mitre":        MitreMapping(tactic="Initial Access", technique_id="T1566", technique="Phishing"),
        "ports":        [25, 465, 587, 443],
        "protocols":    ["SMTP", "HTTPS"],
        "tags":         ["phishing", "credential-harvest", "spear-phishing"],
        "descriptions": [
            "Phishing campaign mimicking bank login page detected.",
            "Spear phishing email targeting corporate credentials.",
            "Credential harvesting site impersonating Microsoft 365.",
            "Business Email Compromise campaign using lookalike domain.",
        ]
    },
    {
        "type":         AttackType.MALWARE,
        "weight":       18,
        "severity_range": (5.0, 9.0),
        "confidence_range": (70, 95),
        "mitre":        MitreMapping(tactic="Execution", technique_id="T1204", technique="User Execution"),
        "ports":        [443, 8080, 4444, 1337],
        "protocols":    ["HTTPS", "TCP"],
        "tags":         ["malware", "c2", "dropper"],
        "descriptions": [
            "Remote Access Trojan (RAT) C2 communication detected.",
            "Malicious PowerShell dropper observed in network traffic.",
            "Infostealer malware exfiltrating browser credentials.",
            "Loader malware delivering second-stage payload.",
        ]
    },
    {
        "type":         AttackType.RANSOMWARE,
        "weight":       8,
        "severity_range": (8.0, 10.0),
        "confidence_range": (80, 98),
        "mitre":        MitreMapping(tactic="Impact", technique_id="T1486", technique="Data Encrypted for Impact"),
        "ports":        [445, 3389, 22, 443],
        "protocols":    ["SMB", "RDP", "SSH"],
        "tags":         ["ransomware", "encryption", "critical-threat"],
        "descriptions": [
            "LockBit ransomware variant detected in enterprise environment.",
            "File encryption activity indicating active ransomware deployment.",
            "Ransomware lateral movement using SMB protocol observed.",
            "Double extortion ransomware exfiltrating data before encryption.",
        ]
    },
    {
        "type":         AttackType.SCAN,
        "weight":       25,
        "severity_range": (1.5, 5.0),
        "confidence_range": (50, 85),
        "mitre":        MitreMapping(tactic="Discovery", technique_id="T1046", technique="Network Service Discovery"),
        "ports":        [22, 23, 80, 443, 3389, 8080, 21, 25],
        "protocols":    ["TCP", "UDP"],
        "tags":         ["port-scan", "reconnaissance", "automated"],
        "descriptions": [
            "Automated port scan targeting common service ports.",
            "TCP SYN scan detecting open services across IP range.",
            "Vulnerability scanner probing for exposed RDP services.",
            "Shodan-style mass scan for SSH honeypot enumeration.",
        ]
    },
    {
        "type":         AttackType.BRUTE_FORCE,
        "weight":       15,
        "severity_range": (4.0, 7.5),
        "confidence_range": (65, 90),
        "mitre":        MitreMapping(tactic="Credential Access", technique_id="T1110", technique="Brute Force"),
        "ports":        [22, 3389, 21, 25, 5432, 3306],
        "protocols":    ["SSH", "RDP", "FTP", "TCP"],
        "tags":         ["brute-force", "credential-attack", "automated"],
        "descriptions": [
            "SSH brute force attack with 500+ failed login attempts.",
            "RDP credential stuffing using leaked password lists.",
            "MySQL database brute force from Tor exit node.",
            "FTP brute force targeting legacy servers.",
        ]
    },
    {
        "type":         AttackType.EXPLOIT,
        "weight":       10,
        "severity_range": (6.0, 9.5),
        "confidence_range": (70, 95),
        "mitre":        MitreMapping(tactic="Initial Access", technique_id="T1190", technique="Exploit Public-Facing Application"),
        "ports":        [80, 443, 8080, 8443],
        "protocols":    ["HTTP", "HTTPS"],
        "tags":         ["exploit", "cve", "web-attack"],
        "descriptions": [
            "CVE exploit attempt against Apache Log4Shell vulnerability.",
            "SQL injection attack targeting web application database.",
            "Remote code execution exploit targeting unpatched CMS.",
            "XXE injection exploit in API endpoint.",
        ]
    },
    {
        "type":         AttackType.BOTNET,
        "weight":       5,
        "severity_range": (4.0, 8.0),
        "confidence_range": (60, 85),
        "mitre":        MitreMapping(tactic="Command and Control", technique_id="T1071", technique="Application Layer Protocol"),
        "ports":        [443, 80, 6667, 8443],
        "protocols":    ["HTTPS", "IRC", "TCP"],
        "tags":         ["botnet", "c2", "mirai-variant"],
        "descriptions": [
            "Mirai-variant botnet C2 beaconing detected.",
            "IoT device enrolled in botnet for DDoS campaigns.",
            "Botnet node receiving updated target lists.",
            "Compromised host relaying botnet commands.",
        ]
    },
]

# Build weighted scenario pool
_SCENARIO_POOL = []
for s in ATTACK_SCENARIOS:
    _SCENARIO_POOL.extend([s] * s["weight"])


def _random_ip() -> str:
    """Generate a realistic-looking public IP address."""
    while True:
        o1 = random.randint(1, 254)
        o2 = random.randint(0, 255)
        o3 = random.randint(0, 255)
        o4 = random.randint(1, 254)
        # Skip private ranges
        if o1 in (10, 127, 169, 172, 192):
            continue
        return f"{o1}.{o2}.{o3}.{o4}"


def generate_simulated_events(
    count: int = 200,
    hours_back: int = 24,
    include_spike: bool = True,
) -> List[ThreatEvent]:
    """
    Generate a list of realistic simulated ThreatEvents.

    Args:
        count: Number of events to generate
        hours_back: Spread events over this many hours
        include_spike: Inject a realistic attack spike for anomaly detection testing
    """
    events: List[ThreatEvent] = []
    now = datetime.now(timezone.utc)

    # Base time distribution — more attacks during business hours (UTC)
    def random_timestamp() -> datetime:
        offset_hours = random.uniform(0, hours_back)
        ts = now - timedelta(hours=offset_hours)
        # Slightly more attacks during 8am-8pm UTC
        hour = ts.hour
        if 8 <= hour <= 20 and random.random() < 0.3:
            ts = ts.replace(hour=random.randint(8, 20))
        return ts

    # Inject attack spike (simulate anomaly) in last 2 hours
    spike_timestamps = []
    if include_spike:
        spike_count = random.randint(25, 45)
        spike_type  = random.choice([AttackType.DDOS, AttackType.SCAN, AttackType.BRUTE_FORCE])
        for _ in range(spike_count):
            spike_ts = now - timedelta(minutes=random.uniform(10, 90))
            spike_timestamps.append((spike_ts, spike_type))

    for i in range(count):
        scenario = random.choice(_SCENARIO_POOL)
        geo_info  = random.choice(_GEO_POOL)
        country, code, base_lat, base_lon = geo_info

        # Add small jitter to lat/lon for visual diversity
        lat = base_lat + random.uniform(-3, 3)
        lon = base_lon + random.uniform(-3, 3)

        source_ip    = _random_ip()
        severity_score = round(random.uniform(*scenario["severity_range"]), 1)
        confidence     = round(random.uniform(*scenario["confidence_range"]), 1)
        timestamp      = random_timestamp()

        # Severity level from score
        if severity_score >= 8.0:    severity = SeverityLevel.CRITICAL
        elif severity_score >= 6.0:  severity = SeverityLevel.HIGH
        elif severity_score >= 4.0:  severity = SeverityLevel.MEDIUM
        else:                        severity = SeverityLevel.LOW

        description = random.choice(scenario["descriptions"])
        port        = random.choice(scenario["ports"])
        protocol    = random.choice(scenario["protocols"])
        tags        = list(scenario["tags"])

        # Unique deterministic event_id
        raw_id   = f"sim_{source_ip}_{timestamp.isoformat()}_{i}"
        event_id = hashlib.md5(raw_id.encode()).hexdigest()

        event = ThreatEvent(
            event_id       = event_id,
            source         = DataSource.SIMULATED,
            timestamp      = timestamp,
            attack_type    = scenario["type"],
            indicator      = source_ip,
            source_ip      = source_ip,
            description    = description,
            port           = port,
            protocol       = protocol,
            severity       = severity,
            severity_score = severity_score,
            confidence     = confidence,
            source_geo     = GeoLocation(
                country      = country,
                country_code = code,
                city         = None,
                latitude     = round(lat, 4),
                longitude    = round(lon, 4),
            ),
            mitre = scenario["mitre"],
            tags  = tags,
            raw   = {"simulated": True, "scenario": scenario["type"].value}
        )
        events.append(event)

    # Add spike events
    for spike_ts, spike_type in spike_timestamps:
        scenario = next(s for s in ATTACK_SCENARIOS if s["type"] == spike_type)
        geo_info  = random.choice(_GEO_POOL[:5])   # spikes from top-5 geo sources
        country, code, base_lat, base_lon = geo_info
        source_ip = _random_ip()
        raw_id    = f"spike_{source_ip}_{spike_ts.isoformat()}"
        event_id  = hashlib.md5(raw_id.encode()).hexdigest()

        events.append(ThreatEvent(
            event_id       = event_id,
            source         = DataSource.SIMULATED,
            timestamp      = spike_ts,
            attack_type    = spike_type,
            indicator      = source_ip,
            source_ip      = source_ip,
            description    = random.choice(scenario["descriptions"]),
            port           = random.choice(scenario["ports"]),
            protocol       = random.choice(scenario["protocols"]),
            severity       = SeverityLevel.HIGH,
            severity_score = round(random.uniform(7.5, 9.5), 1),
            confidence     = round(random.uniform(80, 95), 1),
            source_geo     = GeoLocation(
                country      = country,
                country_code = code,
                latitude     = round(base_lat + random.uniform(-2, 2), 4),
                longitude    = round(base_lon + random.uniform(-2, 2), 4),
            ),
            mitre = scenario["mitre"],
            tags  = list(scenario["tags"]) + ["spike", "anomaly"],
            raw   = {"simulated": True, "spike": True}
        ))

    random.shuffle(events)
    logger.info(f"Generated {len(events)} simulated events ({len(spike_timestamps)} spike events)")
    return events


def run_simulation_ingestion(count: int = 300) -> dict:
    """Generate and store simulated threat data."""
    logger.info(f"=== Simulation Ingestion Started (count={count}) ===")
    events = generate_simulated_events(count=count, hours_back=48, include_spike=True)
    result = upsert_threat_events(events)
    logger.info(f"=== Simulation Complete === {result}")
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from config.database import ensure_indexes
    ensure_indexes()
    result = run_simulation_ingestion(count=300)
    print(f"\n✅ Done: {result}")
