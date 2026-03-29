"""
fetch_nvd.py — Module 1: NVD CVE Feed Ingestion
Fetches recent CVEs from NIST NVD API v2.0 (free, no key needed for basic use).
Normalizes into CVEEvent + ThreatEvent and stores in MongoDB.
"""

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import requests

# Add parent dir to path when running standalone
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import NVD_BASE_URL, NVD_API_KEY, NVD_FETCH_DAYS_BACK
from config.schema import CVEEvent, ThreatEvent, AttackType, DataSource
from config.database import upsert_cve_events, upsert_threat_events

logger = logging.getLogger(__name__)


# ── MITRE ATT&CK keyword → technique mapping ───────────────────────────────────
# Used to auto-tag CVEs with MITRE context from their description text.

KEYWORD_TO_MITRE = {
    "sql injection":          ("Initial Access",      "T1190", "Exploit Public-Facing Application"),
    "buffer overflow":        ("Execution",           "T1203", "Exploitation for Client Execution"),
    "remote code execution":  ("Execution",           "T1203", "Exploitation for Client Execution"),
    "rce":                    ("Execution",           "T1203", "Exploitation for Client Execution"),
    "cross-site scripting":   ("Initial Access",      "T1189", "Drive-by Compromise"),
    "xss":                    ("Initial Access",      "T1189", "Drive-by Compromise"),
    "privilege escalation":   ("Privilege Escalation","T1068", "Exploitation for Privilege Escalation"),
    "authentication bypass":  ("Defense Evasion",     "T1556", "Modify Authentication Process"),
    "path traversal":         ("Discovery",           "T1083", "File and Directory Discovery"),
    "directory traversal":    ("Discovery",           "T1083", "File and Directory Discovery"),
    "denial of service":      ("Impact",              "T1499", "Endpoint Denial of Service"),
    "dos":                    ("Impact",              "T1499", "Endpoint Denial of Service"),
    "information disclosure": ("Collection",          "T1213", "Data from Information Repositories"),
    "command injection":      ("Execution",           "T1059", "Command and Scripting Interpreter"),
    "xxe":                    ("Initial Access",      "T1190", "Exploit Public-Facing Application"),
    "deserialization":        ("Execution",           "T1203", "Exploitation for Client Execution"),
    "ssrf":                   ("Discovery",           "T1018", "Remote System Discovery"),
    "open redirect":          ("Initial Access",      "T1189", "Drive-by Compromise"),
    "csrf":                   ("Initial Access",      "T1189", "Drive-by Compromise"),
    "backdoor":               ("Persistence",         "T1505", "Server Software Component"),
    "ransomware":             ("Impact",              "T1486", "Data Encrypted for Impact"),
}

def _extract_vendor_product(cve_data: dict) -> tuple:
    """
    Recursively search NVD configurations for the first vulnerable CPE entry.
    NVD nests CPE matches at varying depths: nodes → cpeMatch, or nodes → children → cpeMatch.
    Returns (vendor, product) or (None, None) if not found.
    """
    def _search_nodes(nodes: list) -> tuple:
        for node in nodes:
            # Direct cpeMatch on this node
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", True):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) > 4:
                        v = parts[3] if parts[3] not in ("*", "-", "") else None
                        p = parts[4] if parts[4] not in ("*", "-", "") else None
                        if v:
                            return v, p
            # Recurse into children
            result = _search_nodes(node.get("children", []))
            if result[0]:
                return result
        return None, None

    for config in cve_data.get("configurations", []):
        v, p = _search_nodes(config.get("nodes", []))
        if v:
            return v, p
    return None, None


def _extract_mitre(description: str) -> tuple:
    """Return (tactic, technique_id, technique) based on description keywords."""
    desc_lower = description.lower()
    for keyword, mapping in KEYWORD_TO_MITRE.items():
        if keyword in desc_lower:
            return mapping
    return (None, None, None)


def _extract_attack_type(description: str) -> AttackType:
    """Best-guess attack type from CVE description."""
    d = description.lower()
    if any(k in d for k in ["ransomware", "encrypt"]):    return AttackType.RANSOMWARE
    if any(k in d for k in ["denial of service", " dos "]):return AttackType.DDOS
    if any(k in d for k in ["phish", "spoofing"]):         return AttackType.PHISHING
    if any(k in d for k in ["malware", "trojan", "worm"]): return AttackType.MALWARE
    if any(k in d for k in ["brute force", "brute-force"]): return AttackType.BRUTE_FORCE
    return AttackType.EXPLOIT


def _parse_cve_item(item: dict) -> Optional[CVEEvent]:
    """Parse a single NVD CVE item dict into a CVEEvent model."""
    try:
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "No description available."
        )

        # Dates
        published_str     = cve_data.get("published", "")
        last_modified_str = cve_data.get("lastModified", published_str)

        published     = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
        last_modified = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))

        # CVSS v3.1 scoring (preferred) then v3.0 then v2.0
        cvss_score    = None
        cvss_severity = None
        attack_vector = None
        metrics = cve_data.get("metrics", {})

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data     = metric_list[0].get("cvssData", {})
                cvss_score    = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity") or cvss_data.get("accessVector", "").upper()
                attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
                break

        # Affected vendor/product — search all nodes + children recursively
        vendor, product = _extract_vendor_product(cve_data)

        # References
        refs = [r.get("url", "") for r in cve_data.get("references", [])[:5]]

        # MITRE mapping from description
        tactic, technique_id, technique = _extract_mitre(desc_en)

        return CVEEvent(
            cve_id           = cve_id,
            published        = published,
            last_modified    = last_modified,
            description      = desc_en[:500],
            cvss_score       = cvss_score,
            cvss_severity    = cvss_severity,
            attack_vector    = attack_vector,
            affected_vendor  = vendor,
            affected_product = product,
            patch_available  = False,       # NVD doesn't expose this directly
            exploit_available= False,
            mitre_technique  = technique,
            references       = [r for r in refs if r],
            source           = DataSource.NVD,
        )

    except Exception as e:
        logger.warning(f"Failed to parse CVE item: {e}")
        return None


def fetch_nvd_cves(days_back: int = NVD_FETCH_DAYS_BACK) -> List[CVEEvent]:
    """
    Fetch recent CVEs from NVD API.
    Returns a list of CVEEvent objects ready for DB storage.
    """
    end_dt   = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=days_back)

    params = {
        "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
        "startIndex": 0,
    }
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    all_cves: List[CVEEvent] = []
    total_results = None

    logger.info(f"Fetching NVD CVEs for last {days_back} days...")

    while True:
        try:
            response = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            break

        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info(f"NVD: {total_results} CVEs found for period")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = _parse_cve_item(item)
            if cve:
                all_cves.append(cve)

        params["startIndex"] += len(vulnerabilities)
        if params["startIndex"] >= total_results:
            break

        # NVD rate limit: 5 requests/30s without key, 50/30s with key
        sleep_time = 1.0 if NVD_API_KEY else 6.0
        time.sleep(sleep_time)

    logger.info(f"NVD: parsed {len(all_cves)} CVEs")
    return all_cves


def run_nvd_ingestion() -> dict:
    """
    Full NVD ingestion pipeline:
    Fetch → Parse → Store CVEs → Convert to ThreatEvents → Store Events
    """
    logger.info("=== NVD Ingestion Started ===")

    cves = fetch_nvd_cves()
    if not cves:
        logger.warning("No CVEs fetched from NVD")
        return {"cves_stored": 0, "events_stored": 0}

    # Store raw CVE records
    cve_result = upsert_cve_events(cves)

    # Convert each CVE to a unified ThreatEvent and store
    threat_events = [cve.to_threat_event() for cve in cves]
    event_result  = upsert_threat_events(threat_events)

    logger.info(f"=== NVD Ingestion Complete === CVEs:{cve_result} Events:{event_result}")
    return {
        "cves_stored":   cve_result["inserted"],
        "events_stored": event_result["inserted"]
    }


# ── Standalone run ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from config.database import ensure_indexes
    ensure_indexes()
    result = run_nvd_ingestion()
    print(f"\n✅ Done: {result}")
