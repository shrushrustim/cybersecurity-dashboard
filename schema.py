"""
schema.py — Pydantic models for all threat event data.
Every API response gets normalized into ThreatEvent before DB storage.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Literal
from datetime import datetime
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────────

class AttackType(str, Enum):
    MALWARE       = "Malware"
    RANSOMWARE    = "Ransomware"
    DDOS          = "DDoS"
    PHISHING      = "Phishing"
    SCAN          = "Port Scan"
    BRUTE_FORCE   = "Brute Force"
    DATA_BREACH   = "Data Breach"
    BOTNET        = "Botnet"
    EXPLOIT       = "Exploit"
    UNKNOWN       = "Unknown"

class SeverityLevel(str, Enum):
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"

class DataSource(str, Enum):
    NVD        = "NVD"
    OTX        = "AlienVault OTX"
    ABUSEIPDB  = "AbuseIPDB"
    VIRUSTOTAL = "VirusTotal"
    SIMULATED  = "Simulated"


# ── Geo Location ───────────────────────────────────────────────────────────────

class GeoLocation(BaseModel):
    country:      Optional[str]  = None
    country_code: Optional[str]  = None   # ISO 3166-1 alpha-2  e.g. "IN"
    city:         Optional[str]  = None
    latitude:     Optional[float] = None
    longitude:    Optional[float] = None
    asn:          Optional[str]  = None   # Autonomous System Number
    isp:          Optional[str]  = None


# ── MITRE ATT&CK mapping ───────────────────────────────────────────────────────

class MitreMapping(BaseModel):
    tactic:       Optional[str] = None   # e.g. "Initial Access"
    technique_id: Optional[str] = None   # e.g. "T1190"
    technique:    Optional[str] = None   # e.g. "Exploit Public-Facing Application"


# ── Core Threat Event ──────────────────────────────────────────────────────────

class ThreatEvent(BaseModel):
    """
    Unified normalized threat event.
    All ingestion sources map their raw data into this model.
    """
    # Identity
    event_id:    str                        # unique hash of source+indicator
    source:      DataSource

    # Timing
    timestamp:   datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    # Attack details
    attack_type: AttackType   = AttackType.UNKNOWN
    indicator:   Optional[str] = None      # IP, domain, URL, hash, CVE-ID
    description: Optional[str] = None

    # Network
    source_ip:   Optional[str] = None
    target_ip:   Optional[str] = None
    port:        Optional[int] = None
    protocol:    Optional[str] = None      # TCP, UDP, HTTP, etc.

    # Scoring
    severity:       SeverityLevel = SeverityLevel.LOW
    severity_score: float = 0.0            # 0.0 – 10.0
    confidence:     float = 0.0            # 0.0 – 100.0 (%)

    # Geo
    source_geo: Optional[GeoLocation] = None
    target_geo: Optional[GeoLocation] = None

    # MITRE
    mitre: Optional[MitreMapping] = None

    # Tags (free-form list for flexible filtering)
    tags: List[str] = []

    # Raw payload kept for debugging
    raw: Optional[dict] = None

    @validator("severity_score")
    def clamp_score(cls, v):
        return max(0.0, min(10.0, v))

    @validator("confidence")
    def clamp_conf(cls, v):
        return max(0.0, min(100.0, v))

    def to_db_dict(self) -> dict:
        """Convert to MongoDB-friendly dict (no ObjectId yet)."""
        d = self.dict()
        d["timestamp"]   = self.timestamp.isoformat()
        d["ingested_at"] = self.ingested_at.isoformat()
        return d


# ── CVE Event (for Module 1 NVD feed) ─────────────────────────────────────────

class CVEEvent(BaseModel):
    cve_id:          str
    published:       datetime
    last_modified:   datetime
    description:     str
    cvss_score:      Optional[float] = None    # CVSS v3.1 base score
    cvss_severity:   Optional[str]   = None    # LOW / MEDIUM / HIGH / CRITICAL
    attack_vector:   Optional[str]   = None    # NETWORK / ADJACENT / LOCAL / PHYSICAL
    affected_vendor: Optional[str]   = None
    affected_product:Optional[str]   = None
    patch_available: bool             = False
    exploit_available:bool            = False
    mitre_technique: Optional[str]   = None
    references:      List[str]        = []
    source:          DataSource       = DataSource.NVD

    def to_threat_event(self) -> ThreatEvent:
        """Convert a CVEEvent into a unified ThreatEvent for the dashboard."""
        score = self.cvss_score or 0.0
        sev = (
            SeverityLevel.CRITICAL if score >= 9.0 else
            SeverityLevel.HIGH     if score >= 7.0 else
            SeverityLevel.MEDIUM   if score >= 4.0 else
            SeverityLevel.LOW
        )
        import hashlib
        event_id = hashlib.md5(self.cve_id.encode()).hexdigest()
        return ThreatEvent(
            event_id       = event_id,
            source         = DataSource.NVD,
            timestamp      = self.published,
            attack_type    = AttackType.EXPLOIT,
            indicator      = self.cve_id,
            description    = self.description,
            severity       = sev,
            severity_score = score,
            confidence     = 95.0,
            mitre          = MitreMapping(technique=self.mitre_technique) if self.mitre_technique else None,
            tags           = (["exploit"] if self.exploit_available else []) +
                             (["no-patch"] if not self.patch_available else ["patch-available"]),
            raw            = self.dict(),
        )
