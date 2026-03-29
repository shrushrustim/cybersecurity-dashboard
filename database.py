"""
database.py — MongoDB connection, CRUD helpers, and index setup.
Uses pymongo (sync) for ingestion scripts and motor (async) for the FastAPI backend.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import certifi
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError, BulkWriteError

from config.settings import (
    MONGO_URI, MONGO_DB_NAME,
    MONGO_TLS,
    COLLECTION_EVENTS, COLLECTION_CVES, COLLECTION_ALERTS
)
from config.schema import ThreatEvent, CVEEvent

logger = logging.getLogger(__name__)


# ── Filter helper ───────────────────────────────────────────────────────────────

def _match(hours_back: int,
           attack_type: Optional[str] = None,
           severity: Optional[str] = None) -> dict:
    """Build a MongoDB $match dict with optional attack_type and severity filters."""
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    q: dict = {"timestamp": {"$gte": cutoff.isoformat()}}
    if attack_type and attack_type != "all":
        q["attack_type"] = attack_type
    if severity and severity != "all":
        q["severity"] = severity
    return q


# ── Connection ──────────────────────────────────────────────────────────────────

_client: Optional[MongoClient] = None

def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=30000,
            tls=MONGO_TLS,
            tlsAllowInvalidCertificates=True,
            tlsCAFile=certifi.where() if MONGO_TLS else None
        )
        logger.info("MongoDB connected")

    return _client


def get_db():
    return get_client()[MONGO_DB_NAME]


# ── Index Setup (run once on first deploy) ──────────────────────────────────────

def ensure_indexes():
    """
    Create indexes for fast dashboard queries.
    Safe to call multiple times — MongoDB ignores duplicates.
    """
    db = get_db()

    # threat_events indexes
    events: Collection = db[COLLECTION_EVENTS]
    events.create_index([("timestamp", DESCENDING)])
    events.create_index([("attack_type", ASCENDING)])
    events.create_index([("severity", ASCENDING)])
    events.create_index([("source_geo.country_code", ASCENDING)])
    events.create_index([("severity_score", DESCENDING)])
    events.create_index([("event_id", ASCENDING)], unique=True)
    events.create_index([
        ("timestamp", DESCENDING),
        ("attack_type", ASCENDING)
    ])  # compound for dashboard filters

    # cve_events indexes
    cves: Collection = db[COLLECTION_CVES]
    cves.create_index([("cve_id", ASCENDING)], unique=True)
    cves.create_index([("published", DESCENDING)])
    cves.create_index([("cvss_score", DESCENDING)])

    # alerts indexes
    alerts: Collection = db[COLLECTION_ALERTS]
    alerts.create_index([("created_at", DESCENDING)])
    alerts.create_index([("resolved", ASCENDING)])

    logger.info("MongoDB indexes ensured")


# ── Threat Events ───────────────────────────────────────────────────────────────

def upsert_threat_events(events: List[ThreatEvent]) -> Dict[str, int]:
    """
    Bulk upsert threat events. Uses event_id as the unique key so
    re-running ingestion never creates duplicates.
    Returns counts of inserted/updated/skipped.
    """
    if not events:
        return {"inserted": 0, "updated": 0, "skipped": 0}

    collection: Collection = get_db()[COLLECTION_EVENTS]
    inserted = updated = skipped = 0

    for event in events:
        doc = event.to_db_dict()
        try:
            result = collection.update_one(
                {"event_id": event.event_id},
                {"$setOnInsert": doc},
                upsert=True
            )
            if result.upserted_id:
                inserted += 1
            elif result.matched_count:
                skipped += 1   # already exists, don't overwrite
        except Exception as e:
            logger.warning(f"Failed to upsert event {event.event_id}: {e}")
            skipped += 1

    logger.info(f"Upserted events → inserted:{inserted} skipped:{skipped}")
    return {"inserted": inserted, "updated": updated, "skipped": skipped}


def upsert_cve_events(cves: List[CVEEvent]) -> Dict[str, int]:
    """Bulk upsert CVE events."""
    if not cves:
        return {"inserted": 0, "skipped": 0}

    collection: Collection = get_db()[COLLECTION_CVES]
    inserted = skipped = 0

    for cve in cves:
        doc = cve.dict()
        doc["published"]      = cve.published.isoformat()
        doc["last_modified"]  = cve.last_modified.isoformat()
        # $set and $setOnInsert cannot share field paths — exclude overlapping fields
        update_fields = {"cvss_score", "cvss_severity", "last_modified", "exploit_available"}
        insert_doc = {k: v for k, v in doc.items() if k not in update_fields}
        try:
            result = collection.update_one(
                {"cve_id": cve.cve_id},
                {
                    "$set": {
                        "cvss_score":        cve.cvss_score,
                        "cvss_severity":     cve.cvss_severity,
                        "last_modified":     doc["last_modified"],
                        "exploit_available": cve.exploit_available,
                    },
                    "$setOnInsert": insert_doc
                },
                upsert=True
            )
            if result.upserted_id:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            logger.warning(f"Failed to upsert CVE {cve.cve_id}: {e}")

    logger.info(f"Upserted CVEs → inserted:{inserted} skipped:{skipped}")
    return {"inserted": inserted, "skipped": skipped}


# ── Dashboard Query Helpers ─────────────────────────────────────────────────────

def get_recent_events(limit: int = 100, hours_back: int = 24,
                      attack_type: str = None, severity: str = None) -> List[dict]:
    """Fetch the most recent threat events for the live feed panel."""
    collection = get_db()[COLLECTION_EVENTS]
    cursor = (
        collection
        .find(_match(hours_back, attack_type, severity))
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    docs = list(cursor)
    for d in docs:
        d.pop("_id", None)
    return docs


def get_event_count(hours_back: int = 24,
                    attack_type: str = None, severity: str = None) -> int:
    """Fast count of total events in the time window — used for KPI total."""
    return get_db()[COLLECTION_EVENTS].count_documents(
        _match(hours_back, attack_type, severity)
    )


def get_hourly_counts_by_type(hours_back: int = 48,
                               attack_type: str = None, severity: str = None) -> List[dict]:
    """Stacked trend data: attack counts bucketed by hour AND attack type."""
    pipeline = [
        {"$match": _match(hours_back, attack_type, severity)},
        {"$group": {
            "_id":   {"hour": {"$substr": ["$timestamp", 0, 13]}, "attack_type": "$attack_type"},
            "count": {"$sum": 1}
        }},
        {"$project": {"hour": "$_id.hour", "attack_type": "$_id.attack_type", "count": 1, "_id": 0}},
        {"$sort": {"hour": 1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_attack_type_counts(hours_back: int = 24,
                           attack_type: str = None,
                           severity: str = None) -> List[dict]:
    """Aggregate attack counts by type for bar charts."""
    pipeline = [
        {"$match": _match(hours_back, attack_type, severity)},
        {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
        {"$project": {"attack_type": "$_id", "count": 1, "_id": 0}},
        {"$sort": {"count": -1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_hourly_counts(hours_back: int = 48,
                      attack_type: str = None, severity: str = None) -> List[dict]:
    """Time-series data: attack counts bucketed by hour."""
    pipeline = [
        {"$match": _match(hours_back, attack_type, severity)},
        {"$group": {
            "_id":          {"$substr": ["$timestamp", 0, 13]},
            "count":        {"$sum": 1},
            "avg_severity": {"$avg": "$severity_score"},
            "max_severity": {"$max": "$severity_score"},
        }},
        {"$project": {"hour": "$_id", "count": 1, "avg_severity": 1, "max_severity": 1, "_id": 0}},
        {"$sort": {"hour": 1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_avg_severity_score(hours_back: int = 24,
                           attack_type: str = None, severity: str = None) -> float:
    """Compute true average severity_score directly from MongoDB (no event cap)."""
    pipeline = [
        {"$match": _match(hours_back, attack_type, severity)},
        {"$group": {"_id": None, "avg": {"$avg": "$severity_score"}}},
    ]
    result = list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))
    if result and result[0].get("avg") is not None:
        return round(result[0]["avg"], 1)
    return 0.0


def get_country_counts(hours_back: int = 24,
                       attack_type: str = None, severity: str = None) -> List[dict]:
    """Geo data for choropleth map."""
    base = _match(hours_back, attack_type, severity)
    base["source_geo.country_code"] = {"$ne": None}
    base["source_geo.country"]      = {"$ne": None}
    pipeline = [
        {"$match": base},
        {
            "$group": {
                "_id": {
                    "country_code": "$source_geo.country_code",
                    "country":      "$source_geo.country"
                },
                "count":        {"$sum": 1},
                "avg_severity": {"$avg": "$severity_score"},
                "lat":          {"$first": "$source_geo.latitude"},
                "lon":          {"$first": "$source_geo.longitude"},
            }
        },
        {
            "$project": {
                "country_code": "$_id.country_code",
                "country":      "$_id.country",
                "count": 1, "avg_severity": 1, "lat": 1, "lon": 1,
                "_id": 0
            }
        },
        {"$sort": {"count": -1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_mitre_technique_counts(hours_back: int = 168,
                               attack_type: str = None, severity: str = None) -> List[dict]:
    """MITRE ATT&CK technique distribution for treemap / sunburst."""
    base = _match(hours_back, attack_type, severity)
    base["mitre.tactic"] = {"$ne": None}
    pipeline = [
        {"$match": base},
        {
            "$group": {
                "_id": {
                    "tactic":       "$mitre.tactic",
                    "technique_id": "$mitre.technique_id",
                    "technique":    "$mitre.technique"
                },
                "count": {"$sum": 1},
                "avg_severity": {"$avg": "$severity_score"}
            }
        },
        {
            "$project": {
                "tactic":       "$_id.tactic",
                "technique_id": "$_id.technique_id",
                "technique":    "$_id.technique",
                "count": 1, "avg_severity": 1, "_id": 0
            }
        },
        {"$sort": {"count": -1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_top_cves(limit: int = 20) -> List[dict]:
    """Fetch top critical CVEs sorted by CVSS score."""
    collection = get_db()[COLLECTION_CVES]
    cursor = (
        collection
        .find({"cvss_score": {"$ne": None}})
        .sort("cvss_score", DESCENDING)
        .limit(limit)
    )
    docs = list(cursor)
    for d in docs:
        d.pop("_id", None)
    return docs


def get_alerts(limit: int = 50, resolved: Optional[bool] = None) -> List[dict]:
    """Fetch alerts stored by the alert engine, newest first."""
    collection = get_db()[COLLECTION_ALERTS]
    query: dict = {}
    if resolved is not None:
        query["resolved"] = resolved
    cursor = (
        collection
        .find(query)
        .sort("created_at", DESCENDING)
        .limit(limit)
    )
    docs = list(cursor)
    for d in docs:
        d.pop("_id", None)
    return docs


def get_unresolved_alert_count() -> int:
    """Count of alerts that have not been resolved — used for the badge."""
    return get_db()[COLLECTION_ALERTS].count_documents({"resolved": False})


def get_severity_distribution(hours_back: int = 24,
                              attack_type: str = None,
                              severity: str = None) -> List[dict]:
    """Severity breakdown for donut chart."""
    pipeline = [
        {"$match": _match(hours_back, attack_type, severity)},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$project": {"severity": "$_id", "count": 1, "_id": 0}},
        {"$sort": {"count": -1}}
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))


def get_top_source_ips(limit: int = 15, hours_back: int = 168) -> List[dict]:
    """Top most-reported source IPs for the Threat Intelligence tab."""
    cutoff = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()
    pipeline = [
        {"$match": {
            "timestamp": {"$gte": cutoff},
            "source_ip": {"$ne": None},
        }},
        {"$group": {
            "_id": "$source_ip",
            "count": {"$sum": 1},
            "country": {"$first": "$source_geo.country"},
            "attack_types": {"$addToSet": "$attack_type"},
        }},
        {"$project": {
            "source_ip": "$_id",
            "count": 1,
            "country": 1,
            "attack_types": 1,
            "_id": 0,
        }},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    return list(get_db()[COLLECTION_EVENTS].aggregate(pipeline))
