"""
fetch_all.py — Master ingestion orchestrator (Module 1).
Runs all data sources in sequence with proper error isolation.
This is the script called by GitHub Actions cron every 15 minutes.

Usage:
    python ingestion/fetch_all.py                   # run all sources
    python ingestion/fetch_all.py --sim-only        # simulated data only (no API keys needed)
    python ingestion/fetch_all.py --sources nvd otx # specific sources
"""

import argparse
import logging
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.database import ensure_indexes
from config.settings import OTX_API_KEY, ABUSEIPDB_KEY

# Alert engine — imported here so alerts fire after every ingestion run
try:
    from ingestion.alert_engine import run_alert_checks
    ALERTS_ENABLED = True
except ImportError:
    ALERTS_ENABLED = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("fetch_all")


def run_all(sources: list = None, sim_count: int = 100) -> dict:
    """
    Run ingestion for all specified sources.
    Each source is isolated — one failing doesn't stop others.
    """
    results = {}
    start   = datetime.utcnow()

    # Ensure MongoDB indexes exist
    try:
        ensure_indexes()
    except Exception as e:
        logger.error(f"Failed to ensure MongoDB indexes: {e}")
        logger.error("Check your MONGO_URI environment variable.")
        return {"error": str(e)}

    available_sources = sources or ["nvd", "otx", "abuseipdb", "sim"]

    # ── NVD CVE Feed ────────────────────────────────────────────────────────────
    if "nvd" in available_sources:
        logger.info("─" * 50)
        logger.info("Starting NVD CVE ingestion...")
        try:
            from ingestion.fetch_nvd import run_nvd_ingestion
            results["nvd"] = run_nvd_ingestion()
        except Exception as e:
            logger.error(f"NVD ingestion failed: {e}", exc_info=True)
            results["nvd"] = {"error": str(e)}

    # ── AlienVault OTX ──────────────────────────────────────────────────────────
    if "otx" in available_sources:
        logger.info("─" * 50)
        if OTX_API_KEY:
            logger.info("Starting OTX ingestion...")
            try:
                from ingestion.fetch_otx import run_otx_ingestion
                results["otx"] = run_otx_ingestion()
            except Exception as e:
                logger.error(f"OTX ingestion failed: {e}", exc_info=True)
                results["otx"] = {"error": str(e)}
        else:
            logger.warning("OTX_API_KEY not set — skipping OTX. Get a free key at otx.alienvault.com")
            results["otx"] = {"skipped": "no API key"}

    # ── AbuseIPDB ───────────────────────────────────────────────────────────────
    if "abuseipdb" in available_sources:
        logger.info("─" * 50)
        if ABUSEIPDB_KEY:
            logger.info("Starting AbuseIPDB ingestion...")
            try:
                from ingestion.fetch_abuseipdb import run_abuseipdb_ingestion
                results["abuseipdb"] = run_abuseipdb_ingestion()
            except Exception as e:
                logger.error(f"AbuseIPDB ingestion failed: {e}", exc_info=True)
                results["abuseipdb"] = {"error": str(e)}
        else:
            logger.warning("ABUSEIPDB_KEY not set — skipping AbuseIPDB. Get a free key at abuseipdb.com")
            results["abuseipdb"] = {"skipped": "no API key"}

    # ── Simulated Data (always runs if included, useful for dev) ────────────────
    if "sim" in available_sources:
        logger.info("─" * 50)
        logger.info(f"Generating {sim_count} simulated events...")
        try:
            from ingestion.simulate_data import run_simulation_ingestion
            results["simulated"] = run_simulation_ingestion(count=sim_count)
        except Exception as e:
            logger.error(f"Simulation failed: {e}", exc_info=True)
            results["simulated"] = {"error": str(e)}

    # ── Summary ─────────────────────────────────────────────────────────────────
    elapsed = (datetime.utcnow() - start).total_seconds()
    logger.info("═" * 50)
    logger.info(f"INGESTION COMPLETE in {elapsed:.1f}s")
    for source, result in results.items():
        logger.info(f"  {source}: {result}")
    logger.info("═" * 50)

    # ── Run Alert Checks after every ingestion ───────────────────────────────────
    # Fires Telegram + email if severity/volume thresholds are crossed
    if ALERTS_ENABLED:
        logger.info("Running alert checks...")
        try:
            from config.database import get_recent_events, get_top_cves
            recent_events = get_recent_events(limit=200, hours_back=1)
            recent_cves   = get_top_cves(limit=20)
            alert_results = run_alert_checks(
                new_events = recent_events,
                new_cves   = recent_cves,
            )
            results["alerts"] = alert_results
            fired = alert_results.get("alerts_fired", 0)
            if fired > 0:
                logger.warning(f"🚨 {fired} alert(s) fired and sent!")
            else:
                logger.info("No alert thresholds crossed this run.")
        except Exception as e:
            logger.error(f"Alert checks failed: {e}")
            results["alerts"] = {"error": str(e)}
    else:
        logger.info("Alert engine not loaded — skipping alert checks")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Threat Dashboard — Data Ingestion")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["nvd", "otx", "abuseipdb", "sim"],
        default=["nvd", "otx", "abuseipdb", "sim"],
        help="Which data sources to ingest (default: all)"
    )
    parser.add_argument(
        "--sim-only",
        action="store_true",
        help="Only generate simulated data (no API keys needed)"
    )
    parser.add_argument(
        "--sim-count",
        type=int,
        default=100,
        help="Number of simulated events to generate (default: 100)"
    )
    args = parser.parse_args()

    if args.sim_only:
        sources = ["sim"]
    else:
        sources = args.sources

    results = run_all(sources=sources, sim_count=args.sim_count)
    print("\n📊 Final Results:")
    for source, result in results.items():
        print(f"   {source}: {result}")
