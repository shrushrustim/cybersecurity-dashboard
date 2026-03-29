"""
url_scanner.py — URL / Domain security scanner.
Checks: SSL validity, security headers, URLhaus blacklist, VirusTotal (if key set).
"""

import re
import ssl
import socket
import logging
import requests
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


def scan_url(url: str, virustotal_key: str = "") -> dict:
    """
    Comprehensive URL scan.
    Returns a dict with keys: url, risk_score, ssl, headers, blacklist, vt, error
    """
    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "Low",
        "ssl": {},
        "headers": {},
        "blacklist": {},
        "vt": {},
        "error": None,
        "checked_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        result["url"] = url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    risk = 0

    # ── 1. SSL Check ──────────────────────────────────────────────────────────
    ssl_info = {"valid": False, "expiry": "—", "issuer": "—", "error": None}
    if parsed.scheme == "https" or not parsed.scheme:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=6),
                server_hostname=hostname,
            ) as s:
                cert = s.getpeercert()
                expiry_str = cert.get("notAfter", "")
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
                issuer = dict(x[0] for x in cert.get("issuer", []))
                ssl_info["valid"] = True
                ssl_info["expiry"] = expiry.strftime("%Y-%m-%d") if expiry else "—"
                ssl_info["issuer"] = issuer.get("organizationName", "—")
                if expiry and (expiry - datetime.utcnow()).days < 14:
                    risk += 15
        except ssl.SSLCertVerificationError as e:
            ssl_info["valid"] = False
            ssl_info["error"] = str(e)[:80]
            risk += 30
        except Exception as e:
            ssl_info["error"] = str(e)[:60]
            if parsed.scheme == "https":
                risk += 10
    else:
        ssl_info["valid"] = False
        ssl_info["error"] = "HTTP (no SSL)"
        risk += 20

    result["ssl"] = ssl_info

    # ── 2. HTTP Headers Check ─────────────────────────────────────────────────
    headers_info = {"present": [], "missing": [], "server": "—", "error": None}
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (security-scanner)"})
        server = resp.headers.get("Server", "—")
        headers_info["server"] = server

        for h in SECURITY_HEADERS:
            if h.lower() in {k.lower() for k in resp.headers}:
                headers_info["present"].append(h)
            else:
                headers_info["missing"].append(h)

        # Penalise missing security headers
        risk += len(headers_info["missing"]) * 4

        # Penalise revealing server header
        if server and server != "—" and re.search(r"\d", server):
            risk += 5

    except requests.exceptions.SSLError:
        headers_info["error"] = "SSL error connecting"
        risk += 25
    except requests.exceptions.ConnectionError:
        headers_info["error"] = "Could not connect to host"
        risk += 20
    except Exception as e:
        headers_info["error"] = str(e)[:60]

    result["headers"] = headers_info

    # ── 3. URLhaus Blacklist Check ────────────────────────────────────────────
    blacklist_info = {"listed": False, "threat": "—", "source": "URLhaus", "error": None}
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "is_listed":
                blacklist_info["listed"] = True
                blacklist_info["threat"] = data.get("threat", "malware")
                risk += 50
    except Exception as e:
        blacklist_info["error"] = str(e)[:50]

    result["blacklist"] = blacklist_info

    # ── 4. VirusTotal (optional) ──────────────────────────────────────────────
    vt_info = {"available": False, "positives": 0, "total": 0, "permalink": ""}
    if virustotal_key:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": virustotal_key},
                timeout=10,
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                vt_info = {
                    "available": True,
                    "positives": positives,
                    "total": total,
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                }
                risk += min(positives * 5, 40)
        except Exception as e:
            vt_info["error"] = str(e)[:50]

    result["vt"] = vt_info

    # ── Final Risk Score ──────────────────────────────────────────────────────
    risk = min(risk, 100)
    result["risk_score"] = risk
    result["risk_level"] = (
        "Critical" if risk >= 75 else
        "High"     if risk >= 50 else
        "Medium"   if risk >= 25 else
        "Low"
    )

    return result
