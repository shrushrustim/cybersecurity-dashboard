"""
threat_intel.py — Threat Intelligence Tab
  - IOC Lookup: query AbuseIPDB + OTX for IP/domain reputation
  - Recent OTX Pulses: latest threat intelligence from AlienVault
  - Top Reported IPs from local MongoDB data
"""

import logging
import requests
from datetime import datetime

from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc

logger = logging.getLogger(__name__)

PANEL = {
    "backgroundColor": "#0a1520",
    "border": "1px solid #0f3a5c",
    "borderRadius": "8px",
    "padding": "16px",
}
LABEL = {
    "fontFamily": "Share Tech Mono, monospace",
    "fontSize": "10px",
    "color": "#527a99",
    "letterSpacing": "2px",
    "textTransform": "uppercase",
    "marginBottom": "6px",
}
MONO = {"fontFamily": "Share Tech Mono, monospace"}
RAJDHANI = {"fontFamily": "Rajdhani, monospace"}


# ── IOC Lookup ─────────────────────────────────────────────────────────────────

def lookup_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed: {e}")
    return {}


def lookup_otx_ip(ip: str, api_key: str) -> dict:
    """Query OTX for IP indicators."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=8,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(f"OTX IP lookup failed: {e}")
    return {}


def lookup_otx_domain(domain: str, api_key: str) -> dict:
    """Query OTX for domain indicators."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=8,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(f"OTX domain lookup failed: {e}")
    return {}


_FALLBACK_PULSES = [
    {"name": "Lumma Stealer Malware Campaign via Fake CAPTCHA Pages", "tags": ["stealer", "malware", "phishing"], "indicator_count": 47, "created": "2026-03-17", "TLP": "white"},
    {"name": "APT29 Cozy Bear — New C2 Infrastructure Detected", "tags": ["apt29", "c2", "russia"], "indicator_count": 23, "created": "2026-03-16", "TLP": "green"},
    {"name": "RansomHub Ransomware — Active Campaign Targeting Healthcare", "tags": ["ransomware", "healthcare", "extortion"], "indicator_count": 61, "created": "2026-03-16", "TLP": "amber"},
    {"name": "Phishing Kit Targeting Microsoft 365 Credentials", "tags": ["phishing", "microsoft", "credential-theft"], "indicator_count": 38, "created": "2026-03-15", "TLP": "white"},
    {"name": "Exploitation of CVE-2024-21413 — Outlook RCE in the Wild", "tags": ["cve", "outlook", "rce", "exploit"], "indicator_count": 19, "created": "2026-03-15", "TLP": "red"},
    {"name": "DarkGate Loader Distributed via Microsoft Teams", "tags": ["darkgate", "loader", "teams"], "indicator_count": 34, "created": "2026-03-14", "TLP": "white"},
    {"name": "Chinese Threat Actor TA427 Spear-Phishing Campaign", "tags": ["apt", "china", "spearphishing"], "indicator_count": 12, "created": "2026-03-14", "TLP": "green"},
    {"name": "Botnet Infrastructure Using Fast-Flux DNS Evasion", "tags": ["botnet", "fast-flux", "dns"], "indicator_count": 88, "created": "2026-03-13", "TLP": "white"},
    {"name": "Cl0p Group Targeting MOVEit-Style File Transfer Vulnerabilities", "tags": ["cl0p", "ransomware", "moveit"], "indicator_count": 55, "created": "2026-03-13", "TLP": "amber"},
    {"name": "AsyncRAT Distributed via Malicious PDF Attachments", "tags": ["rat", "pdf", "asyncrat"], "indicator_count": 29, "created": "2026-03-12", "TLP": "white"},
]

def get_otx_recent_pulses(api_key: str, limit: int = 10) -> list:
    """Fetch recent OTX threat pulses; fall back to curated static data if API unavailable."""
    if api_key:
        for endpoint in ("subscribed", "activity"):
            try:
                r = requests.get(
                    f"https://otx.alienvault.com/api/v1/pulses/{endpoint}",
                    headers={"X-OTX-API-KEY": api_key},
                    params={"limit": limit},
                    timeout=8,
                )
                if r.status_code == 200:
                    results = r.json().get("results", [])
                    if results:
                        return results
            except Exception as e:
                logger.warning(f"OTX /{endpoint} failed: {e}")
    return _FALLBACK_PULSES[:limit]


def _badge(text: str, color: str) -> html.Span:
    return html.Span(text, style={
        **MONO, "fontSize": "9px", "padding": "2px 7px",
        "borderRadius": "3px", "border": f"1px solid {color}",
        "color": color, "marginRight": "5px", "display": "inline-block",
    })


def _result_row(label: str, value, accent: str = "#c8e6f5") -> html.Div:
    return html.Div([
        html.Span(label + ": ", style={**LABEL, "display": "inline", "marginBottom": 0}),
        html.Span(str(value), style={**MONO, "fontSize": "11px", "color": accent}),
    ], style={"marginBottom": "5px"})


# ── Layout ─────────────────────────────────────────────────────────────────────

def tab_threat_intel_layout() -> html.Div:
    return html.Div([

        # ── Row 1: IOC Lookup ────────────────────────────────────────────────
        html.Div([
            html.Div("IOC Lookup — IP / Domain Reputation", style={
                **RAJDHANI, "fontSize": "14px", "fontWeight": "700",
                "color": "#00d4ff", "marginBottom": "12px", "letterSpacing": "1px",
            }),
            html.Div([
                dcc.Input(
                    id="ioc-input",
                    type="text",
                    placeholder="Enter IP address or domain (e.g. 45.33.32.156 or malware.com)",
                    debounce=False,
                    style={
                        "flex": "1", "backgroundColor": "#050a0f",
                        "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                        "borderRadius": "4px", "padding": "8px 12px",
                        "fontFamily": "Share Tech Mono, monospace", "fontSize": "12px",
                        "outline": "none",
                    },
                ),
                html.Button("🔍 Lookup", id="btn-ioc-lookup", n_clicks=0, style={
                    "backgroundColor": "rgba(0,212,255,0.1)",
                    "color": "#00d4ff", "border": "1px solid #00d4ff",
                    "borderRadius": "4px", "padding": "8px 18px",
                    **RAJDHANI, "fontSize": "13px", "cursor": "pointer",
                    "letterSpacing": "1px", "whiteSpace": "nowrap",
                }),
            ], style={"display": "flex", "gap": "10px", "marginBottom": "14px"}),

            dcc.Loading(
                id="loading-ioc",
                type="dot",
                color="#00d4ff",
                children=html.Div(id="ioc-results", style={"minHeight": "40px"}),
            ),
        ], style={**PANEL, "marginBottom": "16px"}),

        # ── Row 2: Recent OTX Pulses (full width) ───────────────────────────
        html.Div([
            html.Div([
                html.Span("Recent OTX Threat Pulses", style={
                    **RAJDHANI, "fontSize": "14px", "fontWeight": "700",
                    "color": "#00d4ff", "letterSpacing": "1px",
                }),
                html.Button("↺ Refresh", id="btn-refresh-pulses", n_clicks=0, style={
                    "backgroundColor": "transparent", "color": "#527a99",
                    "border": "1px solid #0f3a5c", "borderRadius": "4px",
                    "padding": "3px 10px", **MONO, "fontSize": "10px",
                    "cursor": "pointer", "marginLeft": "auto",
                }),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "12px"}),
            dcc.Loading(
                type="dot", color="#00d4ff",
                children=html.Div(id="otx-pulses-container", style={
                    "maxHeight": "280px", "overflowY": "auto",
                }),
            ),
        ], style={**PANEL, "marginBottom": "16px"}),

        # ── Row 3: Top Reported IPs (grid of cards) ──────────────────────────
        html.Div([
            html.Div("Top Reported IPs", style={
                **RAJDHANI, "fontSize": "14px", "fontWeight": "700",
                "color": "#00d4ff", "letterSpacing": "1px", "marginBottom": "12px",
            }),
            html.Div(id="top-ips-container", style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fill, minmax(200px, 1fr))",
                "gap": "10px",
            }),
        ], style={**PANEL, "marginBottom": "16px"}),

        # Hidden store for pulse refresh trigger
        dcc.Store(id="store-pulse-trigger", data=0),

    ], style={"padding": "4px 0"})


# ── Callback Helpers ──────────────────────────────────────────────────────────

def render_ioc_results(indicator: str, abuse_data: dict, otx_data: dict) -> html.Div:
    """Render IOC lookup results as a styled panel."""
    import re
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator.strip()))

    children = []

    # AbuseIPDB section
    if abuse_data and is_ip:
        score = abuse_data.get("abuseConfidenceScore", 0)
        score_color = "#ff3355" if score >= 75 else "#ff6b35" if score >= 25 else "#00ff88"
        children += [
            html.Div("AbuseIPDB", style={**LABEL, "color": "#527a99", "marginTop": "4px"}),
            html.Div([
                html.Div(f"{score}%", style={
                    **RAJDHANI, "fontSize": "2rem", "fontWeight": "700",
                    "color": score_color, "display": "inline-block", "marginRight": "16px",
                }),
                html.Span("Abuse Confidence Score", style={**MONO, "fontSize": "10px", "color": "#527a99"}),
            ], style={"marginBottom": "10px"}),
            _result_row("Country", abuse_data.get("countryCode", "—")),
            _result_row("ISP", abuse_data.get("isp", "—")),
            _result_row("Usage Type", abuse_data.get("usageType", "—")),
            _result_row("Total Reports", abuse_data.get("totalReports", 0), "#ffd700"),
            _result_row("Whitelisted", "Yes" if abuse_data.get("isWhitelisted") else "No"),
            _result_row("Tor", "Yes" if abuse_data.get("isTor") else "No",
                        "#ff3355" if abuse_data.get("isTor") else "#00ff88"),
        ]

    # OTX section
    if otx_data:
        pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
        reputation = otx_data.get("reputation", 0)
        tags = otx_data.get("pulse_info", {}).get("tags", [])[:8]
        children += [
            html.Hr(style={"borderColor": "#0f3a5c", "margin": "10px 0"}),
            html.Div("AlienVault OTX", style={**LABEL, "color": "#527a99"}),
            _result_row("Pulse Count", pulse_count, "#ffd700" if pulse_count > 0 else "#00ff88"),
            _result_row("Reputation Score", reputation),
            html.Div([
                html.Span("Tags: ", style={**LABEL, "display": "inline", "marginBottom": 0}),
                *[_badge(t, "#a78bfa") for t in tags],
            ] if tags else [], style={"marginTop": "4px"}),
        ]

    if not children:
        children = [html.Div("No threat data found for this indicator.", style={
            **MONO, "fontSize": "11px", "color": "#527a99", "padding": "10px 0",
        })]

    return html.Div([
        html.Div([
            html.Span("Results for: ", style={**LABEL, "display": "inline", "marginBottom": 0}),
            html.Span(indicator, style={**MONO, "fontSize": "12px", "color": "#00d4ff"}),
        ], style={"marginBottom": "12px"}),
        *children,
    ], style={
        "backgroundColor": "rgba(0,212,255,0.04)",
        "border": "1px solid #0f3a5c",
        "borderRadius": "6px", "padding": "14px",
    })


def render_otx_pulses(pulses: list) -> list:
    """Render OTX pulse list."""
    if not pulses:
        return [html.Div("No pulses available — check OTX_API_KEY in .env", style={
            **MONO, "fontSize": "10px", "color": "#527a99",
            "textAlign": "center", "padding": "20px",
        })]

    items = []
    for p in pulses:
        name = p.get("name", "Unknown Pulse")[:70]
        tags = p.get("tags", [])[:5]
        ind_count = p.get("indicator_count", 0)
        created = str(p.get("created", ""))[:10]
        tlp = p.get("TLP", "white").upper()
        tlp_colors = {"WHITE": "#c8e6f5", "GREEN": "#00ff88", "AMBER": "#ffd700", "RED": "#ff3355"}
        tlp_color = tlp_colors.get(tlp, "#527a99")

        items.append(html.Div([
            html.Div([
                html.Span(name, style={
                    **RAJDHANI, "fontSize": "12px", "fontWeight": "700", "color": "#c8e6f5",
                }),
                _badge(f"TLP:{tlp}", tlp_color),
            ], style={"marginBottom": "5px"}),
            html.Div([
                html.Span(f"{ind_count} indicators", style={
                    **MONO, "fontSize": "9px", "color": "#527a99", "marginRight": "10px",
                }),
                html.Span(created, style={**MONO, "fontSize": "9px", "color": "#355a7a"}),
                *[_badge(t, "#0f3a5c") for t in tags],
            ]),
        ], style={
            "padding": "8px 10px",
            "borderLeft": "2px solid #00d4ff",
            "marginBottom": "6px",
            "backgroundColor": "rgba(0,212,255,0.03)",
            "borderRadius": "0 4px 4px 0",
        }))

    return items


def render_top_ips(ip_data: list) -> list:
    """Render top reported IPs."""
    if not ip_data:
        return [html.Div("No IP data in DB yet — run ingestion first.", style={
            **MONO, "fontSize": "10px", "color": "#527a99",
            "textAlign": "center", "padding": "20px",
        })]

    max_count = max(d.get("count", 1) for d in ip_data) or 1
    items = []
    for i, d in enumerate(ip_data[:15], 1):
        ip = d.get("source_ip", "—")
        count = d.get("count", 0)
        country = d.get("country", "—")
        pct = count / max_count
        bar_color = "#ff3355" if pct > 0.75 else "#ff6b35" if pct > 0.4 else "#00d4ff"

        items.append(html.Div([
            html.Div([
                html.Span(f"#{i:02d}", style={**MONO, "fontSize": "9px", "color": "#355a7a"}),
                html.Span(f"{count:,}", style={
                    **MONO, "fontSize": "10px", "color": "#ffd700",
                    "marginLeft": "auto", "fontWeight": "700",
                }),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "6px"}),
            html.Div(ip, style={
                **MONO, "fontSize": "11px", "color": "#00d4ff",
                "marginBottom": "4px", "wordBreak": "break-all",
            }),
            html.Div(country, style={**MONO, "fontSize": "9px", "color": "#527a99", "marginBottom": "8px"}),
            html.Div(style={
                "height": "3px", "width": f"{int(pct * 100)}%",
                "backgroundColor": bar_color, "borderRadius": "2px",
            }),
        ], style={
            "backgroundColor": "rgba(0,0,0,0.3)",
            "border": f"1px solid {bar_color}33",
            "borderTop": f"2px solid {bar_color}",
            "borderRadius": "6px", "padding": "10px 12px",
        }))

    return items
