"""
charts.py — Module 2: All Core Visualization Functions
Each function takes processed data and returns a Plotly figure.
These are called by the Dash callbacks in the dashboard.

Charts included:
  - Time series (attack frequency over time with anomaly markers)
  - Attack type distribution (bar + donut)
  - Severity distribution (donut)
  - Top attacking countries (horizontal bar)
  - Severity heatmap (country × attack type)
  - CVE severity table / bar
  - Live feed summary stats
"""

import logging
from typing import List, Dict, Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

logger = logging.getLogger(__name__)


# ── Design System ───────────────────────────────────────────────────────────────

COLORS = {
    "bg":           "#050a0f",
    "panel":        "#0a1520",
    "border":       "#0f3a5c",
    "text":         "#c8e6f5",
    "muted":        "#527a99",
    "grid":         "#0e2a40",

    # Severity
    "critical":     "#ff3355",
    "high":         "#ff6b35",
    "medium":       "#ffd700",
    "low":          "#00ff88",

    # Attack types (consistent across all charts)
    "DDoS":         "#ff3355",
    "Ransomware":   "#ff6b35",
    "Malware":      "#ff9500",
    "Phishing":     "#ffd700",
    "Exploit":      "#a78bfa",
    "Brute Force":  "#00d4ff",
    "Port Scan":    "#00ff88",
    "Botnet":       "#ff79c6",
    "Data Breach":  "#ff5555",
    "Unknown":      "#6272a4",
}

SEVERITY_COLORS = {
    "Critical": COLORS["critical"],
    "High":     COLORS["high"],
    "Medium":   COLORS["medium"],
    "Low":      COLORS["low"],
}

FONT_FAMILY = "Rajdhani, Share Tech Mono, monospace"

# Base layout applied to all figures
BASE_LAYOUT = dict(
    paper_bgcolor = COLORS["bg"],
    plot_bgcolor  = COLORS["panel"],
    font          = dict(family=FONT_FAMILY, color=COLORS["text"], size=12),
    margin        = dict(l=16, r=16, t=40, b=16),
    legend        = dict(
        bgcolor     = "rgba(10,21,32,0.9)",
        bordercolor = COLORS["border"],
        borderwidth = 1,
        font        = dict(size=11),
    ),
    xaxis = dict(
        gridcolor    = COLORS["grid"],
        showgrid     = True,
        zeroline     = False,
        tickfont     = dict(size=10),
    ),
    yaxis = dict(
        gridcolor    = COLORS["grid"],
        showgrid     = True,
        zeroline     = False,
        tickfont     = dict(size=10),
    ),
)


def _apply_base(fig: go.Figure, title: str = "") -> go.Figure:
    """Apply base styling to any figure."""
    layout = dict(BASE_LAYOUT)
    if title:
        layout["title"] = dict(
            text      = title,
            font      = dict(size=13, color=COLORS["text"]),
            x         = 0.01,
            xanchor   = "left",
        )
    fig.update_layout(**layout)
    return fig


def _empty_fig(message: str = "No data available") -> go.Figure:
    """Return a styled empty figure with a message."""
    fig = go.Figure()
    fig.add_annotation(
        text      = f'<span style="color:{COLORS["muted"]}">{message}</span>',
        xref      = "paper", yref = "paper",
        x=0.5, y=0.5, showarrow=False,
        font      = dict(size=14, family=FONT_FAMILY),
    )
    return _apply_base(fig)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 1: Time-Series Attack Frequency
# ══════════════════════════════════════════════════════════════════════════════

def build_timeseries_chart(
    hourly_data: List[dict],
    anomaly_hours: Optional[List[str]] = None,
) -> go.Figure:
    """
    Line chart: attacks per hour over time.
    Highlights anomaly spikes with red markers.

    Args:
        hourly_data: Output of database.get_hourly_counts()
            [{"hour": "2026-02-24T10", "count": 17, "avg_severity": 6.2}, ...]
        anomaly_hours: List of hour strings that are anomalies (from anomaly detector)
    """
    if not hourly_data:
        return _empty_fig("No time-series data — run ingestion first")

    df = pd.DataFrame(hourly_data)
    df["hour_dt"] = pd.to_datetime(df["hour"], format="%Y-%m-%dT%H", errors="coerce")
    df = df.dropna(subset=["hour_dt"]).sort_values("hour_dt")

    fig = go.Figure()

    # Main area fill line
    fig.add_trace(go.Scatter(
        x         = df["hour_dt"],
        y         = df["count"],
        mode      = "lines",
        name      = "Attack Count",
        line      = dict(color=COLORS["DDoS"], width=2),
        fill      = "tozeroy",
        fillcolor = "rgba(255,51,85,0.08)",
        hovertemplate = "<b>%{x|%b %d %H:00}</b><br>Attacks: %{y}<extra></extra>",
    ))

    # Average severity line (secondary)
    if "avg_severity" in df.columns:
        fig.add_trace(go.Scatter(
            x         = df["hour_dt"],
            y         = df["avg_severity"],
            mode      = "lines",
            name      = "Avg Severity",
            line      = dict(color=COLORS["medium"], width=1.5, dash="dot"),
            yaxis     = "y2",
            hovertemplate = "<b>%{x|%b %d %H:00}</b><br>Avg Severity: %{y:.1f}<extra></extra>",
        ))

    # Anomaly spike markers
    if anomaly_hours:
        anomaly_df = df[df["hour"].isin(anomaly_hours)]
        if not anomaly_df.empty:
            fig.add_trace(go.Scatter(
                x         = anomaly_df["hour_dt"],
                y         = anomaly_df["count"],
                mode      = "markers",
                name      = "⚠ Anomaly Spike",
                marker    = dict(
                    color  = COLORS["critical"],
                    size   = 12,
                    symbol = "triangle-up",
                    line   = dict(color="white", width=1),
                ),
                hovertemplate = "<b>ANOMALY</b><br>%{x|%b %d %H:00}<br>Count: %{y}<extra></extra>",
            ))

    fig.update_layout(
        yaxis2 = dict(
            overlaying  = "y",
            side        = "right",
            gridcolor   = COLORS["grid"],
            title       = dict(text="Avg Severity", font=dict(size=10, color=COLORS["medium"])),
            tickfont    = dict(size=9, color=COLORS["medium"]),
            range       = [0, 10],
            showgrid    = False,
        ),
        legend = dict(orientation="h", y=-0.2, x=0),
    )

    return _apply_base(fig, "Attack Frequency Over Time")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 2: Attack Type Distribution Bar
# ══════════════════════════════════════════════════════════════════════════════

def build_attack_type_bar(attack_counts: List[dict]) -> go.Figure:
    """
    Horizontal bar chart of attack types sorted by count.
    Args:
        attack_counts: [{"attack_type": "DDoS", "count": 42}, ...]
    """
    if not attack_counts:
        return _empty_fig("No attack type data")

    df = pd.DataFrame(attack_counts).sort_values("count", ascending=True)

    fig = go.Figure(go.Bar(
        y         = df["attack_type"],
        x         = df["count"],
        orientation = "h",
        marker    = dict(
            color = [COLORS.get(t, COLORS["Unknown"]) for t in df["attack_type"]],
            line  = dict(color="rgba(255,255,255,0.05)", width=1),
        ),
        text      = df["count"],
        textposition = "outside",
        textfont  = dict(size=11, color=COLORS["text"]),
        hovertemplate = "<b>%{y}</b><br>Count: %{x}<extra></extra>",
    ))

    fig.update_layout(
        xaxis = dict(showgrid=True, gridcolor=COLORS["grid"]),
        yaxis = dict(showgrid=False),
    )

    return _apply_base(fig, "Attack Distribution by Type")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 3: Severity Donut
# ══════════════════════════════════════════════════════════════════════════════

def build_severity_donut(severity_data: List[dict]) -> go.Figure:
    """
    Donut chart of attack counts by severity level.
    Args:
        severity_data: [{"severity": "High", "count": 28}, ...]
    """
    if not severity_data:
        return _empty_fig("No severity data")

    df = pd.DataFrame(severity_data)

    # Ensure consistent severity ordering
    severity_order = ["Critical", "High", "Medium", "Low"]
    df["severity"] = pd.Categorical(df["severity"], categories=severity_order, ordered=True)
    df = df.sort_values("severity")

    fig = go.Figure(go.Pie(
        labels    = df["severity"],
        values    = df["count"],
        hole      = 0.55,
        marker    = dict(
            colors = [SEVERITY_COLORS.get(s, "#6272a4") for s in df["severity"]],
            line   = dict(color=COLORS["bg"], width=3),
        ),
        textinfo  = "label+percent",
        textfont  = dict(size=11),
        hovertemplate = "<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
    ))

    # Center annotation
    total = df["count"].sum()
    fig.add_annotation(
        text      = f"<b>{total}</b><br><span style='font-size:10px'>events</span>",
        x=0.5, y=0.5, showarrow=False,
        font      = dict(size=16, color=COLORS["text"]),
    )

    fig.update_layout(
        showlegend = True,
        legend     = dict(orientation="h", y=-0.1),
    )

    return _apply_base(fig, "Severity Distribution")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 4: Attack Type Donut (companion to bar)
# ══════════════════════════════════════════════════════════════════════════════

def build_attack_type_donut(attack_counts: List[dict]) -> go.Figure:
    """
    Donut variant of attack type distribution.
    Good for dashboard summary widget.
    """
    if not attack_counts:
        return _empty_fig("No data")

    df = pd.DataFrame(attack_counts)

    fig = go.Figure(go.Pie(
        labels    = df["attack_type"],
        values    = df["count"],
        hole      = 0.5,
        marker    = dict(
            colors = [COLORS.get(t, COLORS["Unknown"]) for t in df["attack_type"]],
            line   = dict(color=COLORS["bg"], width=2),
        ),
        textinfo  = "percent",
        textfont  = dict(size=10),
        hovertemplate = "<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(showlegend=True, legend=dict(font=dict(size=10)))
    return _apply_base(fig, "Attack Types")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 5: Top Countries Bar
# ══════════════════════════════════════════════════════════════════════════════

def build_top_countries_bar(country_data: List[dict], top_n: int = 15) -> go.Figure:
    """
    Horizontal bar chart of top attack-originating countries.
    Color-encodes average severity.

    Args:
        country_data: Output of database.get_country_counts()
    """
    if not country_data:
        return _empty_fig("No geographic data")

    df = pd.DataFrame(country_data)
    df = df[df["country"].notna() & (df["country"] != "None") & (df["country"] != "")]
    if df.empty:
        return _empty_fig("No geographic data")
    df = df.head(top_n).sort_values("count", ascending=True)

    # Color by avg severity (green → red scale)
    colors = []
    for _, row in df.iterrows():
        sev = row.get("avg_severity", 5)
        if sev >= 8:   colors.append(COLORS["critical"])
        elif sev >= 6: colors.append(COLORS["high"])
        elif sev >= 4: colors.append(COLORS["medium"])
        else:          colors.append(COLORS["low"])

    max_count = df["count"].max() if not df.empty else 1

    fig = go.Figure(go.Bar(
        y           = df["country"],
        x           = df["count"],
        orientation = "h",
        marker      = dict(color=colors, line=dict(color="rgba(255,255,255,0.05)", width=1)),
        text        = [f"{row['count']:,}  (avg sev: {row.get('avg_severity', 0):.1f})" for _, row in df.iterrows()],
        textposition= "inside",
        insidetextanchor = "end",
        textfont    = dict(size=10, color="#ffffff"),
        hovertemplate = "<b>%{y}</b><br>Events: %{x:,}<extra></extra>",
    ))

    fig.update_layout(
        yaxis  = dict(showgrid=False, automargin=True),
        xaxis  = dict(range=[0, max_count * 1.05]),
        margin = dict(l=120, r=24, t=40, b=16),
    )
    return _apply_base(fig, "Top Attack Source Countries")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 6: Severity Heatmap (Country × Attack Type)
# ══════════════════════════════════════════════════════════════════════════════

def build_severity_heatmap(events_data: List[dict], top_countries: int = 12) -> go.Figure:
    """
    Heatmap: rows = countries, columns = attack types, cell = average severity.
    Highlights exactly which countries are most dangerous for each attack type.
    """
    if not events_data:
        return _empty_fig("No data for heatmap")

    df = pd.DataFrame(events_data)
    required = {"source_geo", "attack_type", "severity_score"}

    # Flatten nested geo for convenience
    if "source_geo" in df.columns:
        df["country"] = df["source_geo"].apply(
            lambda g: g.get("country", "Unknown") if isinstance(g, dict) else "Unknown"
        )
    elif "country" not in df.columns:
        return _empty_fig("Geo data missing")

    df = df[df["country"] != "Unknown"]
    if df.empty:
        return _empty_fig("No country data in events")

    # Keep top N countries by event count
    top = df["country"].value_counts().head(top_countries).index.tolist()
    df  = df[df["country"].isin(top)]

    pivot = df.pivot_table(
        index   = "country",
        columns = "attack_type",
        values  = "severity_score",
        aggfunc = "mean"
    ).round(1).fillna(0)

    fig = go.Figure(go.Heatmap(
        z         = pivot.values,
        x         = pivot.columns.tolist(),
        y         = pivot.index.tolist(),
        colorscale= [
            [0.0,  COLORS["panel"]],
            [0.3,  "#1a5c2a"],
            [0.6,  COLORS["medium"]],
            [0.8,  COLORS["high"]],
            [1.0,  COLORS["critical"]],
        ],
        zmin      = 0,
        zmax      = 10,
        colorbar  = dict(
            title     = "Avg Severity",
            titlefont = dict(size=10, color=COLORS["muted"]),
            tickfont  = dict(size=9, color=COLORS["muted"]),
            outlinewidth=0,
        ),
        hovertemplate = "<b>%{y}</b> × <b>%{x}</b><br>Avg Severity: %{z}<extra></extra>",
        text      = pivot.values.astype(str),
        texttemplate = "%{z}",
        textfont  = dict(size=9),
    ))

    fig.update_layout(
        xaxis=dict(side="bottom", tickangle=-30, showgrid=False),
        yaxis=dict(showgrid=False),
    )

    return _apply_base(fig, "Severity Heatmap: Country × Attack Type")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 7: CVE Severity Bar
# ══════════════════════════════════════════════════════════════════════════════

def build_cve_chart(cve_data: List[dict], top_n: int = 20) -> go.Figure:
    """
    Horizontal bar of top CVEs by CVSS score.
    Shows CVE ID, score, and severity color.
    """
    if not cve_data:
        return _empty_fig("No CVE data — run NVD ingestion first")

    df = pd.DataFrame(cve_data).head(top_n)
    if "cvss_score" not in df.columns or df.empty:
        return _empty_fig("CVE CVSS data missing")

    df = df.sort_values("cvss_score", ascending=True)

    colors = []
    for score in df["cvss_score"]:
        if score >= 9.0:   colors.append(COLORS["critical"])
        elif score >= 7.0: colors.append(COLORS["high"])
        elif score >= 4.0: colors.append(COLORS["medium"])
        else:              colors.append(COLORS["low"])

    hover_texts = []
    for _, row in df.iterrows():
        product = row.get("affected_product") or "N/A"
        vendor  = row.get("affected_vendor")  or "N/A"
        desc    = (row.get("description") or "")[:100]
        hover_texts.append(f"<b>{row['cve_id']}</b><br>{vendor}/{product}<br>{desc}")

    fig = go.Figure(go.Bar(
        y           = df["cve_id"],
        x           = df["cvss_score"],
        orientation = "h",
        marker      = dict(color=colors, line=dict(color="rgba(255,255,255,0.05)", width=1)),
        text        = df["cvss_score"].round(1),
        textposition= "outside",
        textfont    = dict(size=10, color=COLORS["text"]),
        hovertext   = hover_texts,
        hoverinfo   = "text",
    ))

    fig.update_layout(
        xaxis = dict(range=[0, 11], showgrid=True, gridcolor=COLORS["grid"]),
        yaxis = dict(showgrid=False, tickfont=dict(size=9)),
    )

    return _apply_base(fig, f"Top {top_n} CVEs by CVSS Score")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 8: Multi-Attack Trend (stacked area)
# ══════════════════════════════════════════════════════════════════════════════

def build_stacked_trend_from_hourly(hourly_type_data: List[dict]) -> go.Figure:
    """
    Stacked area chart built from pre-aggregated hourly-by-type data.
    Much more accurate than using raw events (no 500-event cap).
    Input: [{"hour": "2026-02-25T14", "attack_type": "DDoS", "count": 5}, ...]
    """
    if not hourly_type_data:
        return _empty_fig("No trend data")

    df = pd.DataFrame(hourly_type_data)
    if "hour" not in df.columns or "attack_type" not in df.columns:
        return _empty_fig("Missing required fields")

    df["hour"] = pd.to_datetime(df["hour"], format="%Y-%m-%dT%H", errors="coerce")
    df = df.dropna(subset=["hour"])
    pivot = df.pivot_table(index="hour", columns="attack_type", values="count", aggfunc="sum", fill_value=0)

    fig = go.Figure()
    for attack_type in pivot.columns:
        color = COLORS.get(attack_type, COLORS["Unknown"])
        fill  = color.replace(")", ", 0.6)").replace("rgb", "rgba") if color.startswith("rgb") else color
        fig.add_trace(go.Scatter(
            x             = pivot.index,
            y             = pivot[attack_type],
            mode          = "lines",
            name          = attack_type,
            stackgroup    = "one",
            line          = dict(width=0.5, color=color),
            fillcolor     = fill,
            hovertemplate = f"<b>{attack_type}</b><br>%{{x|%b %d %H:00}}<br>Count: %{{y}}<extra></extra>",
        ))

    fig.update_layout(legend=dict(orientation="h", y=-0.2, font=dict(size=9)))
    return _apply_base(fig, "Attack Volume by Type Over Time (Stacked)")


def build_stacked_trend(events_data: List[dict]) -> go.Figure:
    """
    Stacked area chart: attack volume per type over the last 24h.
    Shows how different attack types trend relative to each other.
    """
    if not events_data:
        return _empty_fig("No event data")

    df = pd.DataFrame(events_data)
    if "timestamp" not in df.columns or "attack_type" not in df.columns:
        return _empty_fig("Missing required fields")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df["hour"] = df["timestamp"].dt.floor("H")

    pivot = df.groupby(["hour", "attack_type"]).size().unstack(fill_value=0)

    fig = go.Figure()
    for attack_type in pivot.columns:
        fig.add_trace(go.Scatter(
            x         = pivot.index,
            y         = pivot[attack_type],
            mode      = "lines",
            name      = attack_type,
            stackgroup= "one",
            line      = dict(width=0.5, color=COLORS.get(attack_type, COLORS["Unknown"])),
            fillcolor = COLORS.get(attack_type, COLORS["Unknown"]).replace(")", ", 0.6)").replace("rgb", "rgba") if COLORS.get(attack_type, "").startswith("rgb") else COLORS.get(attack_type, COLORS["Unknown"]),
            hovertemplate = f"<b>{attack_type}</b><br>%{{x|%H:00}}<br>Count: %{{y}}<extra></extra>",
        ))

    fig.update_layout(legend=dict(orientation="h", y=-0.2, font=dict(size=9)))
    return _apply_base(fig, "Attack Volume by Type Over Time (Stacked)")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CHART 9: KPI Summary Cards (returns dict, not a figure)
# ══════════════════════════════════════════════════════════════════════════════

def compute_kpi_stats(
    events_data: List[dict],
    prev_events_data: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """
    Compute KPI numbers for the top summary cards.
    Returns a dict used by the dashboard layout to update stat cards.
    """
    if not events_data:
        return {
            "total_events":    0,
            "critical_count":  0,
            "unique_countries":0,
            "avg_severity":    0.0,
            "top_attack_type": "N/A",
            "top_country":     "N/A",
        }

    df = pd.DataFrame(events_data)

    total     = len(df)
    critical  = len(df[df.get("severity", pd.Series()) == "Critical"]) if "severity" in df else 0
    avg_sev   = round(df["severity_score"].mean(), 1) if "severity_score" in df else 0.0

    # Top attack type
    top_type = "N/A"
    if "attack_type" in df:
        top_type = df["attack_type"].value_counts().idxmax()

    # Top country from nested geo
    top_country = "N/A"
    if "source_geo" in df:
        countries = df["source_geo"].apply(
            lambda g: g.get("country") if isinstance(g, dict) else None
        ).dropna()
        if not countries.empty:
            top_country   = countries.value_counts().idxmax()
            unique_ctry   = countries.nunique()
        else:
            unique_ctry = 0
    else:
        unique_ctry = 0

    return {
        "total_events":     total,
        "critical_count":   critical,
        "unique_countries": unique_ctry,
        "avg_severity":     avg_sev,
        "top_attack_type":  top_type,
        "top_country":      top_country,
    }
