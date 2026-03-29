"""
report_generator.py — PDF Report Generator (Module 4)
Generates an executive-ready PDF report from current dashboard data.
Includes summary stats, all key charts as images, CVE table, and recommendations.

Dependencies: kaleido (chart export) + reportlab (PDF assembly)
Both are in requirements.txt

Usage:
    from dashboard.report_generator import generate_pdf_report
    pdf_path = generate_pdf_report(hours_back=24)
"""

import logging
import os
import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── ReportLab imports ──────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import cm, mm
    from reportlab.lib.colors import (
        HexColor, white, black
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        Image, PageBreak, HRFlowable, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable
    REPORTLAB_OK = True

    # ── Design colors (defined here so HexColor is in scope) ───────────────────
    C_BG       = HexColor("#050a0f")
    C_PANEL    = HexColor("#0a1520")
    C_CYAN     = HexColor("#00d4ff")
    C_GREEN    = HexColor("#00ff88")
    C_RED      = HexColor("#ff3355")
    C_ORANGE   = HexColor("#ff6b35")
    C_YELLOW   = HexColor("#ffd700")
    C_PURPLE   = HexColor("#a78bfa")
    C_TEXT     = HexColor("#c8e6f5")
    C_MUTED    = HexColor("#527a99")
    C_DARK     = HexColor("#0a1520")
    C_BORDER   = HexColor("#0f3a5c")

except ImportError:
    REPORTLAB_OK = False
    logger.warning("reportlab not installed — run: pip install reportlab")
    # Stub colors so module-level references don't raise NameError
    C_BG = C_PANEL = C_CYAN = C_GREEN = C_RED = C_ORANGE = None
    C_YELLOW = C_PURPLE = C_TEXT = C_MUTED = C_DARK = C_BORDER = None

# ── Kaleido for chart export ───────────────────────────────────────────────────
try:
    import kaleido  # noqa — just checking it's installed
    KALEIDO_OK = True
except ImportError:
    KALEIDO_OK = False
    logger.warning("kaleido not installed — run: pip install kaleido")

SEVERITY_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_YELLOW,
    "Low":      C_GREEN,
}


def _export_chart_as_image(fig, width_px: int = 900, height_px: int = 400) -> Optional[bytes]:
    """
    Export a Plotly figure to PNG bytes using kaleido.
    Returns None if kaleido is not available.
    """
    if not KALEIDO_OK:
        return None
    try:
        return fig.to_image(format="png", width=width_px, height=height_px, scale=1.5)
    except Exception as e:
        logger.warning(f"Chart export failed: {e}")
        return None


def generate_pdf_report(
    hours_back:  int  = 24,
    attack_type: str  = None,
    severity:    str  = None,
    output_path: str  = None,
) -> Optional[str]:
    """
    Generate a complete executive PDF report.

    Args:
        hours_back:  Time window for report data (default 24h)
        output_path: Where to save the PDF. If None, saves to /tmp/

    Returns:
        Path to the generated PDF file, or None if generation failed.
    """
    if not REPORTLAB_OK:
        logger.error("reportlab not installed — cannot generate PDF")
        return None

    # ── Load data ──────────────────────────────────────────────────────────
    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

        from config.database import (
            get_recent_events, get_attack_type_counts,
            get_hourly_counts, get_country_counts,
            get_top_cves, get_severity_distribution,
            get_mitre_technique_counts, get_event_count,
            get_avg_severity_score,
        )
        from visualizations.charts import (
            build_timeseries_chart, build_attack_type_bar,
            build_severity_donut, build_top_countries_bar,
            compute_kpi_stats,
        )
        from visualizations.geo_charts import (
            build_choropleth_map, build_mitre_treemap,
        )

        events        = get_recent_events(limit=500, hours_back=hours_back,
                                          attack_type=attack_type, severity=severity)
        hourly        = get_hourly_counts(hours_back=hours_back)
        country       = get_country_counts(hours_back=hours_back,
                                           attack_type=attack_type, severity=severity)
        attack_counts = get_attack_type_counts(hours_back=hours_back,
                                               attack_type=attack_type, severity=severity)
        severity_data = get_severity_distribution(hours_back=hours_back,
                                                  attack_type=attack_type, severity=severity)
        cves          = get_top_cves(limit=15)
        mitre_data    = get_mitre_technique_counts(hours_back=hours_back,
                                                   attack_type=attack_type, severity=severity)

        # Accurate KPIs — all from full DB aggregations, not the 500-event sample
        total_events   = get_event_count(hours_back=hours_back,
                                         attack_type=attack_type, severity=severity)
        avg_sev        = get_avg_severity_score(hours_back=hours_back,
                                                attack_type=attack_type, severity=severity)
        critical_count = next((s["count"] for s in severity_data
                                if s.get("severity") == "Critical"), 0)
        high_count     = next((s["count"] for s in severity_data
                                if s.get("severity") == "High"), 0)
        country_count  = len(country)
        top_attack     = attack_counts[0]["attack_type"] if attack_counts else "N/A"

        kpis = compute_kpi_stats(events)  # still used for recommendations logic

    except Exception as e:
        logger.error(f"Failed to load data for report: {e}")
        return None

    # ── Output path ────────────────────────────────────────────────────────
    if output_path is None:
        ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        output_path = os.path.join(tempfile.gettempdir(), f"threat_report_{ts}.pdf")

    # ── Build PDF ──────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize    = A4,
        leftMargin  = 1.5 * cm,
        rightMargin = 1.5 * cm,
        topMargin   = 1.5 * cm,
        bottomMargin= 1.5 * cm,
    )

    story = []
    styles = _build_styles()
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC")

    # ══ PAGE 1: Cover ══════════════════════════════════════════════════════

    story.append(Spacer(1, 2 * cm))

    # Title block
    story.append(Paragraph("CYBER THREAT INTELLIGENCE", styles["label"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Executive Security Report", styles["cover_title"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Reporting Period: Last {hours_back} Hours", styles["cover_sub"]))
    if attack_type or severity:
        filters_str = "  |  ".join(filter(None, [
            f"Attack Type: {attack_type}" if attack_type else None,
            f"Severity: {severity}"       if severity    else None,
        ]))
        story.append(Paragraph(f"Active Filters: {filters_str}", styles["cover_sub"]))
    story.append(Paragraph(f"Generated: {now_str}", styles["cover_sub"]))

    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
    story.append(Spacer(1, 0.8 * cm))

    # ── KPI Summary Table ──────────────────────────────────────────────────
    story.append(Paragraph("KEY METRICS", styles["section_label"]))
    story.append(Spacer(1, 0.3 * cm))

    kpi_data = [
        ["Total Events", "Critical Events", "Countries", "Avg Severity", "Top Attack Type"],
        [
            f"{total_events:,}",
            f"{critical_count:,}",
            str(country_count),
            str(avg_sev),
            top_attack,
        ]
    ]

    kpi_table = Table(kpi_data, colWidths=[3.5 * cm] * 5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
        ("BACKGROUND",  (0, 1), (-1, 1), C_PANEL),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_MUTED),
        ("TEXTCOLOR",   (0, 1), (-1, 1), C_CYAN),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, 0), 7),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (-1, 1), 14),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_PANEL]),
        ("BOX",         (0, 0), (-1, -1), 1, C_BORDER),
        ("INNERGRID",   (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.8 * cm))

    # ── Severity distribution — visual bar chart (native ReportLab, no kaleido) ──
    if severity_data:
        story.append(Paragraph("SEVERITY DISTRIBUTION", styles["section_label"]))
        story.append(Spacer(1, 0.4 * cm))
        for item in _build_severity_bars(severity_data):
            story.append(item)

    story.append(PageBreak())

    # ══ PAGE 2: Attack Analysis ════════════════════════════════════════════

    story.append(Paragraph("ATTACK TYPE BREAKDOWN", styles["section_title"]))
    story.append(Spacer(1, 0.4 * cm))

    # Attack type visual bar chart (native ReportLab, no kaleido)
    if attack_counts:
        story.append(Paragraph("EVENTS BY ATTACK TYPE", styles["section_label"]))
        story.append(Spacer(1, 0.3 * cm))
        for item in _build_attack_bars(attack_counts):
            story.append(item)
        story.append(Spacer(1, 0.8 * cm))

    # Time-series chart (kaleido — optional, skipped if not installed)
    try:
        fig_ts  = build_timeseries_chart(hourly)
        img_ts  = _export_chart_as_image(fig_ts, 900, 320)
        if img_ts:
            story.append(Paragraph("ATTACK FREQUENCY OVER TIME", styles["section_label"]))
            story.append(Spacer(1, 0.3 * cm))
            story.append(Image(io.BytesIO(img_ts), width=17 * cm, height=6 * cm))
            story.append(Paragraph(
                "Figure 1: Attack frequency over the reporting period. Spikes indicate potential coordinated attack waves.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Time series chart failed: {e}")

    story.append(PageBreak())

    # ══ PAGE 3: Geographic Analysis ════════════════════════════════════════

    story.append(Paragraph("GEOGRAPHIC THREAT ANALYSIS", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    try:
        fig_map = build_choropleth_map(country)
        img_map = _export_chart_as_image(fig_map, 900, 400)
        if img_map:
            story.append(Image(io.BytesIO(img_map), width=17 * cm, height=7.5 * cm))
            story.append(Paragraph(
                "Figure 4: Global attack origin map. Darker regions indicate higher threat event volume.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Map chart failed: {e}")

    story.append(Spacer(1, 0.5 * cm))

    # Top countries table
    if country:
        story.append(Paragraph("TOP ATTACK SOURCE COUNTRIES", styles["section_label"]))
        story.append(Spacer(1, 0.3 * cm))

        ctry_rows = [["Rank", "Country", "Country Code", "Events", "Avg Severity"]]
        for i, c in enumerate(country[:10], 1):
            ctry_rows.append([
                str(i),
                c.get("country", "Unknown"),
                c.get("country_code", "??"),
                str(c.get("count", 0)),
                f"{c.get('avg_severity', 0):.1f}",
            ])

        ctry_table = Table(ctry_rows, colWidths=[1.5*cm, 5*cm, 3*cm, 3*cm, 4.5*cm])
        ctry_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",    (0, 0), (-1, 0), C_MUTED),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("BOX",          (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_DARK]),
            ("TEXTCOLOR",    (0, 1), (-1, -1), C_TEXT),
            ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ]))
        story.append(ctry_table)

    story.append(PageBreak())

    # ══ PAGE 4: MITRE ATT&CK ═══════════════════════════════════════════════

    story.append(Paragraph("MITRE ATT&amp;CK COVERAGE", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    if mitre_data:
        story.append(Paragraph("TOP TECHNIQUES BY EVENT VOLUME", styles["section_label"]))
        story.append(Spacer(1, 0.3 * cm))
        for item in _build_mitre_bars(mitre_data, top_n=15):
            story.append(item)

        # Tactic legend
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("TACTIC COLOUR KEY", styles["section_label"]))
        story.append(Spacer(1, 0.2 * cm))
        story.append(_build_mitre_legend())
    else:
        story.append(Paragraph(
            "No MITRE ATT&amp;CK technique data available for this reporting period.",
            styles["caption"]
        ))

    story.append(PageBreak())

    # ══ PAGE 5: CVE Intelligence ════════════════════════════════════════════

    story.append(Paragraph("CRITICAL VULNERABILITY INTELLIGENCE", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    if cves:
        # Paragraph styles for wrapping table cells
        hdr_ps  = ParagraphStyle("ch", fontName="Helvetica",      fontSize=7,   textColor=C_MUTED, leading=9)
        id_ps   = ParagraphStyle("ci", fontName="Helvetica-Bold", fontSize=7.5, textColor=C_TEXT,  leading=9)
        cell_ps = ParagraphStyle("cc", fontName="Helvetica",      fontSize=7.5, textColor=C_TEXT,  leading=9)

        # Column widths — total = 18 cm (full usable width)
        COL_W = [3.0*cm, 1.2*cm, 1.6*cm, 2.2*cm, 2.2*cm, 7.8*cm]

        cve_rows = [[
            Paragraph("CVE ID",      hdr_ps),
            Paragraph("CVSS",        hdr_ps),
            Paragraph("Sev",         hdr_ps),
            Paragraph("Vendor",      hdr_ps),
            Paragraph("Product",     hdr_ps),
            Paragraph("Description", hdr_ps),
        ]]

        sev_colors = []  # (row_index, color) for severity column colouring
        for idx, cve in enumerate(cves[:12], 1):
            score = cve.get("cvss_score") or 0
            sev   = (cve.get("cvss_severity") or "N/A").capitalize()
            desc  = (cve.get("description") or "")[:160]
            color = C_RED if score >= 9 else C_ORANGE if score >= 7 else C_YELLOW if score >= 4 else C_GREEN
            sev_colors.append((idx, color))

            sev_ps = ParagraphStyle(f"cs{idx}", fontName="Helvetica-Bold", fontSize=7.5,
                                    textColor=color, leading=9)
            cve_rows.append([
                Paragraph(cve.get("cve_id", ""),                           id_ps),
                Paragraph(f"{score:.1f}" if score else "N/A",              ParagraphStyle(f"cv{idx}", fontName="Helvetica-Bold", fontSize=7.5, textColor=color, leading=9, alignment=1)),
                Paragraph(sev,                                             sev_ps),
                Paragraph((cve.get("affected_vendor")  or "N/A")[:16],    cell_ps),
                Paragraph((cve.get("affected_product") or "N/A")[:18],    cell_ps),
                Paragraph(desc,                                            cell_ps),
            ])

        cve_table = Table(cve_rows, colWidths=COL_W, repeatRows=1)
        cve_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_DARK),
            ("BACKGROUND",    (0, 1), (-1, -1), C_PANEL),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_DARK]),
            ("BOX",           (0, 0), (-1, -1), 1,   C_BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(cve_table)
        story.append(Spacer(1, 0.5 * cm))

    # ══ PAGE 6: Recommendations ═════════════════════════════════════════════

    story.append(PageBreak())
    story.append(Paragraph("SECURITY RECOMMENDATIONS", styles["section_title"]))
    story.append(Spacer(1, 0.5 * cm))

    recommendations = _generate_recommendations(kpis, attack_counts, cves)
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec['title']}", styles["rec_title"]))
        story.append(Paragraph(rec["detail"], styles["rec_detail"]))
        story.append(Spacer(1, 0.4 * cm))

    # Footer
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"This report was automatically generated by the Cyber Threat Visualization Dashboard on {now_str}. "
        f"Data sourced from NVD CVE Feed, AlienVault OTX, and AbuseIPDB.",
        styles["footer"]
    ))

    # ── Build PDF ──────────────────────────────────────────────────────────
    try:
        doc.build(story, onFirstPage=_page_template, onLaterPages=_page_template)
        logger.info(f"PDF report generated: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"PDF build failed: {e}")
        return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    """Return all custom paragraph styles for the report."""
    return {
        "label": ParagraphStyle("label",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=4, letterSpacing=3, alignment=TA_LEFT,
        ),
        "cover_title": ParagraphStyle("cover_title",
            fontName="Helvetica-Bold", fontSize=28, textColor=C_CYAN,
            spaceAfter=8, leading=32,
        ),
        "cover_sub": ParagraphStyle("cover_sub",
            fontName="Helvetica", fontSize=11, textColor=C_MUTED,
            spaceAfter=4,
        ),
        "section_title": ParagraphStyle("section_title",
            fontName="Helvetica-Bold", fontSize=14, textColor=C_CYAN,
            spaceAfter=8,
        ),
        "section_label": ParagraphStyle("section_label",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=4, letterSpacing=2,
        ),
        "caption": ParagraphStyle("caption",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=8, spaceBefore=4, alignment=TA_CENTER,
        ),
        "rec_title": ParagraphStyle("rec_title",
            fontName="Helvetica-Bold", fontSize=11, textColor=C_CYAN,
            spaceAfter=3,
        ),
        "rec_detail": ParagraphStyle("rec_detail",
            fontName="Helvetica", fontSize=9, textColor=C_TEXT,
            spaceAfter=4, leftIndent=12, leading=14,
        ),
        "footer": ParagraphStyle("footer",
            fontName="Helvetica", fontSize=7, textColor=C_MUTED,
            alignment=TA_CENTER,
        ),
    }


def _build_severity_bars(severity_data: list) -> list:
    """
    Native ReportLab horizontal bar chart for severity distribution.
    No kaleido or matplotlib needed — pure ReportLab Tables.
    Each row: [Label | Filled bar | Empty remainder | Count | Pct%]
    """
    ORDER  = ["Critical", "High", "Medium", "Low"]
    COLORS = {
        "Critical": HexColor("#ff3355"),
        "High":     HexColor("#ff6b35"),
        "Medium":   HexColor("#ffd700"),
        "Low":      HexColor("#00ff88"),
    }
    total = sum(s.get("count", 0) for s in severity_data)
    if not total:
        return []

    sorted_data = sorted(
        severity_data,
        key=lambda x: ORDER.index(x.get("severity", "Low"))
        if x.get("severity") in ORDER else 99,
    )

    LABEL_W = 2.5 * cm
    BAR_MAX = 9.5 * cm   # max bar fills this width at 100%
    COUNT_W = 2.0 * cm
    PCT_W   = 1.5 * cm

    items = []
    for s in sorted_data:
        sev   = s.get("severity", "?")
        count = s.get("count", 0)
        pct   = count / total
        color = COLORS.get(sev, HexColor("#527a99"))

        bar_filled = max(0.25 * cm, pct * BAR_MAX)
        bar_empty  = BAR_MAX - bar_filled

        row_table = Table(
            [[sev, "", "", f"{count:,}", f"{pct * 100:.1f}%"]],
            colWidths=[LABEL_W, bar_filled, bar_empty, COUNT_W, PCT_W],
        )
        row_table.setStyle(TableStyle([
            # Label cell
            ("BACKGROUND",    (0, 0), (0, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (0, 0), color),
            ("FONTNAME",      (0, 0), (0, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (0, 0), 10),
            ("ALIGN",         (0, 0), (0, 0), "RIGHT"),
            ("RIGHTPADDING",  (0, 0), (0, 0), 8),
            # Filled bar
            ("BACKGROUND",    (1, 0), (1, 0), color),
            ("LEFTPADDING",   (1, 0), (1, 0), 0),
            ("RIGHTPADDING",  (1, 0), (1, 0), 0),
            # Empty bar remainder
            ("BACKGROUND",    (2, 0), (2, 0), HexColor("#0d1e2e")),
            ("LEFTPADDING",   (2, 0), (2, 0), 0),
            ("RIGHTPADDING",  (2, 0), (2, 0), 0),
            # Count + pct cells
            ("BACKGROUND",    (3, 0), (4, 0), C_DARK),
            ("TEXTCOLOR",     (3, 0), (4, 0), C_TEXT),
            ("FONTNAME",      (3, 0), (4, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (3, 0), (4, 0), 10),
            ("ALIGN",         (3, 0), (4, 0), "CENTER"),
            # Row height & padding
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (0, 0), 4),
            ("INNERGRID",     (0, 0), (-1, -1), 0, white),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#0f3a5c")),
        ]))
        items.append(row_table)
        items.append(Spacer(1, 3))

    return items


def _build_attack_bars(attack_counts: list, top_n: int = 10) -> list:
    """
    Native ReportLab horizontal bar chart for attack type distribution.
    Same approach as severity bars — pure ReportLab, no kaleido.
    """
    BAR_COLOR = HexColor("#00d4ff")
    sorted_data = sorted(attack_counts, key=lambda x: x.get("count", 0), reverse=True)[:top_n]
    max_count   = max((a.get("count", 0) for a in sorted_data), default=1)

    LABEL_W = 3.5 * cm
    BAR_MAX = 9.5 * cm
    COUNT_W = 2.5 * cm

    items = []
    for a in sorted_data:
        label = a.get("attack_type", "Unknown")
        count = a.get("count", 0)
        pct   = count / max_count if max_count else 0

        bar_filled = max(0.2 * cm, pct * BAR_MAX)
        bar_empty  = BAR_MAX - bar_filled

        row_table = Table(
            [[label, "", "", f"{count:,}"]],
            colWidths=[LABEL_W, bar_filled, bar_empty, COUNT_W],
        )
        row_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (0, 0), C_TEXT),
            ("FONTNAME",      (0, 0), (0, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (0, 0), 9),
            ("ALIGN",         (0, 0), (0, 0), "RIGHT"),
            ("RIGHTPADDING",  (0, 0), (0, 0), 8),
            ("BACKGROUND",    (1, 0), (1, 0), BAR_COLOR),
            ("LEFTPADDING",   (1, 0), (1, 0), 0),
            ("RIGHTPADDING",  (1, 0), (1, 0), 0),
            ("BACKGROUND",    (2, 0), (2, 0), HexColor("#0d1e2e")),
            ("LEFTPADDING",   (2, 0), (2, 0), 0),
            ("RIGHTPADDING",  (2, 0), (2, 0), 0),
            ("BACKGROUND",    (3, 0), (3, 0), C_DARK),
            ("TEXTCOLOR",     (3, 0), (3, 0), C_MUTED),
            ("FONTNAME",      (3, 0), (3, 0), "Helvetica"),
            ("FONTSIZE",      (3, 0), (3, 0), 9),
            ("ALIGN",         (3, 0), (3, 0), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("INNERGRID",     (0, 0), (-1, -1), 0, white),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#0f3a5c")),
        ]))
        items.append(row_table)
        items.append(Spacer(1, 3))

    return items


MITRE_TACTIC_COLORS = {
    "Initial Access":       HexColor("#ff3355"),
    "Execution":            HexColor("#ff6b35"),
    "Persistence":          HexColor("#ffd700"),
    "Privilege Escalation": HexColor("#a78bfa"),
    "Defense Evasion":      HexColor("#00ff88"),
    "Credential Access":    HexColor("#00d4ff"),
    "Discovery":            HexColor("#7dd3fc"),
    "Lateral Movement":     HexColor("#f472b6"),
    "Collection":           HexColor("#fb923c"),
    "Command and Control":  HexColor("#34d399"),
    "Exfiltration":         HexColor("#f87171"),
    "Impact":               HexColor("#e879f9"),
}


def _build_mitre_bars(mitre_data: list, top_n: int = 15) -> list:
    """
    Native ReportLab bar chart for MITRE ATT&CK top techniques.
    Columns: [TechID | Technique Name | filled bar | empty | count]
    Bar color = tactic color.  No kaleido needed.
    """
    sorted_data = sorted(mitre_data, key=lambda x: x.get("count", 0), reverse=True)[:top_n]
    max_count   = max((a.get("count", 0) for a in sorted_data), default=1)

    ID_W    = 1.5 * cm
    LABEL_W = 4.5 * cm
    BAR_MAX = 7.5 * cm
    COUNT_W = 2.0 * cm

    items = []
    for a in sorted_data:
        tech_id   = (a.get("technique_id") or "")[:10]
        technique = (a.get("technique")    or "Unknown")[:28]
        tactic    = a.get("tactic", "")
        count     = a.get("count", 0)
        pct       = count / max_count if max_count else 0
        color     = MITRE_TACTIC_COLORS.get(tactic, HexColor("#527a99"))

        bar_filled = max(0.2 * cm, pct * BAR_MAX)
        bar_empty  = BAR_MAX - bar_filled

        row = Table(
            [[tech_id, technique, "", "", f"{count:,}"]],
            colWidths=[ID_W, LABEL_W, bar_filled, bar_empty, COUNT_W],
        )
        row.setStyle(TableStyle([
            # Technique ID
            ("BACKGROUND",    (0, 0), (0, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (0, 0), C_MUTED),
            ("FONTNAME",      (0, 0), (0, 0), "Helvetica"),
            ("FONTSIZE",      (0, 0), (0, 0), 7),
            ("ALIGN",         (0, 0), (0, 0), "CENTER"),
            # Technique name (tactic color)
            ("BACKGROUND",    (1, 0), (1, 0), C_DARK),
            ("TEXTCOLOR",     (1, 0), (1, 0), color),
            ("FONTNAME",      (1, 0), (1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (1, 0), (1, 0), 8),
            ("ALIGN",         (1, 0), (1, 0), "LEFT"),
            ("LEFTPADDING",   (1, 0), (1, 0), 4),
            # Filled bar
            ("BACKGROUND",    (2, 0), (2, 0), color),
            ("LEFTPADDING",   (2, 0), (2, 0), 0),
            ("RIGHTPADDING",  (2, 0), (2, 0), 0),
            # Empty bar
            ("BACKGROUND",    (3, 0), (3, 0), HexColor("#0d1e2e")),
            ("LEFTPADDING",   (3, 0), (3, 0), 0),
            ("RIGHTPADDING",  (3, 0), (3, 0), 0),
            # Count
            ("BACKGROUND",    (4, 0), (4, 0), C_DARK),
            ("TEXTCOLOR",     (4, 0), (4, 0), C_MUTED),
            ("FONTNAME",      (4, 0), (4, 0), "Helvetica"),
            ("FONTSIZE",      (4, 0), (4, 0), 8),
            ("ALIGN",         (4, 0), (4, 0), "CENTER"),
            # Row
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("INNERGRID",     (0, 0), (-1, -1), 0, white),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#0f3a5c")),
        ]))
        items.append(row)
        items.append(Spacer(1, 2))

    return items


def _build_mitre_legend() -> Table:
    """2-column legend mapping tactic name → color swatch."""
    items = list(MITRE_TACTIC_COLORS.items())
    # Pair them up: two tactics per row
    rows = []
    for i in range(0, len(items), 2):
        left_tactic,  left_color  = items[i]
        right_tactic, right_color = items[i + 1] if i + 1 < len(items) else ("", None)
        rows.append([
            "■", left_tactic,
            "■" if right_color else "", right_tactic,
        ])

    legend = Table(rows, colWidths=[0.5*cm, 7.5*cm, 0.5*cm, 7.5*cm])
    style_cmds = [
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
    ]
    for row_idx, (i) in enumerate(range(0, len(items), 2)):
        left_tactic,  left_color  = items[i]
        right_tactic, right_color = items[i + 1] if i + 1 < len(items) else ("", None)
        style_cmds.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), left_color))
        style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), left_color))
        if right_color:
            style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), right_color))
            style_cmds.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), right_color))
    legend.setStyle(TableStyle(style_cmds))
    return legend


def _page_template(canvas, doc):
    """Draw page header/footer on every page."""
    canvas.saveState()
    w, h = A4

    # Full-page dark background (must be drawn first, behind everything)
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    # Top bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(C_CYAN)
    canvas.rect(0, h - 1.2*cm, 4*mm, 1.2*cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_TEXT)
    canvas.drawString(1*cm, h - 0.8*cm, "CYBER THREAT INTELLIGENCE REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawRightString(w - 1*cm, h - 0.8*cm,
        datetime.now(timezone.utc).strftime("%Y-%m-%d"))

    # Bottom bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(w/2, 0.3*cm, f"Page {doc.page} — CONFIDENTIAL")

    canvas.restoreState()


def _generate_recommendations(kpis: dict, attack_counts: list, cves: list) -> list:
    """Generate context-aware recommendations based on actual data."""
    recs = []

    # Based on top attack type
    top_type = kpis.get("top_attack_type", "")
    if top_type == "Ransomware":
        recs.append({
            "title": "Immediate Ransomware Mitigation",
            "detail": "Ransomware is the dominant threat. Verify all backups are offline and tested. "
                      "Enforce application whitelisting and restrict macro execution in Office documents. "
                      "Ensure EDR solutions are active on all endpoints."
        })
    elif top_type in ("Brute Force", "Port Scan"):
        recs.append({
            "title": "Strengthen Authentication Controls",
            "detail": "Brute force and scanning activity is elevated. Enable account lockout policies, "
                      "enforce MFA on all remote access services, and review exposed RDP/SSH ports. "
                      "Consider IP allowlisting for administrative interfaces."
        })
    elif top_type == "Phishing":
        recs.append({
            "title": "Email Security Enhancement",
            "detail": "Phishing campaigns are the dominant threat vector. Review email gateway rules, "
                      "enable DMARC/DKIM/SPF validation, and run security awareness training. "
                      "Consider deploying a sandboxed email attachment scanner."
        })
    elif top_type == "DDoS":
        recs.append({
            "title": "DDoS Resilience Review",
            "detail": "High DDoS activity detected. Verify CDN and DDoS scrubbing services are active. "
                      "Review rate limiting on public-facing services and ensure failover capacity is available."
        })

    # Based on critical CVEs
    critical_cve_count = sum(1 for c in cves if (c.get("cvss_score") or 0) >= 9.0)
    if critical_cve_count > 0:
        recs.append({
            "title": f"Patch {critical_cve_count} Critical CVE(s) Immediately",
            "detail": f"{critical_cve_count} critical vulnerabilities (CVSS ≥ 9.0) were published in this "
                      "reporting period. Cross-reference affected vendors/products against your asset inventory "
                      "and prioritize patching within 24 hours for internet-facing systems."
        })

    # Based on avg severity
    avg_sev = float(kpis.get("avg_severity", 0))
    if avg_sev >= 7.0:
        recs.append({
            "title": "Elevate Security Posture — High Average Severity",
            "detail": f"Average event severity is {avg_sev:.1f}/10 — above normal thresholds. "
                      "Consider moving to heightened monitoring mode: increase SIEM alerting sensitivity, "
                      "activate 24/7 SOC coverage, and review incident response playbooks."
        })

    # Standard recommendations always included
    recs.append({
        "title": "Review Threat Intelligence Feed Coverage",
        "detail": "Ensure AlienVault OTX, AbuseIPDB, and NVD feeds are ingesting continuously. "
                  "Cross-reference top attacking IPs against your firewall blocklists and update "
                  "threat intelligence platform (TIP) with current indicators of compromise (IOCs)."
    })
    recs.append({
        "title": "Log Retention and SIEM Tuning",
        "detail": "Retain raw security logs for minimum 90 days. Review SIEM correlation rules against "
                  "the MITRE ATT&amp;CK techniques active in this report. Tune detection rules for "
                  "techniques with high frequency but low current alert coverage."
    })

    return recs[:6]   # cap at 6 recommendations per report
