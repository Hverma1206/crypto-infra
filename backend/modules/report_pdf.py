"""
PDF report generation using ReportLab.

Generates a professional threat intelligence report containing:
  - Header with title, date, and input artifact
  - Risk Assessment (score, level, gauge)
  - Scam Classification (type, confidence, reasoning)
  - Key Findings
  - Domain Intelligence (WHOIS, crt.sh, Wayback)
  - Wallet Analysis (balance, impact, deployer)
  - Verification Links
"""

from __future__ import annotations

import io
import logging
from datetime import datetime

logger = logging.getLogger("report_pdf")


def _risk_color(level: str):
    """Return RGB tuple for the risk level."""
    from reportlab.lib.colors import HexColor

    colors = {
        "CRITICAL": HexColor("#c62828"),
        "HIGH": HexColor("#d84315"),
        "MEDIUM": HexColor("#e67e00"),
        "LOW": HexColor("#2f7d32"),
    }
    return colors.get(level, HexColor("#666666"))


def generate_pdf(analysis: dict, report_narrative: str | None = None) -> bytes:
    """
    MAIN FUNCTION — generates a PDF report and returns it as bytes.

    Parameters:
        analysis: The full analysis result dict from /analyze
        report_narrative: Optional AI-generated narrative text

    Returns:
        PDF file contents as bytes
    """
    from reportlab.lib import colors
    from reportlab.lib.colors import HexColor
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=HexColor("#1a1a1a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#666666"),
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=HexColor("#1a1a1a"),
        spaceBefore=16,
        spaceAfter=8,
        borderWidth=0,
        borderPadding=0,
    )
    body_style = ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#333333"),
        leading=15,
    )
    finding_style = ParagraphStyle(
        "FindingItem",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#444444"),
        leftIndent=12,
        spaceBefore=2,
        leading=14,
    )
    muted_style = ParagraphStyle(
        "MutedText",
        parent=styles["Normal"],
        fontSize=9,
        textColor=HexColor("#888888"),
    )

    elements = []

    # ---- Header ----
    input_value = analysis.get("input", "Unknown")
    input_type = analysis.get("input_type", "unknown")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    elements.append(Paragraph("Crypto Scam Infrastructure Report", title_style))
    elements.append(Paragraph(f"Generated: {now}  |  Input: {input_value} ({input_type})", subtitle_style))

    # Divider
    divider_table = Table([[""]], colWidths=[170 * mm])
    divider_table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1, HexColor("#e0e0e0")),
    ]))
    elements.append(divider_table)
    elements.append(Spacer(1, 10))

    # ---- Risk Assessment ----
    risk = analysis.get("risk") or {}
    risk_level = risk.get("level", "UNKNOWN")
    risk_score = risk.get("score", 0)
    risk_clr = _risk_color(risk_level)

    elements.append(Paragraph("Risk Assessment", section_style))

    risk_data = [
        ["Risk Level", "Risk Score", "Reasons"],
        [
            Paragraph(f'<font color="{risk_clr}">{risk_level}</font>', body_style),
            Paragraph(f'<font color="{risk_clr}"><b>{risk_score}</b>/100</font>', body_style),
            Paragraph("<br/>".join(risk.get("reasons") or ["No risk factors identified"]), muted_style),
        ],
    ]
    risk_table = Table(risk_data, colWidths=[40 * mm, 35 * mm, 95 * mm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f5f5f5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#333333")),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 10),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(risk_table)

    # ---- Key Findings ----
    findings = analysis.get("findings") or []
    if findings:
        elements.append(Paragraph("Key Findings", section_style))
        for i, finding in enumerate(findings[:10], 1):
            elements.append(Paragraph(f"• {finding}", finding_style))

    # ---- Wallet Intelligence ----
    raw = analysis.get("raw") or {}
    wallet_raw = raw.get("wallet")
    if wallet_raw:
        elements.append(Paragraph("Wallet Intelligence", section_style))

        impact = wallet_raw.get("impact") or {}
        contract = wallet_raw.get("contract_info") or {}

        wallet_info = [
            ["Field", "Value"],
            ["Address", wallet_raw.get("address", "—")],
            ["Balance", f'{wallet_raw.get("balance_eth", 0)} ETH'],
            ["Total ETH Received", str(impact.get("total_eth_received", "—"))],
            ["Unique Senders (est. victims)", str(impact.get("unique_senders", "—"))],
            ["Days Active", str(impact.get("days_active", "—"))],
            ["Is Contract", "Yes" if contract.get("is_contract") else "No"],
            ["Deployer", contract.get("deployer") or "—"],
        ]
        w_table = Table(wallet_info, colWidths=[55 * mm, 115 * mm])
        w_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f5f5f5")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (0, -1), HexColor("#555555")),
        ]))
        elements.append(w_table)

    # ---- Domain Intelligence ----
    whois_raw = raw.get("whois")
    if whois_raw:
        elements.append(Paragraph("Domain Intelligence", section_style))

        domain_info = [
            ["Field", "Value"],
            ["Domain", whois_raw.get("domain", "—")],
            ["Registrar", whois_raw.get("registrar") or "—"],
            ["Created", whois_raw.get("creation_date") or "—"],
            ["Expires", whois_raw.get("expiry_date") or "—"],
            ["Age (days)", str(whois_raw.get("age_days") or "—")],
            ["Registrant Emails", ", ".join(whois_raw.get("emails") or []) or "—"],
            ["Privacy Protected", "Yes" if whois_raw.get("privacy_protected") else "No"],
            ["Country", whois_raw.get("country") or "—"],
        ]
        d_table = Table(domain_info, colWidths=[55 * mm, 115 * mm])
        d_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f5f5f5")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (0, -1), HexColor("#555555")),
        ]))
        elements.append(d_table)

    # ---- Wayback / Timeline ----
    wayback_raw = raw.get("wayback")
    if wayback_raw and wayback_raw.get("snapshot_count"):
        elements.append(Paragraph("Archive Timeline", section_style))
        timeline = wayback_raw.get("timeline") or {}
        timeline_info = [
            ["Field", "Value"],
            ["Snapshots Found", str(wayback_raw.get("snapshot_count", 0))],
            ["First Seen", timeline.get("first_seen") or "—"],
            ["Last Seen", timeline.get("last_seen") or "—"],
            ["Operational Days", str(timeline.get("operational_days") or "—")],
        ]
        t_table = Table(timeline_info, colWidths=[55 * mm, 115 * mm])
        t_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f5f5f5")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (0, -1), HexColor("#555555")),
        ]))
        elements.append(t_table)

    # ---- AI Narrative ----
    if report_narrative:
        elements.append(Paragraph("Investigation Narrative", section_style))
        elements.append(Paragraph(report_narrative, body_style))

    # ---- Verification Links ----
    web_raw = raw.get("web_mentions") or {}
    external_links = web_raw.get("external_links") or []
    if external_links:
        elements.append(Paragraph("Verification Links", section_style))
        for link in external_links:
            link_text = f'<link href="{link["link"]}">{link["title"]}</link> — {link.get("snippet", "")}'
            elements.append(Paragraph(f"• {link['title']}: {link['link']}", finding_style))

    # ---- Footer ----
    elements.append(Spacer(1, 20))
    elements.append(divider_table)
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        "This report was generated by Crypto Scam Infrastructure Mapper — an OSINT tool "
        "that investigates wallet addresses and domains using public data sources. "
        "All data is sourced from publicly available APIs and databases.",
        muted_style,
    ))

    doc.build(elements)
    return buffer.getvalue()
