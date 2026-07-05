import io
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from models.schemas import ScanResult, Vulnerability, SeverityLevel

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: (0.8, 0.1, 0.1),
    SeverityLevel.HIGH: (0.9, 0.4, 0.0),
    SeverityLevel.MEDIUM: (0.9, 0.75, 0.0),
    SeverityLevel.LOW: (0.2, 0.5, 0.9),
    SeverityLevel.INFO: (0.5, 0.5, 0.5),
}

SEVERITY_LABELS = {
    SeverityLevel.CRITICAL: "CRITICAL",
    SeverityLevel.HIGH: "HIGH",
    SeverityLevel.MEDIUM: "MEDIUM",
    SeverityLevel.LOW: "LOW",
    SeverityLevel.INFO: "INFO",
}


def generate_pdf_report(scan_result: ScanResult) -> bytes:
    """Generate a comprehensive PDF report for a scan result."""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether, PageBreak
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        story = []

        # ─────────────────────────────────────────────────────────────
        # STYLES
        # ─────────────────────────────────────────────────────────────
        title_style = ParagraphStyle(
            "Title",
            parent=styles["Title"],
            fontSize=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=20,
            fontName="Helvetica",
        )
        section_style = ParagraphStyle(
            "Section",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=20,
            spaceAfter=8,
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#334155"),
            spaceAfter=4,
            leading=14,
        )
        mono_style = ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#475569"),
            fontName="Courier",
            spaceAfter=4,
        )

        # ─────────────────────────────────────────────────────────────
        # HEADER
        # ─────────────────────────────────────────────────────────────
        story.append(Paragraph("🔒 Security Vulnerability Report", title_style))
        story.append(Paragraph(
            f"Target: <b>{scan_result.target}</b> &nbsp;|&nbsp; "
            f"Scan Type: <b>{scan_result.scan_type.value.upper()}</b> &nbsp;|&nbsp; "
            f"Generated: <b>{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</b>",
            subtitle_style
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0ea5e9")))
        story.append(Spacer(1, 0.3 * inch))

        # ─────────────────────────────────────────────────────────────
        # EXECUTIVE SUMMARY
        # ─────────────────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", section_style))
        summary = scan_result.summary or {}
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = summary.get("total", 0)

        # Risk color
        if critical > 0:
            risk_label = "CRITICAL RISK"
            risk_color = colors.HexColor("#dc2626")
        elif high > 0:
            risk_label = "HIGH RISK"
            risk_color = colors.HexColor("#ea580c")
        elif medium > 0:
            risk_label = "MEDIUM RISK"
            risk_color = colors.HexColor("#ca8a04")
        elif low > 0:
            risk_label = "LOW RISK"
            risk_color = colors.HexColor("#2563eb")
        else:
            risk_label = "CLEAN"
            risk_color = colors.HexColor("#16a34a")

        summary_data = [
            ["Metric", "Value"],
            ["Overall Risk Level", risk_label],
            ["Total Vulnerabilities", str(total)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)],
            ["Open Ports Found", str(len(scan_result.open_ports))],
            ["Scan Duration", f"{scan_result.started_at} → {scan_result.completed_at or 'N/A'}"],
        ]

        summary_table = Table(summary_data, colWidths=[3.5 * inch, 3.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
            ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # ─────────────────────────────────────────────────────────────
        # VULNERABILITY FINDINGS
        # ─────────────────────────────────────────────────────────────
        if scan_result.vulnerabilities:
            story.append(Paragraph("Vulnerability Findings", section_style))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
            story.append(Spacer(1, 0.1 * inch))

            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                sev_color = SEVERITY_COLORS.get(vuln.severity, (0.5, 0.5, 0.5))
                sev_r, sev_g, sev_b = sev_color
                sev_hex = "#{:02x}{:02x}{:02x}".format(
                    int(sev_r * 255), int(sev_g * 255), int(sev_b * 255)
                )
                sev_label = SEVERITY_LABELS.get(vuln.severity, "INFO")

                vuln_data = [
                    [f"#{i} {vuln.title}", f"[{sev_label}]"],
                    ["Category:", vuln.category],
                    ["Affected:", vuln.affected_component],
                    ["Description:", vuln.description],
                    ["Recommendation:", vuln.recommendation],
                ]
                if vuln.cve_id:
                    vuln_data.append(["CVE/CWE:", vuln.cve_id])
                if vuln.cvss_score:
                    vuln_data.append(["CVSS Score:", f"{vuln.cvss_score}/10"])
                if vuln.evidence:
                    vuln_data.append(["Evidence:", vuln.evidence[:100]])

                vuln_table = Table(vuln_data, colWidths=[1.5 * inch, 5.5 * inch])
                vuln_table.setStyle(TableStyle([
                    ("SPAN", (0, 0), (0, 0)),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.HexColor(sev_hex)),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("ALIGN", (0, 1), (-1, -1), "LEFT"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                    ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                    ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#64748b")),
                ]))
                story.append(KeepTogether(vuln_table))
                story.append(Spacer(1, 0.15 * inch))

        # ─────────────────────────────────────────────────────────────
        # OPEN PORTS
        # ─────────────────────────────────────────────────────────────
        if scan_result.open_ports:
            story.append(PageBreak())
            story.append(Paragraph("Open Ports", section_style))

            port_data = [["Port", "Service", "State", "Risk Level", "Version/Banner"]]
            for port_info in scan_result.open_ports:
                risk = port_info.risk.value if hasattr(port_info.risk, 'value') else str(port_info.risk)
                port_data.append([
                    str(port_info.port),
                    port_info.service,
                    port_info.state.upper(),
                    risk.upper(),
                    (port_info.version or "N/A")[:40],
                ])

            port_table = Table(port_data, colWidths=[0.7*inch, 1.2*inch, 0.7*inch, 1.0*inch, 3.4*inch])
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ]))
            story.append(port_table)

        # ─────────────────────────────────────────────────────────────
        # SSL INFO
        # ─────────────────────────────────────────────────────────────
        if scan_result.ssl_info:
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("SSL/TLS Certificate", section_style))
            ssl = scan_result.ssl_info
            ssl_data = [
                ["Property", "Value"],
                ["Status", "Valid ✓" if ssl.valid else "Invalid ✗"],
                ["Issuer", ssl.issuer or "N/A"],
                ["Subject", ssl.subject or "N/A"],
                ["Expiry Date", ssl.expiry_date or "N/A"],
                ["Days Remaining", str(ssl.days_remaining) if ssl.days_remaining is not None else "N/A"],
                ["Protocol", ssl.protocol or "N/A"],
                ["Grade", ssl.grade or "N/A"],
            ]
            ssl_table = Table(ssl_data, colWidths=[2 * inch, 5 * inch])
            ssl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#64748b")),
            ]))
            story.append(ssl_table)

        # ─────────────────────────────────────────────────────────────
        # FOOTER NOTE
        # ─────────────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            "⚠️ This report is for authorized security assessment purposes only. "
            "Unauthorized scanning of systems is illegal. Generated by VulnScanner — Automated Security Assessment Platform.",
            ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                           textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)
        ))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    except ImportError as e:
        logger.error(f"ReportLab not installed: {e}")
        raise RuntimeError("ReportLab library required for PDF generation. Install with: pip install reportlab")
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise
