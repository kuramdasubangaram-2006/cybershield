"""Build a compact PDF for one saved CyberShield scan."""

from datetime import datetime, timezone
from html import escape
from urllib.parse import urlsplit, urlunsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _pdf_text(value):
    """Limit strings to printable WinAnsi characters supported by built-in fonts."""
    text = str(value or "")
    text = "".join(character if character in "\n\t" or ord(character) >= 32 else " " for character in text)
    return text.encode("cp1252", errors="replace").decode("cp1252")


def build_scan_pdf(scan, details, risk_label, formatted_time):
    from io import BytesIO

    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=17 * mm, bottomMargin=17 * mm, title="CyberShield Scan Report",
        author="CyberShield",
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20,
        leading=24, textColor=colors.HexColor("#0b2334"), alignment=TA_LEFT, spaceAfter=4 * mm,
    )
    heading_style = ParagraphStyle(
        "SectionHeading", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12,
        leading=15, textColor=colors.HexColor("#087d91"), spaceBefore=4 * mm, spaceAfter=2 * mm,
    )
    body_style = ParagraphStyle(
        "ReportBody", parent=base["BodyText"], fontName="Helvetica", fontSize=9,
        leading=13, textColor=colors.HexColor("#263746"), spaceAfter=2 * mm,
        wordWrap="CJK",
    )
    small_style = ParagraphStyle("ReportSmall", parent=body_style, fontSize=8, leading=11)
    story = [
        Paragraph("CyberShield Scan Report", title_style),
        Paragraph("A detailed record of the checks performed. This report is not a guarantee that the item is safe.", body_style),
        Spacer(1, 2 * mm),
    ]

    def paragraph(value, style=body_style):
        return Paragraph(escape(_pdf_text(value)).replace("\n", "<br/>"), style)

    def add_section(title, lines):
        story.append(Paragraph(escape(title), heading_style))
        if not lines:
            story.append(paragraph("No details were saved for this section.", small_style))
            return
        for line in lines:
            story.append(Paragraph("• " + escape(_pdf_text(line)).replace("\n", "<br/>"), body_style))

    target = scan["target"]
    if scan["module"] == "URL Scanner":
        parsed_target = urlsplit(target if "://" in target else f"https://{target}")
        target = urlunsplit((parsed_target.scheme, parsed_target.netloc, parsed_target.path, "", ""))
    summary_rows = [
        [paragraph("Module", small_style), paragraph(scan["module"], body_style)],
        [paragraph("Risk", small_style), paragraph(risk_label, body_style)],
        [paragraph("Scanned", small_style), paragraph(f"{formatted_time} IST", body_style)],
        [paragraph("Target", small_style), paragraph(target, body_style)],
        [paragraph("Summary", small_style), paragraph(scan["summary"], body_style)],
    ]
    if "email" in scan.keys():
        summary_rows.insert(1, [paragraph("Account", small_style), paragraph(scan["email"], body_style)])
    summary = Table(summary_rows, colWidths=[31 * mm, 143 * mm], repeatRows=0, hAlign="LEFT")
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf4f7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd9df")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d8e3e8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary)

    if details.get("explanation"):
        add_section("Detailed explanation", [details["explanation"]])
    if details.get("site_explanation"):
        add_section("Website response details", [details["site_explanation"]])
    if details.get("analysis_scope"):
        add_section("Analysis scope", [details["analysis_scope"]])
    if details.get("findings"):
        add_section("Detailed static findings", [
            f"{item.get('severity', 'Review')} — {item.get('name', 'Finding')}: {item.get('detail', '')}"
            for item in details["findings"] if isinstance(item, dict)
        ])

    facts = details.get("facts") or {}
    if details.get("sha256"):
        facts = {**facts, "SHA-256": details["sha256"]}
    if facts:
        story.append(Paragraph("Checked facts", heading_style))
        fact_rows = [[paragraph("Finding", small_style), paragraph("Value", small_style)]]
        fact_rows.extend([[paragraph(key, small_style), paragraph(value, small_style)] for key, value in facts.items()])
        facts_table = Table(fact_rows, colWidths=[52 * mm, 122 * mm], repeatRows=1, hAlign="LEFT")
        facts_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2f2f5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd9df")),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d8e3e8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(facts_table)

    add_section("Observed indicators", details.get("indicators") or [])
    add_section("Suggested next steps", details.get("recommendations") or [])
    if details.get("redirect_chain"):
        add_section("Redirect path", details["redirect_chain"])
    story.extend([
        Spacer(1, 4 * mm),
        paragraph("CyberShield checks are limited. Normal means no configured warning was found; it does not prove safety. This report is not an antivirus scan or a live threat-intelligence verdict.", small_style),
    ])

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#627786"))
        canvas.drawString(18 * mm, 10 * mm, f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} | CyberShield")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    output.seek(0)
    return output
