"""Build a compact PDF for one saved CyberShield scan."""

from datetime import datetime, timezone
from html import escape
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _pdf_text(value):
    """Limit strings to printable WinAnsi characters supported by built-in fonts."""
    text = str(value or "")
    text = "".join(character if character in "\n\t" or ord(character) >= 32 else " " for character in text)
    return text.encode("cp1252", errors="replace").decode("cp1252")


def _severity_summary_chart(events):
    """Draw a compact chart of the severity labels present in submitted logs."""
    labels = Counter(
        str(event.get("severity") or "Not specified").upper()
        for event in events
    )
    order = ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "ERROR", "NOTICE", "INFO", "LOW", "DEBUG", "NOT SPECIFIED"]
    rows = sorted(labels.items(), key=lambda item: (order.index(item[0]) if item[0] in order else len(order), item[0]))
    width = 174 * mm
    row_height = 8 * mm
    height = max(20 * mm, (len(rows) + 1) * row_height)
    drawing = Drawing(width, height)
    bar_x = 36 * mm
    bar_width = 122 * mm
    max_count = max(labels.values(), default=1)
    palette = {
        "CRITICAL": colors.HexColor("#bd2633"),
        "HIGH": colors.HexColor("#dc5a36"),
        "MEDIUM": colors.HexColor("#d58b16"),
        "WARNING": colors.HexColor("#d58b16"),
        "ERROR": colors.HexColor("#dc5a36"),
        "NOTICE": colors.HexColor("#247aa5"),
        "INFO": colors.HexColor("#34865a"),
        "LOW": colors.HexColor("#34865a"),
        "DEBUG": colors.HexColor("#718397"),
        "NOT SPECIFIED": colors.HexColor("#718397"),
    }
    for index, (label, count) in enumerate(rows):
        y = height - (index + 1) * row_height + 2 * mm
        drawing.add(String(0, y + 1.5 * mm, _pdf_text(label), fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#263746")))
        drawn_width = max(2 * mm, bar_width * count / max_count)
        drawing.add(Rect(bar_x, y, drawn_width, 4 * mm, fillColor=palette.get(label, colors.HexColor("#247aa5")), strokeColor=None))
        drawing.add(String(bar_x + drawn_width + 2 * mm, y + 1 * mm, str(count), fontName="Helvetica-Bold", fontSize=7, fillColor=colors.HexColor("#263746")))
    return drawing


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
            story.append(Paragraph("- " + escape(_pdf_text(line)).replace("\n", "<br/>"), body_style))

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
    if details.get("log_events"):
        events = details["log_events"]
        story.append(Paragraph("Severity labels in the submitted logs", heading_style))
        story.append(_severity_summary_chart(events))
        story.append(paragraph("Counts use the severity labels present in the input. They are not independently verified or assigned severity judgments.", small_style))
        log_section_heading = Paragraph("Parsed log events and network details", heading_style)
        for event_index, event in enumerate(events):
            source = event.get("source_ip", "Not present")
            if event.get("source_port") not in (None, "Not present"):
                source += f" port {event['source_port']}"
            destination = event.get("destination_ip", "Not present")
            if event.get("destination_port") not in (None, "Not present"):
                destination += f" port {event['destination_port']}"
            other_ips = ", ".join(event.get("other_ips", [])) or "Not present"
            cve_text = ", ".join(event.get("cves", [])) or "Not present"
            parsed_fields = "; ".join(
                f"{key}={value}" for key, value in event.get("fields", {}).items()
            ) or "No structured fields recognized"
            has_vulnerability_data = (
                bool(event.get("cves"))
                or event.get("cvss_vector_as_reported") not in (None, "Not present")
                or event.get("cvss_as_reported") not in (None, "Not present")
            )
            if has_vulnerability_data:
                cvss_details = (
                    f"CVSS score as written: {event.get('cvss_as_reported', 'Not present')} | "
                    f"Reported severity: {event.get('cvss_reported_severity', 'Not assigned')} | "
                    f"Calculated CVSS v3.1 Base: {event.get('cvss_base_calculated', 'Not calculated')} "
                    f"({event.get('cvss_severity', 'Not assigned')}) | "
                    f"Vector as written: {event.get('cvss_vector_as_reported', 'Not present')}"
                )
                cvss_details += f" | {event.get('cvss_note', 'No CVSS verification performed.')}"
            else:
                cvss_details = "CVE/CVSS: Not present"
            event_rows = [
                [paragraph(f"Line {event.get('line', '?')} | {event.get('timestamp', 'Not present')}", small_style), paragraph(str(event.get("severity", "Not specified")), small_style)],
                [paragraph(f"Event: {event.get('event', 'Event')}", body_style), ""],
                [paragraph(f"Source: {source}", small_style), paragraph(f"Destination: {destination}", small_style)],
                [paragraph(f"Protocol: {event.get('protocol', 'Not present')}", small_style), paragraph(f"Other IPs: {other_ips}", small_style)],
                [paragraph(f"CVE: {cve_text} | {cvss_details}", small_style), ""],
                [paragraph(f"Extracted fields: {parsed_fields}", small_style), ""],
                [paragraph(f"Sanitized log line: {event.get('line_excerpt', '')}", small_style), ""],
            ]
            card = Table(event_rows, colWidths=[87 * mm, 87 * mm], hAlign="LEFT")
            card.setStyle(TableStyle([
                ("SPAN", (0, 1), (-1, 1)),
                ("SPAN", (0, 4), (-1, 4)),
                ("SPAN", (0, 5), (-1, 5)),
                ("SPAN", (0, 6), (-1, 6)),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2f2f5")),
                ("TEXTCOLOR", (1, 0), (1, 0), colors.HexColor("#0b2334")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd9df")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e1e9ed")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            if event_index == 0:
                story.append(KeepTogether([log_section_heading, card, Spacer(1, 2 * mm)]))
            else:
                story.append(KeepTogether([card, Spacer(1, 2 * mm)]))
    elif scan["module"] == "Log Analysis":
        add_section("Log detail availability", [
            "Line-level data is not available for this earlier scan because the original log text was not retained. Rerun the analysis to generate the expanded event report."
        ])

    facts = details.get("facts") or {}
    if details.get("sha256"):
        facts = {**facts, "SHA-256": details["sha256"]}
    if facts:
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
        story.append(KeepTogether([Paragraph("Checked facts", heading_style), facts_table]))

    add_section("Observed indicators", details.get("indicators") or [])
    add_section("Suggested next steps", details.get("recommendations") or [])
    if details.get("redirect_chain"):
        add_section("Redirect path", details["redirect_chain"])
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#627786"))
        canvas.drawString(18 * mm, 15 * mm, "Limited checks only; a Normal result does not prove safety.")
        canvas.drawString(18 * mm, 10 * mm, f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} | CyberShield")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    output.seek(0)
    return output
