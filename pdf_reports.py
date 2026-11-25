"""Build a compact PDF for one saved CyberShield scan."""

from datetime import datetime, timezone
from html import escape
from collections import Counter
import re
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
    if isinstance(events, dict):
        labels = Counter({str(label).upper(): int(count) for label, count in events.items()})
    else:
        labels = Counter(
            str(event.get("severity") or "Not specified").upper()
            for event in events
        )
    order = ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "ERROR", "NOTICE", "INFO", "LOW", "INFORMATIONAL", "NONE", "DEBUG", "NOT SPECIFIED"]
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
        "INFORMATIONAL": colors.HexColor("#718397"),
        "NONE": colors.HexColor("#718397"),
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
    if details.get("nessus_findings"):
        story.append(Paragraph("Nessus source severity distribution", heading_style))
        story.append(_severity_summary_chart(details.get("nessus_counts") or {}))
        story.append(paragraph("Counts and severities are imported from the uploaded Nessus report. CyberShield did not run a network scan or independently verify the listed findings.", small_style))
        for index, finding in enumerate(details["nessus_findings"], start=1):
            plugin_name = _pdf_text(finding.get("plugin_name", "Unnamed finding"))
            plugin_id = _pdf_text(finding.get("plugin_id", "Not provided"))
            story.append(Paragraph(f"Finding {index}: {escape(plugin_name)} (Plugin {escape(plugin_id)})", heading_style))
            metadata = [
                ("Source severity", finding.get("severity", "Not specified")),
                ("Risk factor", finding.get("risk_factor", "Not specified")),
                ("Asset / IP", f"{finding.get('asset', 'Not provided')} / {finding.get('asset_ip', 'Not provided')}"),
                ("Operating system", finding.get("operating_system", "Not provided")),
                ("Port / protocol / service", f"{finding.get('port', 'Not provided')} / {finding.get('protocol', 'Not provided')} / {finding.get('service', 'Not provided')}"),
                ("Plugin family", finding.get("plugin_family", "Not provided")),
                ("CVE IDs", ", ".join(finding.get("cves", [])) or "Not provided"),
                ("CVSS v2 source score / vector", f"{finding.get('cvss2_score', 'Not provided')} / {finding.get('cvss2_vector', 'Not provided')}"),
                ("CVSS v2 temporal source score / vector", f"{finding.get('cvss2_temporal_score', 'Not provided')} / {finding.get('cvss2_temporal_vector', 'Not provided')}"),
                ("CVSS v3 source score / vector", f"{finding.get('cvss3_score_reported', 'Not provided')} / {finding.get('cvss3_vector', 'Not provided')}"),
                ("CVSS v3.1 calculated score", f"{finding.get('cvss3_score_calculated', 'Not calculated')} ({finding.get('cvss3_severity_calculated', 'Not assigned')})"),
                ("CVSS v3.1 calculation note", finding.get("cvss3_note", "Not provided")),
                ("CVSS v3 temporal score / vector", f"{finding.get('cvss3_temporal_score', 'Not provided')} / {finding.get('cvss3_temporal_vector', 'Not provided')}"),
                ("CVSS v4 source score / vector", f"{finding.get('cvss4_score_reported', 'Not provided')} / {finding.get('cvss4_vector', 'Not provided')}"),
                ("Plugin type / version", f"{finding.get('plugin_type', 'Not provided')} / {finding.get('plugin_version', 'Not provided')}"),
                ("Plugin published / modified", f"{finding.get('plugin_publication_date', 'Not provided')} / {finding.get('plugin_modification_date', 'Not provided')}"),
                ("Patch publication date", finding.get("patch_publication_date", "Not provided")),
                ("Exploit availability", finding.get("exploit_available", "Not provided")),
                ("Exploit frameworks", "; ".join(f"{key}: {value}" for key, value in finding.get("exploit_frameworks", {}).items()) or "Not provided"),
                ("References", "; ".join(f"{key}: {', '.join(value)}" for key, value in finding.get("references", {}).items()) or "Not provided"),
            ]
            detail_rows = [[paragraph(label, small_style), paragraph(value, small_style)] for label, value in metadata]
            metadata_table = Table(detail_rows, colWidths=[48 * mm, 126 * mm], hAlign="LEFT")
            metadata_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf4f7")),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd9df")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d8e3e8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(metadata_table)
            for label, key in (("Synopsis", "synopsis"), ("Description", "description"), ("Recommended solution", "solution"), ("Plugin output", "plugin_output")):
                value = finding.get(key)
                if value and value != "Not provided":
                    story.append(Paragraph(f"<b>{label}:</b> {escape(_pdf_text(value)).replace(chr(10), '<br/>')}", small_style))
    if details.get("log_events"):
        events = details["log_events"]
        if details.get("log_severity_counts"):
            story.append(Paragraph("Input log severity levels", heading_style))
            story.append(_severity_summary_chart(details["log_severity_counts"]))
            story.append(paragraph("Counts use explicit priority labels from the input. Other labels remain unclassified; these counts are not CVSS scores or verified threat judgments.", small_style))
        if details.get("cvss_severity_counts"):
            story.append(Paragraph("CVSS v3.1 Base Score Distribution", heading_style))
            story.append(_severity_summary_chart(details["cvss_severity_counts"]))
            unscored = details.get("cvss_unscored_count", 0)
            story.append(paragraph(f"Only complete supplied CVSS v3.1 vectors are calculated; {unscored} event(s) have no usable vector and remain unscored. Bands: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. CVSS rates vulnerability impact, not log activity. CVEs and vectors are not independently verified.", small_style))
        log_section_heading = Paragraph("Parsed log events and network details", heading_style)
        for event_index, event in enumerate(events):
            source = event.get("source_ip", "Not present")
            if event.get("source_port") not in (None, "Not present"):
                source += f" port {event['source_port']}"
            destination = event.get("destination_ip", "Not present")
            if event.get("destination_port") not in (None, "Not present"):
                destination += f" port {event['destination_port']}"
            other_ips = ", ".join(event.get("other_ips", [])) or "Not present"
            cves = [value for value in event.get("cves", []) if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(value))]
            cve_links = "<br/>".join(
                f'<link href="https://nvd.nist.gov/vuln/detail/{escape(str(cve))}" color="#087d91">{escape(str(cve))}</link>'
                for cve in cves
            ) or "No CVE IDs"
            parsed_fields = "; ".join(
                f"{key}={value}" for key, value in event.get("fields", {}).items()
            ) or "No structured fields recognized"
            has_vulnerability_data = (
                bool(event.get("cves"))
                or event.get("cvss_vector_as_reported") not in (None, "Not present")
                or event.get("cvss_as_reported") not in (None, "Not present")
            )
            if has_vulnerability_data:
                cvss_parts = []
                if event.get("cvss_as_reported") not in (None, "Not present"):
                    cvss_parts.append(f"As reported: {event.get('cvss_as_reported')} ({event.get('cvss_reported_severity', 'Not assigned')})")
                if event.get("cvss_base_calculated") not in (None, "Not calculated"):
                    cvss_parts.append(f"Calculated v3.1 Base: {event.get('cvss_base_calculated')} ({event.get('cvss_severity', 'Not assigned')})")
                if event.get("cvss_vector_as_reported") not in (None, "Not present"):
                    cvss_parts.append(f"Vector: {event.get('cvss_vector_as_reported')}")
                if event.get("cvss_note"):
                    cvss_parts.append(event["cvss_note"])
                cvss_details = "<br/>".join(escape(_pdf_text(part)) for part in cvss_parts) or "No CVSS supplied"
            else:
                cvss_details = "No CVSS supplied"
            event_rows = [
                [paragraph(f"Line {event.get('line', '?')} | {event.get('timestamp', 'Not present')} | {event.get('timestamp_status', 'Timestamp not validated')}", small_style), paragraph(str(event.get("severity", "Not specified")), small_style)],
                [paragraph(f"Event: {event.get('event', 'Event')}", body_style), ""],
                [paragraph(f"Source: {source}", small_style), paragraph(f"Destination: {destination}", small_style)],
                [paragraph(f"Protocol: {event.get('protocol', 'Not present')}", small_style), paragraph(f"Other IPs: {other_ips}", small_style)],
                [Paragraph("<b>CVE IDs</b><br/>" + cve_links, small_style), Paragraph("<b>CVSS details</b><br/>" + cvss_details, small_style)],
                [paragraph(f"Extracted fields: {parsed_fields}", small_style), ""],
                [paragraph(f"Sanitized log line: {event.get('line_excerpt', '')}", small_style), ""],
            ]
            card = Table(event_rows, colWidths=[87 * mm, 87 * mm], hAlign="LEFT")
            card.setStyle(TableStyle([
                ("SPAN", (0, 1), (-1, 1)),
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
        story.append(Paragraph("Mitigation guidance and trusted sources", heading_style))
        story.append(paragraph("Log text alone does not confirm that a product is affected. Check the exact product and version, validate each finding in the original scanner, and review the affected versions and vendor advisory references in the CVE record.", small_style))
        for action in (
            "When affected, apply the fix or upgrade recommended by the product vendor, then verify the installed version and rescan.",
            "If a fix cannot be applied yet, use a temporary vendor/CISA-supported mitigation such as restricting exposure, isolating the affected service, or disabling the vulnerable feature where safe. Track it until patched.",
            "Prioritize CVEs in CISA’s Known Exploited Vulnerabilities catalog while considering asset exposure and business impact.",
        ):
            story.append(Paragraph("- " + escape(_pdf_text(action)), body_style))
        references = (
            ("NIST NVD CVE records and references", "https://nvd.nist.gov/vuln/"),
            ("CISA Known Exploited Vulnerabilities catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ("CISA vulnerability response playbook", "https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf"),
            ("FIRST CVSS v3.1 specification", "https://www.first.org/cvss/v3.1/specification-document"),
        )
        for label, url in references:
            story.append(Paragraph(f'- <link href="{escape(url)}" color="#087d91">{escape(label)}</link>', small_style))
        story.append(paragraph("These are general response steps, not a CVE-specific patch recommendation. The input did not establish affected products or versions; follow the relevant vendor advisory before changing production systems.", small_style))
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
        footer_text = "Imported scanner report; findings were not independently verified." if scan["module"] == "Nessus Report" else "Limited checks only; a Normal result does not prove safety."
        canvas.drawString(18 * mm, 15 * mm, footer_text)
        canvas.drawString(18 * mm, 10 * mm, f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} | CyberShield")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    output.seek(0)
    return output
