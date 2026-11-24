"""Local-only analysis helpers. These functions never contact submitted hosts."""

import hashlib
import ipaddress
import io
import json
import math
import re
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import PurePath
from urllib.parse import urlsplit


_LOG_SECRET_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|authorization|proxy.?authorization|set.?cookie|cookie|"
    r"api.?key|access.?key|private.?key|credential|otp|csrf|session.?id)"
)
_LOG_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|authorization|proxy.?authorization|set.?cookie|cookie|"
    r"api.?key|access.?key|private.?key|credential|otp|csrf|session.?id)[A-Za-z0-9_.-]*)\b([\"']?)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|Bearer\s+\S+|[^\s,;]+)"
)
_LOG_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_LOG_KEY_VALUE = re.compile(
    r"(?:^|[\s,;{])['\"]?([A-Za-z][A-Za-z0-9_.-]{0,63})['\"]?\s*[:=]\s*"
    r"(?:\"((?:\\.|[^\"])*)\"|'((?:\\.|[^'])*)'|([^\s,;}\]]+))"
)


def _redact_secret_assignment(match):
    value = match.group(4)
    if value.startswith('"'):
        safe_value = '"[REDACTED]"'
    elif value.startswith("'"):
        safe_value = "'[REDACTED]'"
    else:
        safe_value = "[REDACTED]"
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{safe_value}"


def _safe_log_value(key, value):
    if _LOG_SECRET_KEY.search(str(key)):
        return "[REDACTED]"
    text = str(value)
    text = _LOG_SECRET_ASSIGNMENT.sub(_redact_secret_assignment, text)
    text = _LOG_BEARER.sub("Bearer [REDACTED]", text)
    return text


def _flatten_log_json(value, prefix="", depth=0):
    """Flatten a JSON log object into safe scalar key/value fields."""
    if depth > 8:
        return {}
    fields = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            fields.update(_flatten_log_json(child, name, depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value[:50]):
            name = f"{prefix}[{index}]" if prefix else f"item[{index}]"
            fields.update(_flatten_log_json(child, name, depth + 1))
    elif prefix:
        fields[prefix[:160]] = _safe_log_value(prefix, value)[:2000]
    return fields


def _extract_log_fields(line):
    """Collect structured JSON and common key=value fields, redacting secrets."""
    fields = {}
    try:
        parsed_json = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        parsed_json = None
    if isinstance(parsed_json, (dict, list)):
        fields.update(_flatten_log_json(parsed_json))
    else:
        for match in _LOG_KEY_VALUE.finditer(line):
            key = match.group(1)
            value = next((group for group in match.groups()[1:] if group is not None), "")
            fields.setdefault(key[:160], _safe_log_value(key, value)[:2000])
    return fields


def _log_field_value(fields, names):
    wanted = {name.lower() for name in names}
    for key, value in fields.items():
        if key.lower() in wanted:
            return value
    return None


def _sanitize_log_line(line):
    """Retain useful event wording while redacting common credential fields."""
    return _LOG_BEARER.sub("Bearer [REDACTED]", _LOG_SECRET_ASSIGNMENT.sub(_redact_secret_assignment, line))


def analyze_ip(value):
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from error

    if address.is_loopback:
        label = "Loopback address"
        risk = "Normal"
        summary = "This address points back to the same device; it is not a public reputation result."
        indicators = ["The address is reserved for the local device."]
        recommendations = ["Confirm that a local-device address is what you intended to review."]
        explanation = "This address points back to the same device. It is a local network value, not a public site's reputation result."
    elif address.is_link_local:
        label = "Link-local address"
        risk = "Normal"
        summary = "This address is used on a local network and is not globally reachable."
        indicators = ["The address is link-local."]
        recommendations = ["Compare the address with the expected local network range."]
        explanation = "A link-local address is normally used on the same local network segment and is not generally routed across the public internet."
    elif address.is_private:
        label = "Private network address"
        risk = "Normal"
        summary = "This address belongs to a private network; its public threat reputation cannot be checked here."
        indicators = ["The address is not globally routable."]
        recommendations = ["Compare the address with the expected private network range."]
        explanation = "Private addresses are reused inside homes and organizations. The format check can identify that range, but it cannot tell whether activity from a particular device is trustworthy."
    elif address.is_multicast or address.is_unspecified or address.is_reserved:
        label = "Special-purpose address"
        risk = "Low"
        summary = "This is a special-purpose address, not a normal public host reputation result."
        indicators = ["The address is reserved for a special networking purpose."]
        recommendations = ["Confirm this special-purpose address is expected in your network context."]
        explanation = "This address range is reserved for a networking purpose rather than ordinary public hosting. Confirm that the value makes sense for the system you are checking."
    elif address.is_global:
        label = "Public IP — reputation unverified"
        risk = "Normal"
        summary = "The address is globally routable. No threat-intelligence source is connected, so its reputation is unknown."
        indicators = ["Local format and address-range checks only; no live reputation lookup was performed."]
        recommendations = ["Check an approved threat-intelligence source before trusting this public address."]
        explanation = "This is a globally routable address, but global reachability does not reveal its owner or reputation. CyberShield checked only the address format and range."
    else:
        label = "Non-public address"
        risk = "Normal"
        summary = "This address is not globally routable. No public threat reputation was checked."
        indicators = ["The address is outside the public global address space."]
        recommendations = ["Compare the address with the expected network range; no public reputation check was performed."]
        explanation = "The address is outside the public global range. This local classification says nothing about whether the related activity was expected."

    return {
        "label": label,
        "risk": risk,
        "summary": summary,
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {"IP version": f"IPv{address.version}", "Globally routable": "Yes" if address.is_global else "No"},
        "target": str(address),
    }


def analyze_url(value):
    raw_url = value.strip()
    if not raw_url or len(raw_url) > 2048:
        raise ValueError("Enter a URL that is no longer than 2,048 characters.")
    if any(character.isspace() for character in raw_url):
        raise ValueError("The URL cannot contain spaces.")

    has_scheme = "://" in raw_url
    candidate = raw_url if has_scheme else f"https://{raw_url}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid URL with a hostname.") from error

    if not host:
        raise ValueError("Enter a valid URL with a hostname.")

    indicators = []
    strong_indicators = []
    caution_indicators = []

    scheme_assumption = "The input omitted a URL scheme; HTTPS was assumed only to parse the address. This alone is not a risk indicator."
    if has_scheme and parsed.scheme.lower() != "https":
        caution_indicators.append("The URL does not use HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        strong_indicators.append("The URL contains user information before the hostname.")

    host_is_ip = False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        host_is_ip = True
        strong_indicators.append("The hostname is an IP address instead of a domain name.")

    hostname_labels = host.rstrip(".").lower().split(".")
    if any(label.startswith("xn--") for label in hostname_labels):
        strong_indicators.append("The hostname contains an internationalized (punycode) label.")
    if len(hostname_labels) > 5:
        caution_indicators.append("The hostname has many subdomain levels.")
    if len(raw_url) > 180:
        caution_indicators.append("The URL is unusually long.")

    indicators.extend(strong_indicators)
    indicators.extend(caution_indicators)

    if strong_indicators or caution_indicators:
        label = "URL structure needs review"
        risk = "Low"
        summary = "One or more URL format indicators need context. They do not establish that the website is fake or malicious."
        recommendations = ["Compare the exact hostname with the address you intended to visit. Treat these format indicators as review prompts, not a malicious-site verdict."]
        explanation = "The URL contains format characteristics that can also appear on legitimate websites (for example, IP-based hosts, internationalized domains, long URLs, or HTTP). CyberShield did not verify threat reputation or prove malicious activity."
    else:
        label = "No local warning found — reputation unknown"
        risk = "Normal"
        summary = "No obvious structural warning was found. This does not confirm that the URL is safe."
        indicators.append("No live threat-intelligence lookup was performed.")
        recommendations = ["Confirm the website address independently before signing in or sharing sensitive information."]
        explanation = "The local structure check did not find its configured warning signs. CyberShield did not open the site, check its ownership, or compare it with live threat reports, so this is not a safety verdict."

    if not has_scheme:
        indicators.append(scheme_assumption)

    return {
        "label": label,
        "risk": risk,
        "summary": summary,
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {
            "Hostname": host,
            "Scheme": parsed.scheme.lower(),
            "Scheme supplied": "Yes" if has_scheme else "No — HTTPS assumed only for parsing",
            "HTTPS": "Yes" if parsed.scheme.lower() == "https" else "No",
            "Host is an IP address": "Yes" if host_is_ip else "No",
            "Subdomain levels": str(max(0, len(hostname_labels) - 2)),
            "URL length": f"{len(raw_url)} characters",
            "CVSS Base score": "Not assigned — this URL review did not identify a CVE-based software vulnerability.",
        },
        "target": raw_url,
    }


def calculate_cvss31_base_score(vector):
    """Calculate a CVSS v3.1 Base Score only from a complete, valid vector."""
    if isinstance(vector, str):
        vector = vector.upper()
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        return None
    metrics = {}
    for component in vector[len("CVSS:3.1/"):].split("/"):
        if ":" not in component:
            return None
        key, value = component.split(":", 1)
        if key in metrics:
            return None
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    optional_values = {
        "E": {"X", "U", "P", "F"}, "RL": {"X", "O", "T", "W", "U"},
        "RC": {"X", "U", "R", "C"}, "CR": {"X", "L", "M", "H"},
        "IR": {"X", "L", "M", "H"}, "AR": {"X", "L", "M", "H"},
        "MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"},
        "MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "R"},
        "MS": {"X", "U", "C"}, "MC": {"X", "N", "L", "H"},
        "MI": {"X", "N", "L", "H"}, "MA": {"X", "N", "L", "H"},
    }
    optional = set(optional_values)
    if not required.issubset(metrics) or not set(metrics).issubset(required | optional):
        return None
    if any(metrics[key] not in values for key, values in optional_values.items() if key in metrics):
        return None

    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }
    if metrics["S"] not in {"U", "C"}:
        return None
    if any(metrics[key] not in values for key, values in weights.items()):
        return None
    pr_weights = ({"N": 0.85, "L": 0.62, "H": 0.27} if metrics["S"] == "U"
                  else {"N": 0.85, "L": 0.68, "H": 0.50})
    if metrics["PR"] not in pr_weights:
        return None

    iss = 1 - ((1 - weights["C"][metrics["C"]])
               * (1 - weights["I"][metrics["I"]])
               * (1 - weights["A"][metrics["A"]]))
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = (8.22 * weights["AV"][metrics["AV"]]
                      * weights["AC"][metrics["AC"]]
                      * pr_weights[metrics["PR"]]
                      * weights["UI"][metrics["UI"]])
    score = min(impact + exploitability, 10) if metrics["S"] == "U" else min(1.08 * (impact + exploitability), 10)
    return math.ceil((score - 1e-10) * 10) / 10


def cvss_severity(score):
    if score is None:
        return "Not assigned"
    if score < 0 or score > 10:
        return "Invalid score"
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _file_entropy(content):
    size = len(content)
    return -sum((count / size) * math.log2(count / size) for count in Counter(content).values())


def _inspect_zip(content):
    """Inspect bounded archive metadata and small XML members without extraction."""
    details = {"Archive entries": "Unreadable", "Archive review cap": "100 members / 1 MB XML"}
    indicators = []
    findings = []
    cautions = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            details["Archive entries"] = str(len(members))
            sample = members[:100]
            if len(members) > 100:
                indicators.append("Archive member inspection was limited to the first 100 entries.")
                cautions.append("Archive is larger than the member review limit.")
            names = [item.filename for item in sample]
            normalized = [name.replace("\\", "/") for name in names]
            unsafe = [name for name in normalized if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/")]
            if unsafe:
                indicators.append(f"Found {len(unsafe)} archive path(s) using an absolute or parent-directory path. CyberShield did not extract them.")
                findings.append({"name": "Unsafe archive paths", "detail": f"{len(unsafe)} member path(s) could escape the intended extraction folder.", "severity": "High"})
            executable_suffixes = {".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}
            executable_members = [name for name in names if PurePath(name.lower()).suffix in executable_suffixes]
            if executable_members:
                indicators.append(f"Archive contains {len(executable_members)} executable or script file(s); none were run.")
                findings.append({"name": "Executable content in archive", "detail": f"{len(executable_members)} executable/script member(s) found.", "severity": "Review"})
            encrypted = sum(bool(item.flag_bits & 1) for item in sample)
            if encrypted:
                indicators.append(f"{encrypted} archive member(s) are encrypted and could not be inspected.")
                cautions.append("Encrypted archive members were not inspected.")
            high_ratio = [item for item in sample if item.file_size > 1_000_000 and item.file_size / max(item.compress_size, 1) > 1000]
            if high_ratio:
                indicators.append(f"{len(high_ratio)} archive member(s) have an unusually high compression ratio; content was not extracted.")
                findings.append({"name": "High compression ratio", "detail": f"{len(high_ratio)} member(s) exceed the local review threshold.", "severity": "Review"})
            lower_names = [name.lower() for name in names]
            document_type = next((kind for marker, kind in (("word/document.xml", "Word document (OOXML)"), ("xl/workbook.xml", "Excel workbook (OOXML)"), ("ppt/presentation.xml", "PowerPoint presentation (OOXML)")) if marker in lower_names), None)
            macros = [name for name in lower_names if name.endswith("vbaproject.bin")]
            if macros:
                indicators.append("Office document contains a VBA project. Macros were not executed; verify that they are expected.")
                findings.append({"name": "Office VBA project", "detail": "A VBA project file is present in the document archive.", "severity": "Review"})
            external_links = 0
            read_bytes = 0
            for item in sample:
                lower_name = item.filename.lower()
                if not lower_name.endswith(".rels") or item.flag_bits & 1 or item.file_size > 256_000 or read_bytes + item.file_size > 1_000_000:
                    continue
                try:
                    with archive.open(item) as member:
                        data = member.read(256_001)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                read_bytes += len(data)
                external_links += len(re.findall(rb"TargetMode\s*=\s*['\"]External['\"]", data, re.IGNORECASE))
            details["Relationship metadata read"] = f"{read_bytes} bytes"
            if external_links:
                indicators.append(f"Office relationship metadata contains {external_links} external link reference(s); links were not opened.")
                findings.append({"name": "External document links", "detail": f"{external_links} external relationship(s) found.", "severity": "Review"})
            if len(members) <= 100:
                details["Archive review"] = "Directory and supported document metadata reviewed"
            return details, indicators, findings, cautions, document_type
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        indicators.append("ZIP signature is present, but the archive directory could not be read safely.")
        findings.append({"name": "Unreadable archive", "detail": "The archive directory could not be validated.", "severity": "Review"})
        cautions.append("Archive structure is unreadable.")
        return details, indicators, findings, cautions, None


def analyze_file(filename, content):
    """Perform bounded static inspection; never execute, extract, or retain content."""
    if not content:
        raise ValueError("Choose a non-empty file to analyze.")

    name = PurePath(filename.replace("\\", "/")).name or "uploaded-file"
    suffix = PurePath(name).suffix.lower()
    size = len(content)
    digest = hashlib.sha256(content).hexdigest()

    signatures = (
        (b"MZ", "Windows executable"),
        (b"\x7fELF", "Linux executable"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"%PDF-", "PDF document"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"\x1f\x8b", "GZIP archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
    )
    detected_type = next((label for signature, label in signatures if content.startswith(signature)), None)
    if detected_type is None:
        try:
            content[:512].decode("utf-8")
        except UnicodeDecodeError:
            detected_type = "Unrecognized binary file"
        else:
            detected_type = "Text or unrecognized file"

    executable_types = {"Windows executable", "Linux executable"}
    extension_type = {
        ".exe": "Windows executable", ".dll": "Windows executable", ".scr": "Windows executable",
        ".msi": "Windows executable", ".sys": "Windows executable", ".pdf": "PDF document", ".png": "PNG image",
        ".jpg": "JPEG image", ".jpeg": "JPEG image", ".gif": "GIF image",
        ".zip": "ZIP archive", ".docx": "ZIP archive", ".docm": "ZIP archive", ".xlsx": "ZIP archive", ".xlsm": "ZIP archive", ".pptx": "ZIP archive", ".pptm": "ZIP archive",
        ".jar": "ZIP archive", ".apk": "ZIP archive", ".gz": "GZIP archive", ".rar": "RAR archive",
        ".doc": "OLE compound document", ".xls": "OLE compound document", ".ppt": "OLE compound document",
    }
    indicators = []
    findings = []
    facts = {"Detected type": detected_type, "File size": f"{size} bytes", "Extension": suffix or "None"}
    review_caution = False
    confirmed_warning = False
    if detected_type in executable_types:
        indicators.append("The file signature matches an executable format. Do not run files you do not trust.")
    if suffix in {".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}:
        indicators.append("The file extension can contain executable or script content.")
    expected_type = extension_type.get(suffix)
    if expected_type and expected_type != detected_type:
        indicators.append("The file extension does not match the recognized file signature.")
    if len(PurePath(name).suffixes) > 1 and suffix in {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs"}:
        indicators.append("The filename has multiple extensions ending in an executable or script type.")
        findings.append({"name": "Multiple file extensions", "detail": "The filename has more than one suffix and ends in an executable/script type.", "severity": "High"})
        confirmed_warning = True
    if expected_type and expected_type != detected_type:
        findings.append({"name": "Extension/signature mismatch", "detail": f"Name ends in {suffix}; the recognized signature is {detected_type}.", "severity": "High" if expected_type in executable_types or detected_type in executable_types else "Review"})
        review_caution = True
        confirmed_warning = expected_type in executable_types or detected_type in executable_types

    if detected_type == "Windows executable":
        if len(content) >= 64:
            pe_offset = int.from_bytes(content[0x3C:0x40], "little")
            if pe_offset + 8 <= len(content) and content[pe_offset:pe_offset + 4] == b"PE\0\0":
                machine = int.from_bytes(content[pe_offset + 4:pe_offset + 6], "little")
                section_count = int.from_bytes(content[pe_offset + 6:pe_offset + 8], "little")
                architectures = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM"}
                facts["PE header"] = "Valid PE signature"
                facts["PE architecture"] = architectures.get(machine, f"Unknown (0x{machine:04x})")
                facts["PE section count"] = str(section_count)
                if section_count == 0 or section_count > 96:
                    indicators.append("Executable has an unusual PE section count; review with trusted endpoint-security software.")
                    review_caution = True
            else:
                facts["PE header"] = "MZ signature found; standard PE header not confirmed"
                indicators.append("The file starts with an MZ signature, but a standard PE header was not confirmed.")
                review_caution = True
        else:
            facts["PE header"] = "MZ signature only; header too short"
            review_caution = True

    if detected_type == "ZIP archive":
        zip_facts, zip_indicators, zip_findings, zip_cautions, document_type = _inspect_zip(content)
        facts.update(zip_facts)
        indicators.extend(zip_indicators)
        findings.extend(zip_findings)
        review_caution = review_caution or bool(zip_cautions) or bool(zip_findings)
        confirmed_warning = confirmed_warning or any(item["severity"] == "High" for item in zip_findings)
        if document_type:
            detected_type = document_type
            facts["Detected type"] = detected_type
    elif detected_type in {"GZIP archive", "RAR archive"}:
        indicators.append("Compressed archive contents are not inspected for this archive format.")
        review_caution = True

    if detected_type == "OLE compound document":
        ole_text = content.decode("latin-1", errors="ignore").lower()
        macro_terms = [term for term in ("vba", "autoopen", "document_open", "workbook_open", "createobject") if term in ole_text]
        if macro_terms:
            indicators.append(f"Legacy Office document contains {len(macro_terms)} macro-related marker group(s); macros were not executed.")
            findings.append({"name": "Legacy Office macro hints", "detail": "Macro-related names or automation terms were found in the container bytes.", "severity": "Review"})
            review_caution = True

    if detected_type == "PDF document":
        pdf_patterns = (
            ("JavaScript actions", rb"/(?:JavaScript|JS)\b", "Review"),
            ("automatic open actions", rb"/OpenAction\b", "Review"),
            ("launch actions", rb"/Launch\b", "High"),
            ("embedded files", rb"/EmbeddedFile\b", "Review"),
            ("rich media objects", rb"/RichMedia\b", "Review"),
        )
        for label, pattern, severity in pdf_patterns:
            matches = len(re.findall(pattern, content, re.IGNORECASE))
            if matches:
                indicators.append(f"PDF contains {matches} {label} marker(s); the document was not rendered or executed.")
                findings.append({"name": f"PDF {label}", "detail": f"{matches} structural marker(s) found.", "severity": severity})
                review_caution = True
                confirmed_warning = confirmed_warning or severity == "High"
        if not content.rstrip().endswith(b"%%EOF"):
            indicators.append("PDF end marker is missing or not at the end; the file may be incomplete or have trailing data.")
            review_caution = True

    # Scan printable strings in both ASCII and UTF-16LE without executing the
    # upload. These heuristics are not a malware signature scan.
    ascii_strings = b" ".join(re.findall(rb"[\x20-\x7e]{4,}", content)).decode("ascii").lower()
    wide_strings = b" ".join(re.findall(rb"(?:[\x20-\x7e]\x00){4,}", content))
    utf16_strings = wide_strings.decode("utf-16le", errors="ignore").lower()
    content_text = f"{ascii_strings} {utf16_strings}"
    payload_patterns = (
        ("PowerShell download-and-execute chain", re.compile(r"(?:downloadstring|invoke-webrequest|start-bitstransfer)[\s\S]{0,240}(?:invoke-expression|\biex\b)|(?:invoke-expression|\biex\b)[\s\S]{0,240}(?:downloadstring|invoke-webrequest|start-bitstransfer)")),
        ("Shell reverse-connection pattern", re.compile(r"/dev/tcp/|bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+/bin/(?:sh|bash)")),
        ("Python socket-and-command pattern", re.compile(r"socket\.socket[\s\S]{0,500}(?:subprocess|os\.dup2)|(?:subprocess|os\.dup2)[\s\S]{0,500}socket\.socket")),
        ("JavaScript encoded-evaluation pattern", re.compile(r"(?:eval\s*\(\s*atob\s*\(|new\s+function\s*\(\s*atob\s*\()")),
        ("Windows download-and-execution API combination", re.compile(r"(?=.*(?:urldownloadtofile|internetopenurl|winhttpopenrequest))(?=.*(?:createprocess|shellexecute|winexec))")),
        ("Windows process-injection API combination", re.compile(r"(?=.*(?:virtualallocex|virtualalloc|virtualprotect))(?=.*(?:writeprocessmemory|createremotethread|queueuserapc))")),
        ("Credential or browser-data access pattern", re.compile(r"(?:credential manager|logonpasswords|lsass|login data|\bcookies\b)[\s\S]{0,180}(?:read|copy|dump|decrypt|query)|(?:read|copy|dump|decrypt|query)[\s\S]{0,180}(?:credential manager|logonpasswords|lsass|login data|\bcookies\b)")),
        ("Persistence or autorun pattern", re.compile(r"(?:currentversion\\run|schtasks\s+/create|new-service|startup folder|systemctl\s+enable|crontab\s+-[el])")),
        ("Encoded command pattern", re.compile(r"(?:-enc(?:odedcommand)?\s+[a-z0-9+/]{32,}={0,2}|frombase64string\s*\(|\bbase64\s+-d\b)")),
    )
    matched_payload_patterns = [label for label, pattern in payload_patterns if pattern.search(content_text)]
    for label in matched_payload_patterns:
        indicators.append(f"Static content check matched a {label}; this can indicate harmful behavior but may also occur in security tests or documentation.")
        findings.append({"name": label, "detail": "A configured static string pattern matched. This can be a false positive and does not confirm malicious behavior.", "severity": "High"})
    confirmed_warning = confirmed_warning or bool(matched_payload_patterns)

    entropy = _file_entropy(content)
    facts["Byte entropy"] = f"{entropy:.2f} bits/byte (context only)"
    if detected_type in executable_types and entropy >= 7.2:
        indicators.append("Executable bytes have high entropy, which can occur with packing or encryption; this alone does not prove malware.")
        findings.append({"name": "High-entropy executable", "detail": "High entropy may reflect packing, encryption, or normal bundled data.", "severity": "Review"})
        review_caution = True

    facts["Printable strings"] = str(len(re.findall(rb"[\x20-\x7e]{4,}", content)))
    facts["Static pattern groups matched"] = str(len(matched_payload_patterns))
    facts["Format-specific review"] = "Completed where supported"
    if detected_type == "ZIP archive" and facts.get("Archive entries") == "Unreadable":
        facts["Format-specific review"] = "Archive structure could not be read"
    elif detected_type in {"GZIP archive", "RAR archive"}:
        facts["Format-specific review"] = "Archive internals not inspected"

    if not indicators:
        indicators.append("No configured static warning matched; this is not proof that the file is safe.")

    caution = review_caution or confirmed_warning or any("executable" in item.lower() or "script" in item.lower() or "does not match" in item.lower() for item in indicators)
    strong_caution = any("multiple extensions" in item.lower() for item in indicators) or (
        expected_type and expected_type != detected_type
        and (expected_type in executable_types or detected_type in executable_types)
    )
    risk = "High" if strong_caution or confirmed_warning else "Low" if caution else "Normal"
    recommendations = (
        ["Do not run this file. Verify where it came from and check it with trusted endpoint-security software."]
        if caution or matched_payload_patterns else
        ["No warning was found in the limited checks. Use trusted endpoint-security software before opening an unknown file."]
    )
    if matched_payload_patterns:
        explanation = "Static content checks found one or more command or script patterns commonly associated with payload behavior. These pattern matches are heuristic and can be false positives; the file was not executed, and no antivirus or reputation scan was performed."
    elif findings:
        explanation = "CyberShield checked the file signature and performed bounded format-specific static inspection. Some structures, links, or active-content markers need review; these findings are indicators only, not proof of malware. The file was not executed and no antivirus or reputation scan was performed."
    elif detected_type in executable_types:
        explanation = "The file is a Windows or Linux executable. Limited printable-string checks did not match the configured payload patterns. Obfuscated, packed, encrypted, or otherwise unrecognized behavior may not appear in these strings; no code was executed and no antivirus scan was performed."
    elif strong_caution:
        explanation = "The file has a stronger name or signature mismatch warning. Multiple extensions or a mismatch involving executable content can disguise what a file may do. This is a warning sign, not proof that the file is malware."
    elif caution:
        explanation = "The file name or short signature indicates executable or script content. Many legitimate programs use these formats, but opening an untrusted program can run its code. No antivirus scan was performed."
    else:
        explanation = "The short signature check did not find a configured executable or extension mismatch warning. CyberShield did not inspect all file contents or run antivirus checks; archives and document internals may not have been examined."
    return {
        "label": "Potential payload pattern found" if matched_payload_patterns else "File needs review" if caution else "Basic file checks — no warning found",
        "risk": risk,
        "summary": f"Static review checked file metadata, SHA-256, signature, printable strings, and supported format-specific structure. {len(findings)} detailed indicator(s) were recorded; no antivirus or live reputation scan was performed.",
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": facts,
        "findings": findings,
        "analysis_scope": "Static local review only; no code execution or disk extraction. No antivirus engine or live reputation lookup was used.",
        "target": name,
        "file_type": detected_type,
        "size": size,
        "sha256": digest,
    }


def analyze_logs(value):
    """Review common log patterns and extract only recognized structured fields."""
    if not value or not value.strip():
        raise ValueError("Paste log lines to analyze.")
    if len(value) > 20000:
        raise ValueError("Log text must be 20,000 characters or fewer.")

    numbered_lines = [(line_number, line) for line_number, line in enumerate(value.splitlines(), start=1) if line.strip()]
    lines = [line for _, line in numbered_lines]
    if not lines:
        raise ValueError("Paste at least one non-empty log line.")
    if len(lines) > 1000:
        raise ValueError("Paste no more than 1,000 log lines at a time.")

    patterns = {
        "authentication_failures": re.compile(
            r"failed password|authentication failure|authentication failed|invalid user|login failed|failed login",
            re.IGNORECASE,
        ),
        "successful_logins": re.compile(
            r"accepted password|accepted publickey|login successful|user authenticated|session opened for user|\blogged in\b|\bsuccessful login\b|\blogin succeeded\b",
            re.IGNORECASE,
        ),
        "privileged_events": re.compile(r"\bsudo\b|privilege escalation|\brunas\b", re.IGNORECASE),
        "account_changes": re.compile(
            r"\buseradd\b|\badduser\b|new user|account (?:created|added|modified)|passwd changed|\bgroupadd\b",
            re.IGNORECASE,
        ),
    }
    counts = {name: sum(bool(pattern.search(line)) for line in lines) for name, pattern in patterns.items()}
    # Broader, explainable local event groups. These count matching lines (a
    # line may match more than one group); they are not vendor verdicts.
    event_patterns = {
        "malware_or_endpoint_alerts": re.compile(r"\b(?:malware|ransomware|trojan|virus|quarantin(?:e|ed)|endpoint detection|antivirus detection|threat detected)\b", re.IGNORECASE),
        "network_or_firewall_blocks": re.compile(r"\b(?:firewall|blocked|denied|connection refused|port scan|scan detected|ids alert|ips alert)\b", re.IGNORECASE),
        "web_or_application_attacks": re.compile(r"\b(?:sql injection|sqli|cross.site scripting|\bxss\b|path traversal|directory traversal|command injection|request smuggling|web attack)\b", re.IGNORECASE),
        "suspicious_process_or_script": re.compile(r"\b(?:powershell|encodedcommand|base64|wscript|cscript|rundll32|regsvr32|scheduled task|cron job|process injection)\b", re.IGNORECASE),
        "data_or_policy_events": re.compile(r"\b(?:data exfiltration|large upload|mass download|sensitive data|dlp|policy violation|unauthorized access|permission denied)\b", re.IGNORECASE),
        "dns_or_domain_events": re.compile(r"\b(?:dns query|dns lookup|domain blocked|sinkhole|c2|command.and.control)\b", re.IGNORECASE),
    }
    event_categories = {name: sum(bool(pattern.search(line)) for line in lines) for name, pattern in event_patterns.items()}
    failure_pattern = patterns["authentication_failures"]
    success_pattern = patterns["successful_logins"]
    ip_token_pattern = re.compile(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
        r"|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
    )
    source_field_pattern = re.compile(
        r"(?i)(?:source(?:[_ .](?:network[_ .])?address|[_ .]ip)?|src(?:_ip|addr|_addr)?|client[_ .]ip|remote[_ .](?:addr|ip))\s*[:=]\s*['\"]?([^\s,;\]}\"']+)"
    )
    destination_field_pattern = re.compile(
        r"(?i)(?:destination(?:[_ .](?:network[_ .])?address|[_ .]ip)?|dest(?:_ip|addr|_addr)?|dst(?:_ip|addr|_addr)?)\s*[:=]\s*['\"]?([^\s,;\]}\"']+)"
    )
    source_port_pattern = re.compile(r"(?i)(?:source(?:[_ .]port)?|src_port|sport|spt)\s*[:=]\s*['\"]?(\d{1,5})")
    destination_port_pattern = re.compile(r"(?i)(?:destination(?:[_ .]port)?|dest_port|dst_port|dport|dpt)\s*[:=]\s*['\"]?(\d{1,5})")
    protocol_pattern = re.compile(r"(?i)(?:protocol|proto|network\.transport)\s*[=:]\s*['\"]?([a-z0-9_-]{1,20})")
    severity_pattern = re.compile(r"(?i)(?:severity|level|loglevel)\s*[=:]\s*['\"]?(debug|info|notice|warning|warn|error|err|critical|crit|alert|emergency|fatal|low|medium|moderate|high)\b")
    cve_pattern = re.compile(r"(?i)\bCVE-\d{4}-\d{4,}\b")
    cvss_score_pattern = re.compile(r"(?i)\bCVSS(?:\s*(?:v|version)?\s*\d(?:\.\d)?)?\s*(?:base\s*)?(?:score\s*)?[:=]\s*(10(?:\.0)?|[0-9](?:\.\d)?)\b")
    cvss_vector_pattern = re.compile(r"(?i)\bCVSS:\d\.\d/[A-Z0-9:/]+")
    timestamp_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
    syslog_timestamp_pattern = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
    failure_sources = {}
    success_sources = {}
    timestamped_lines = 0
    log_events = []
    for line_number, line in numbered_lines:
        parsed_fields = _extract_log_fields(line)
        addresses = set()
        for candidate in ip_token_pattern.findall(line):
            try:
                addresses.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        def field_ip(pattern, nested_key):
            match = pattern.search(line)
            candidate = match.group(1).strip("[]()") if match else None
            if candidate:
                try:
                    return str(ipaddress.ip_address(candidate))
                except ValueError:
                    pass
            nested = re.search(
                rf"(?i)[\"']{nested_key}[\"']\s*:\s*\{{[^{{}}]{{0,512}}?[\"']ip[\"']\s*:\s*[\"']([^\"']+)",
                line,
            )
            if nested:
                try:
                    return str(ipaddress.ip_address(nested.group(1)))
                except ValueError:
                    pass
            return None

        source = field_ip(source_field_pattern, "source")
        destination = field_ip(destination_field_pattern, "destination")
        if source is None:
            source_value = _log_field_value(parsed_fields, {"source.ip", "source_ip", "src", "src.ip", "src_ip", "client.ip", "client_ip", "remote_addr", "remote.ip"})
            if source_value:
                try:
                    source = str(ipaddress.ip_address(str(source_value).strip("[]()")))
                except ValueError:
                    pass
        if destination is None:
            destination_value = _log_field_value(parsed_fields, {"destination.ip", "destination_ip", "dest", "dst", "dest.ip", "dest_ip", "dst.ip", "dst_ip"})
            if destination_value:
                try:
                    destination = str(ipaddress.ip_address(str(destination_value).strip("[]()")))
                except ValueError:
                    pass
        if source is None:
            common_log_ip = re.match(r"^\s*(\S+)\s+-\s+\S+\s+\[", line)
            if common_log_ip:
                try:
                    source = str(ipaddress.ip_address(common_log_ip.group(1)))
                except ValueError:
                    pass
        if source is None and failure_pattern.search(line):
            from_match = re.search(r"(?i)\bfrom\s+\[?([0-9a-fA-F:.]+)\]?(?:\s|$)", line)
            if from_match:
                try:
                    source = str(ipaddress.ip_address(from_match.group(1)))
                except ValueError:
                    pass
        if source is None and success_pattern.search(line):
            from_match = re.search(r"(?i)\bfrom\s+\[?([0-9a-fA-F:.]+)\]?(?:\s|$)", line)
            if from_match:
                try:
                    source = str(ipaddress.ip_address(from_match.group(1)))
                except ValueError:
                    pass
        if source is None and len(addresses) == 1 and (failure_pattern.search(line) or success_pattern.search(line)):
            source = next(iter(addresses))

        def port_value(pattern):
            match = pattern.search(line)
            if not match:
                return None
            port = int(match.group(1))
            return port if port <= 65535 else None

        def structured_port(names):
            value = _log_field_value(parsed_fields, names)
            if value is None or not str(value).isdigit():
                return None
            port = int(value)
            return port if port <= 65535 else None

        source_port = port_value(source_port_pattern) or structured_port({"source.port", "source_port", "src.port", "src_port", "sport", "spt"})
        destination_port = port_value(destination_port_pattern) or structured_port({"destination.port", "destination_port", "dest.port", "dest_port", "dst.port", "dst_port", "dport", "dpt"})
        protocol_value = _log_field_value(parsed_fields, {"protocol", "proto", "network.transport", "transport"})
        severity_value = _log_field_value(parsed_fields, {"severity", "level", "log.level", "event.severity"})

        parsed_timestamp = None
        timestamp_status = "Not present"
        timestamp_match = timestamp_pattern.search(line)
        syslog_match = None
        timestamp = None
        if timestamp_match:
            parsed_timestamp = timestamp_match.group(0)
            try:
                timestamp = datetime.fromisoformat(parsed_timestamp.replace("Z", "+00:00"))
                if timestamp.tzinfo is not None:
                    timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
                    timestamp_status = "Parsed; explicit offset normalized to UTC"
                else:
                    timestamp_status = "Parsed; timezone not supplied"
                timestamped_lines += 1
            except ValueError:
                timestamp = None
                timestamp_status = "Invalid timestamp"
        else:
            syslog_match = syslog_timestamp_pattern.search(line)
            if syslog_match:
                parsed_timestamp = syslog_match.group(0)
                try:
                    # Syslog timestamps omit the year and timezone. Use a
                    # fixed leap year for within-sample time-window checks.
                    timestamp = datetime.strptime(
                        f"2000 {parsed_timestamp}",
                        "%Y %b %d %H:%M:%S",
                    )
                    timestamp_status = "Parsed; year and timezone not supplied"
                    timestamped_lines += 1
                except ValueError:
                    timestamp = None
                    timestamp_status = "Invalid syslog timestamp"
        if parsed_timestamp is None:
            parsed_timestamp = _log_field_value(parsed_fields, {"@timestamp", "timestamp", "time", "event.created"})
            if parsed_timestamp is not None:
                timestamp_status = "Not parsed; unrecognized timestamp format"
        parsed_timestamp = parsed_timestamp or "Not present"

        matched_categories = [name for name, pattern in event_patterns.items() if pattern.search(line)]
        cves = sorted({match.upper() for match in cve_pattern.findall(line)})
        event_names = []
        if failure_pattern.search(line): event_names.append("Authentication failure")
        if success_pattern.search(line): event_names.append("Successful authentication")
        if patterns["privileged_events"].search(line): event_names.append("Privileged command")
        if patterns["account_changes"].search(line): event_names.append("Account change")
        event_names.extend(name.replace("_", " ").title() for name in matched_categories)
        if cves and not event_names:
            reported_finding = re.search(
                r"(?i)\b(?:scanner\s+findings?|vulnerability\s+findings?|findings?\s+(?:for|of|on)|"
                r"vulnerabilit(?:y|ies)\s+(?:found|detected|reported)|"
                r"(?:found|detected|reported)\s+(?:a\s+)?vulnerabilit(?:y|ies))\b",
                line,
            )
            negated_finding = re.search(
                r"(?i)\b(?:no|not|never)\s+(?:known\s+)?(?:vulnerabilit(?:y|ies)|findings?|affected)\b",
                line,
            )
            if reported_finding and not negated_finding:
                event_names.append("Vulnerability finding reported")
            else:
                event_names.append("CVE reference")
        event_name = ", ".join(dict.fromkeys(event_names)) or str(
            _log_field_value(parsed_fields, {"event.action", "event.name", "action", "event"})
            or "No configured pattern match"
        )
        cvss_score_match = cvss_score_pattern.search(line)
        if cvss_score_match and line[cvss_score_match.end():cvss_score_match.end() + 1] == "/":
            cvss_score_match = None
        if not cvss_score_match:
            structured_score = _log_field_value(parsed_fields, {"cvss.score", "cvss.base_score", "cvss.baseScore", "vulnerability.cvss.base_score"})
            if structured_score is None:
                structured_score = next((value for key, value in parsed_fields.items() if "cvss" in key.lower() and "score" in key.lower()), None)
            if structured_score is not None and re.fullmatch(r"(?:10(?:\.0)?|[0-9](?:\.\d)?)", str(structured_score)):
                cvss_score_value = str(structured_score)
            else:
                cvss_score_value = None
        else:
            cvss_score_value = cvss_score_match.group(1)
        cvss_vector_match = cvss_vector_pattern.search(line)
        if not cvss_vector_match:
            structured_vector = _log_field_value(parsed_fields, {"cvss.vector", "cvss_vector", "vulnerability.cvss.vector"})
            if structured_vector is None:
                structured_vector = next((value for key, value in parsed_fields.items() if "cvss" in key.lower() and "vector" in key.lower()), None)
            cvss_vector = str(structured_vector) if structured_vector and str(structured_vector).startswith("CVSS:") else None
        else:
            cvss_vector = cvss_vector_match.group(0).rstrip(".,;)")
        computed_cvss31 = calculate_cvss31_base_score(cvss_vector) if cvss_vector else None
        reported_score = cvss_score_value
        reported_score_value = float(reported_score) if reported_score is not None else None
        if computed_cvss31 is not None:
            cvss_note = "CVSS v3.1 Base Score calculated from the supplied Base metrics; vector not independently verified."
            if reported_score is not None and abs(float(reported_score) - computed_cvss31) >= 0.1:
                cvss_note += f" Supplied score {reported_score} differs from the calculated Base Score."
        elif cvss_vector and cvss_vector.startswith("CVSS:4.0/"):
            cvss_note = "CVSS v4.0 vector captured; score not calculated because this analyzer only implements the v3.1 Base formula."
        elif reported_score or cvss_vector:
            cvss_note = "CVSS value copied from the supplied log; not independently validated."
        else:
            cvss_note = "No CVSS vector/score supplied; no CVSS score assigned."
        if source_port is None and source and (failure_pattern.search(line) or success_pattern.search(line)):
            ssh_port = re.search(r"(?i)\bfrom\s+\[?[0-9a-fA-F:.]+\]?\s+port\s+(\d{1,5})\b", line)
            if ssh_port and int(ssh_port.group(1)) <= 65535:
                source_port = int(ssh_port.group(1))
        protocol_match = protocol_pattern.search(line)
        severity_match = severity_pattern.search(line)
        log_events.append({
            "line": line_number,
            "timestamp": parsed_timestamp or "Not present",
            "timestamp_status": timestamp_status,
            "event": event_name,
                "severity": (severity_match.group(1).upper() if severity_match else str(severity_value).upper() if severity_value else "Not specified"),
            "source_ip": source or "Not present",
            "source_port": str(source_port) if source_port is not None else "Not present",
            "destination_ip": destination or "Not present",
            "destination_port": str(destination_port) if destination_port is not None else "Not present",
            "other_ips": sorted(addresses - {item for item in (source, destination) if item}),
                "protocol": (protocol_match.group(1).upper() if protocol_match else str(protocol_value).upper() if protocol_value else "Not present"),
            "cves": cves,
            "cvss_as_reported": reported_score or "Not present",
            "cvss_reported_severity": cvss_severity(reported_score_value),
            "cvss_vector_as_reported": cvss_vector or "Not present",
            "cvss_base_calculated": f"{computed_cvss31:.1f}" if computed_cvss31 is not None else "Not calculated",
            "cvss_severity": cvss_severity(computed_cvss31) if computed_cvss31 is not None else "Not assigned",
            "cvss_note": cvss_note,
            "fields": parsed_fields,
            "line_excerpt": _sanitize_log_line(line),
        })
        event = (line_number, timestamp)
        if source and failure_pattern.search(line):
            failure_sources.setdefault(source, []).append(event)
        if source and success_pattern.search(line):
            success_sources.setdefault(source, []).append(event)

    repeated_failure_sources = {source: events for source, events in failure_sources.items() if len(events) >= 2}
    rapid_failure_sources = set()
    burst_failure_sources = set()
    for source, events in failure_sources.items():
        timed = sorted((ts, line_number) for line_number, ts in events if ts is not None)
        for start_index, (start_time, _) in enumerate(timed):
            end_index = start_index + 1
            while end_index < len(timed):
                end_time = timed[end_index][0]
                if (end_time - start_time).total_seconds() > 300:
                    break
                end_index += 1
            window_count = end_index - start_index
            if window_count >= 2:
                rapid_failure_sources.add(source)
            if window_count >= 5:
                burst_failure_sources.add(source)
                break

    failures_then_success = set()
    for source in set(failure_sources) & set(success_sources):
        failures = failure_sources[source]
        successes = success_sources[source]
        if any(
            success_time > failure_time if success_time is not None and failure_time is not None
            else success_line > failure_line
            for success_line, success_time in successes
            for failure_line, failure_time in failures
        ):
            failures_then_success.add(source)

    reported_vulnerability_events = [
        event for event in log_events
        if "Vulnerability finding reported" in event["event"]
    ]
    high_cvss_vulnerability_events = [
        event for event in reported_vulnerability_events
        if event["cvss_base_calculated"] != "Not calculated"
        and float(event["cvss_base_calculated"]) >= 7.0
    ]

    indicators = []
    failed = counts["authentication_failures"]
    if failed:
        indicators.append(f"Found {failed} log line(s) matching common authentication-failure wording.")
        if failed >= 10:
            indicators.append("The number of matching failures is high enough to review against expected activity.")
    if repeated_failure_sources:
        repeated_attempts = sum(len(events) for events in repeated_failure_sources.values())
        indicators.append(f"Repeated authentication failures came from {len(repeated_failure_sources)} source address(es), accounting for {repeated_attempts} failed line(s). Parsed addresses appear in the detailed event table when the log format identifies them explicitly.")
    if rapid_failure_sources:
        indicators.append(f"At least 2 authentication failures from the same source occurred within 5 minutes for {len(rapid_failure_sources)} source address(es). Parsed addresses appear in the detailed event table when identifiable.")
    if burst_failure_sources:
        indicators.append(f"At least 5 authentication failures from the same source occurred within a 5-minute window for {len(burst_failure_sources)} source address(es). This pattern needs prompt review.")
    if failures_then_success:
        indicators.append(f"A successful login followed failed attempts from the same source address for {len(failures_then_success)} source address(es). Confirm the account owner and session activity.")
    if counts["successful_logins"]:
        indicators.append(f"Found {counts['successful_logins']} line(s) matching common successful-login wording.")
    if reported_vulnerability_events:
        indicators.append(
            f"The input reports {len(reported_vulnerability_events)} vulnerability finding(s). CVE identifiers, affected products, and scanner results were not independently verified."
        )
    for event in high_cvss_vulnerability_events:
        indicators.append(
            f"A reported vulnerability finding has a calculated CVSS v3.1 Base score of {event['cvss_base_calculated']} ({event['cvss_severity']}) from the supplied vector. Confirm the vector, affected asset, and remediation status in the source scanner."
        )
    if counts["privileged_events"]:
        indicators.append(f"Found {counts['privileged_events']} line(s) mentioning privileged commands; confirm they were expected.")
    if counts["account_changes"]:
        indicators.append(f"Found {counts['account_changes']} line(s) matching common account or group change wording.")
    category_labels = {
        "malware_or_endpoint_alerts": "malware or endpoint alerts",
        "network_or_firewall_blocks": "network or firewall events",
        "web_or_application_attacks": "web or application attack patterns",
        "suspicious_process_or_script": "suspicious process or script wording",
        "data_or_policy_events": "data or policy events",
        "dns_or_domain_events": "DNS or domain events",
    }
    for name, count in event_categories.items():
        if count:
            indicators.append(f"Found {count} line(s) matching {category_labels[name]} wording. Review the original event details in your trusted log source.")

    needs_review = bool(
        failed or counts["privileged_events"] or counts["account_changes"]
        or any(event_categories.values()) or reported_vulnerability_events
    )
    if not indicators:
        indicators.append("No configured keyword patterns matched; this does not prove the log is clean.")
    any_match = any(counts.values())
    # A keyword like "malware" or "SQL injection" may appear in a test,
    # policy, or negative result. Keep those as review leads. Escalate only
    # the locally correlated authentication patterns, and describe them as
    # suspicious rather than confirmed compromise.
    high_risk = bool(burst_failure_sources or failures_then_success or high_cvss_vulnerability_events)
    if high_risk:
        recommendations = ["Review the matching events and affected assets in the original system. Confirm scanner evidence and remediation status, and follow your organization's incident process if the activity was not expected."]
        explanations = []
        if burst_failure_sources or failures_then_success:
            explanations.append("The log contains a correlated authentication pattern: at least five failures from one source within five minutes, or a successful login from a source that had earlier failures. This is a high-priority review lead, not proof that an account was compromised.")
        if high_cvss_vulnerability_events:
            explanations.append("The log also reports a vulnerability finding with a calculated CVSS v3.1 Base score of 7.0 or higher from a supplied vector. The score math was calculated locally; the CVE, affected asset, scanner evidence, and remediation state were not independently verified.")
        explanation = " ".join(explanations)
    elif needs_review:
        recommendations = ["Review the matching log entries in context. Confirm any reported vulnerability against the source scanner and affected asset before acting."]
        if reported_vulnerability_events and not (failed or counts["privileged_events"] or counts["account_changes"] or any(event_categories.values())):
            explanation = "The input reports one or more vulnerability findings, but no complete CVSS v3.1 vector at High or Critical severity was available. CyberShield did not verify the CVE, affected product, scanner evidence, or remediation status."
        elif failed and rapid_failure_sources:
            explanation = f"The sample has {failed} authentication-failure line(s), including at least 2 from the same source within 5 minutes. No same-source successful login, five-failure burst, privileged command, or account change was identified. This warrants review, but the small sample does not meet the stronger alert threshold."
        elif failed and repeated_failure_sources:
            explanation = f"The sample has {failed} authentication-failure line(s), including repeated attempts from the same source. No same-source successful login, five-failure burst, privileged command, or account change was identified. This warrants review, but the small sample does not meet the stronger alert threshold."
        else:
            explanation = "One or more lines matched common failure, privileged-command, or account-change phrases. The analyzer searches words and correlates visible timestamps and source addresses; it cannot validate the event source or determine whether the action was authorized."
    else:
        recommendations = ["No configured warning keywords matched. Compare with other system logs; this does not prove the system is safe."]
        explanation = "No configured high-priority phrases matched. If successful-login phrases were found, they are shown as counts; absence of warning phrases does not prove the system is free of suspicious activity."
    return {
        "label": (
            "Log activity needs review" if needs_review
            else "Log patterns found — no high-priority indicator" if any_match
            else "No matching patterns — no warning found"
        ),
        "risk": "High" if high_risk else "Low" if needs_review else "Normal",
        "summary": f"Reviewed {len(lines)} non-empty log line(s) across authentication, privilege, account-change, malware, network, web-attack, process, data-policy, and DNS pattern groups. This is a local text-pattern review; matching wording is not proof of an attack.",
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {
            "Lines reviewed": str(len(lines)),
            "Authentication failures": str(failed),
            "Successful login phrases": str(counts["successful_logins"]),
            "Privileged command phrases": str(counts["privileged_events"]),
            "Account change phrases": str(counts["account_changes"]),
            "Distinct failure sources": str(len(failure_sources)),
            "Repeated failure sources": str(len(repeated_failure_sources)),
            "Sources with 2+ failures within 5 minutes": str(len(rapid_failure_sources)),
            "Failure sources followed by success": str(len(failures_then_success)),
            "Timestamped lines": str(timestamped_lines),
            "Log format coverage": f"Recognized timestamps on {timestamped_lines} of {len(lines)} lines",
            "Timestamp interpretation": "Explicit UTC offsets are normalized to UTC; timestamps without a timezone are compared as if they share one timezone; syslog dates omit the year and timezone.",
            "Event category matches": str(sum(event_categories.values())),
            "Log lines with detailed records": str(len(log_events)),
            "Unique IP addresses observed": str(len({address for event in log_events for address in event["other_ips"]} | {event["source_ip"] for event in log_events if event["source_ip"] != "Not present"} | {event["destination_ip"] for event in log_events if event["destination_ip"] != "Not present"})),
            "CVSS Base score": "Calculated only from a complete CVSS v3.1 vector in the input; otherwise left unassigned.",
        },
        "target": f"Pasted log sample ({len(lines)} lines)",
        "line_count": len(lines),
        "counts": {**counts, "distinct_failure_sources": len(failure_sources), "repeated_failure_sources": len(repeated_failure_sources), "rapid_failure_sources": len(rapid_failure_sources), "failures_then_success": len(failures_then_success), "timestamped_lines": timestamped_lines},
        "event_categories": event_categories,
        "log_events": log_events,
        "analysis_scope": (
            "Local log parsing only; every non-empty input line is represented in the report. The original unmodified text is not retained; a sanitized line excerpt and recognized structured fields are saved. "
            "Common password, token, cookie, authorization, and secret fields are redacted. "
            "The report uses CVE identifiers and CVSS scores, vectors, and severity values found in the submitted logs. CVSS v3.1 Base is calculated only from a complete vector present in the input; CVSS v4 and unscored CVE IDs are recorded without inventing a score. "
            "CVE validity, affected products, and supplied scanner evidence are not independently verified. "
            "No Nessus plugin scan, external CVE lookup, or live threat-intelligence query was performed."
        ),
    }


def analyze_nessus_report(content):
    """Parse a bounded Nessus v2 export without treating it as a live rescan."""
    if not isinstance(content, (bytes, bytearray)) or not content:
        raise ValueError("Choose a non-empty Nessus .nessus report.")
    if len(content) > 5 * 1024 * 1024:
        raise ValueError("Nessus report is too large. Maximum size is 5 MB.")

    try:
        if content.startswith((b"\xff\xfe", b"\xfe\xff")):
            xml_text = bytes(content).decode("utf-16")
        else:
            xml_text = bytes(content).decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("Nessus report must be encoded as UTF-8 or UTF-16 XML.") from error
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml_text, re.IGNORECASE):
        raise ValueError("Nessus reports with DTD or custom entity declarations are not supported.")
    try:
        root = ET.fromstring(bytes(content))
    except ET.ParseError as error:
        raise ValueError("The uploaded file is not valid Nessus XML.") from error
    if root.tag.rsplit("}", 1)[-1] != "NessusClientData_v2":
        raise ValueError("The XML root is not a Nessus v2 report.")

    def child_text(node, name, default=""):
        if node is None:
            return default
        for child in node:
            if child.tag.rsplit("}", 1)[-1] == name:
                return (child.text or "").strip()
        return default

    def source_score(node, name):
        raw = child_text(node, name)
        if not raw:
            return "Not provided"
        try:
            numeric = float(raw)
        except ValueError:
            return f"Invalid source value: {raw[:80]}"
        if not math.isfinite(numeric) or not 0 <= numeric <= 10:
            return f"Invalid source value: {raw[:80]}"
        return f"{numeric:.1f}"

    def child_values(node, name, limit=40):
        return [
            (child.text or "").strip()[:500]
            for child in node
            if child.tag.rsplit("}", 1)[-1] == name and (child.text or "").strip()
        ][:limit]

    reports = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Report"]
    report_name = reports[0].get("name", "Nessus scan") if reports else "Nessus scan"
    host_nodes = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "ReportHost"]
    severity_labels = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    risk_labels = {0: "Normal", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    counts = {label: 0 for label in severity_labels.values()}
    findings = []
    assets = set()
    highest_severity = 0
    total_items = 0
    score_mismatches = 0
    max_findings = 1000
    truncated = False

    for host_node in host_nodes:
        host_name = host_node.get("name", "Unknown asset")[:255]
        assets.add(host_name)
        properties = {}
        for properties_node in host_node:
            if properties_node.tag.rsplit("}", 1)[-1] == "HostProperties":
                for tag in properties_node:
                    if tag.tag.rsplit("}", 1)[-1] == "tag" and tag.get("name"):
                        properties[tag.get("name", "").lower()] = (tag.text or "").strip()[:500]
                break
        asset_ip = properties.get("host-ip", "")
        asset_name = properties.get("host-fqdn") or properties.get("host-rdns") or host_name
        host_os = properties.get("operating-system", "")
        for item in host_node:
            if item.tag.rsplit("}", 1)[-1] != "ReportItem":
                continue
            total_items += 1
            try:
                scanner_severity = int(item.get("severity", ""))
            except ValueError:
                scanner_severity = None
            if scanner_severity not in severity_labels:
                severity = "Not specified"
                scanner_risk = child_text(item, "risk_factor", "Not specified")[:80]
            else:
                severity = severity_labels[scanner_severity]
                scanner_risk = child_text(item, "risk_factor", severity)[:80]
                counts[severity] += 1
                highest_severity = max(highest_severity, scanner_severity)
            if len(findings) >= max_findings:
                truncated = True
                continue

            cves = sorted({(tag.text or "").strip().upper() for tag in item if tag.tag.rsplit("}", 1)[-1] == "cve" and (tag.text or "").strip()})
            cvss3_vector = child_text(item, "cvss3_vector") or child_text(item, "cvss3_vector_string")
            cvss3_reported = source_score(item, "cvss3_base_score")
            if cvss3_reported.startswith("Invalid source value:"):
                cvss3_reported_for_math = ""
            else:
                cvss3_reported_for_math = cvss3_reported if cvss3_reported != "Not provided" else ""
            calculated_cvss31 = calculate_cvss31_base_score(cvss3_vector) if cvss3_vector.startswith("CVSS:3.1/") else None
            cvss3_note = ""
            if calculated_cvss31 is not None:
                cvss3_note = "CVSS v3.1 Base calculated from the vector included in this report; vector and finding were not independently verified."
                if cvss3_reported.startswith("Invalid source value:"):
                    cvss3_note += " The imported score field is invalid."
                    score_mismatches += 1
                elif cvss3_reported_for_math and abs(float(cvss3_reported_for_math) - calculated_cvss31) >= 0.1:
                    cvss3_note += f" Imported score {cvss3_reported} differs from the locally calculated score."
                    score_mismatches += 1
            elif cvss3_vector:
                cvss3_note = "Vector retained as reported; local Base calculation is only implemented for CVSS v3.1."
            elif cvss3_reported.startswith("Invalid source value:"):
                cvss3_note = f"{cvss3_reported} No complete CVSS v3.1 vector was supplied for recalculation."
            elif cvss3_reported != "Not provided":
                cvss3_note = "Score retained as reported; no complete CVSS v3.1 vector was supplied for recalculation."
            else:
                cvss3_note = "No CVSS v3.1 score or vector was supplied."

            findings.append({
                "plugin_id": item.get("pluginID", "Not provided")[:80],
                "plugin_name": item.get("pluginName", "Unnamed Nessus finding")[:300],
                "plugin_family": item.get("pluginFamily", "Not provided")[:200],
                "severity": severity,
                "severity_number": scanner_severity if scanner_severity in severity_labels else None,
                "risk_factor": scanner_risk,
                "asset": asset_name,
                "asset_ip": asset_ip or "Not provided",
                "operating_system": host_os or "Not provided",
                "port": item.get("port", "0")[:20],
                "protocol": item.get("protocol", "Not provided")[:40],
                "service": item.get("svc_name", "Not provided")[:120],
                "cves": cves,
                "cvss2_score": source_score(item, "cvss_base_score"),
                "cvss2_vector": child_text(item, "cvss_vector") or "Not provided",
                "cvss2_temporal_score": source_score(item, "cvss_temporal_score"),
                "cvss2_temporal_vector": child_text(item, "cvss_temporal_vector") or "Not provided",
                "cvss3_score_reported": cvss3_reported or "Not provided",
                "cvss3_vector": cvss3_vector or "Not provided",
                "cvss3_temporal_score": source_score(item, "cvss3_temporal_score"),
                "cvss3_temporal_vector": child_text(item, "cvss3_temporal_vector") or "Not provided",
                "cvss3_score_calculated": f"{calculated_cvss31:.1f}" if calculated_cvss31 is not None else "Not calculated",
                "cvss3_severity_calculated": cvss_severity(calculated_cvss31) if calculated_cvss31 is not None else "Not assigned",
                "cvss3_note": cvss3_note,
                "cvss4_score_reported": source_score(item, "cvss4_base_score"),
                "cvss4_vector": child_text(item, "cvss4_vector") or "Not provided",
                "plugin_type": child_text(item, "plugin_type", "Not provided")[:120],
                "plugin_version": child_text(item, "plugin_version", "Not provided")[:120],
                "plugin_publication_date": child_text(item, "plugin_publication_date", "Not provided")[:120],
                "plugin_modification_date": child_text(item, "plugin_modification_date", "Not provided")[:120],
                "patch_publication_date": child_text(item, "patch_publication_date", "Not provided")[:120],
                "exploit_available": child_text(item, "exploit_available", "Not provided")[:80],
                "exploit_frameworks": {
                    name: child_text(item, name)[:300]
                    for name in ("exploit_framework_metasploit", "exploit_framework_canvas", "exploit_framework_core")
                    if child_text(item, name)
                },
                "references": {
                    name: child_values(item, name)
                    for name in ("cwe", "bid", "xref", "see_also", "cpe")
                    if child_values(item, name)
                },
                "synopsis": child_text(item, "synopsis", "Not provided")[:1000],
                "description": child_text(item, "description", "Not provided")[:5000],
                "solution": child_text(item, "solution", "Not provided")[:3000],
                "plugin_output": _sanitize_log_line(child_text(item, "plugin_output", "Not provided"))[:5000],
            })

    if not host_nodes:
        raise ValueError("The Nessus report contains no scan hosts.")
    if total_items == 0:
        raise ValueError("The Nessus report contains no scan findings.")

    worst = risk_labels.get(highest_severity, "Normal")
    indicators = [
        f"Imported {len(findings)} of {total_items} Nessus finding(s) across {len(assets)} asset(s).",
        "Severity, plugin identifiers, CVEs, and supplied scores are shown as values from the uploaded Nessus report.",
        "No new network scan, CVE database lookup, or independent verification was performed.",
    ]
    if truncated:
        indicators.append(f"The report contained more than {max_findings} findings; only the first {max_findings} were included in the detailed result.")
    if score_mismatches:
        indicators.append(f"{score_mismatches} imported CVSS v3 score(s) differ from the local v3.1 calculation or contain invalid numeric values; compare each value and vector with its source report.")

    report_name = _sanitize_log_line(report_name)[:300]
    return {
        "module": "Nessus Report",
        "label": "Imported Nessus scan report",
        "risk": worst,
        "summary": f"Imported {len(findings)} of {total_items} Nessus finding(s) from {len(assets)} asset(s). Highest severity reported by Nessus: {severity_labels.get(highest_severity, 'Informational')}.",
        "explanation": "This result summarizes the supplied Nessus export. It does not run a scan or independently confirm that a listed vulnerability affects the asset.",
        "analysis_scope": "This report is generated from findings in the imported Nessus v2 XML, including its CVE identifiers, scanner severity, and CVSS v2/v3/v4 values and vectors. CVSS v3.1 Base is recalculated only when a complete v3.1 vector is present; other scores remain source-reported. CVEs, affected assets, and plugin evidence are not independently verified; no CVE lookup or new network scan was performed.",
        "facts": {
            "Source report": report_name,
            "Assets reported": str(len(assets)),
            "Findings in source": str(total_items),
            "Detailed findings included": str(len(findings)),
            "Informational findings": str(counts["Informational"]),
            "Low findings": str(counts["Low"]),
            "Medium findings": str(counts["Medium"]),
            "High findings": str(counts["High"]),
            "Critical findings": str(counts["Critical"]),
            "CVSS v3.1 mismatches / invalid values": str(score_mismatches),
            "CVSS validation": "CVSS v3.1 scores recalculated only from complete v3.1 vectors; other versions left as reported.",
        },
        "indicators": indicators,
        "recommendations": ["Confirm each finding's asset, plugin output, and remediation status in the originating Nessus installation before acting."],
        "nessus_report_name": report_name,
        "nessus_findings": findings,
        "nessus_counts": counts,
        "nessus_total_items": total_items,
        "counts": counts,
        "target": f"Nessus report: {report_name}",
    }
