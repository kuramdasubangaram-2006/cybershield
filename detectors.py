"""Local-only analysis helpers. These functions never contact submitted hosts."""

import hashlib
import ipaddress
import re
from pathlib import PurePath
from urllib.parse import urlsplit


def analyze_ip(value):
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from error

    if address.is_loopback:
        label = "Loopback address"
        risk = "Informational"
        summary = "This address points back to the same device; it is not a public reputation result."
        indicators = ["The address is reserved for the local device."]
    elif address.is_link_local:
        label = "Link-local address"
        risk = "Informational"
        summary = "This address is used on a local network and is not globally reachable."
        indicators = ["The address is link-local."]
    elif address.is_private:
        label = "Private network address"
        risk = "Informational"
        summary = "This address belongs to a private network; its public threat reputation cannot be checked here."
        indicators = ["The address is not globally routable."]
    elif address.is_multicast or address.is_unspecified or address.is_reserved:
        label = "Special-purpose address"
        risk = "Review"
        summary = "This is a special-purpose address, not a normal public host reputation result."
        indicators = ["The address is reserved for a special networking purpose."]
    elif address.is_global:
        label = "Public IP — reputation unverified"
        risk = "Unverified"
        summary = "The address is globally routable. No threat-intelligence source is connected, so its reputation is unknown."
        indicators = ["Local format and address-range checks only; no live reputation lookup was performed."]
    else:
        label = "Non-public address"
        risk = "Informational"
        summary = "This address is not globally routable. No public threat reputation was checked."
        indicators = ["The address is outside the public global address space."]

    return {
        "label": label,
        "risk": risk,
        "summary": summary,
        "indicators": indicators,
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

    if not has_scheme:
        caution_indicators.append("The scheme was omitted; HTTPS was assumed for parsing.")
    elif parsed.scheme.lower() != "https":
        caution_indicators.append("The URL does not use HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        strong_indicators.append("The URL contains user information before the hostname.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
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

    if strong_indicators:
        label = "Structural warning"
        risk = "High"
        summary = "Potentially deceptive URL structure found. Do not open it until it has been reviewed."
    elif caution_indicators:
        label = "Needs review"
        risk = "Review"
        summary = "Some structural caution signs were found. No live threat-reputation check was performed."
    else:
        label = "No obvious structural warning — unverified"
        risk = "Unverified"
        summary = "No obvious structural warning was found. This does not confirm that the URL is safe."
        indicators.append("No live threat-intelligence lookup was performed.")

    return {
        "label": label,
        "risk": risk,
        "summary": summary,
        "indicators": indicators,
        "target": raw_url,
    }


def analyze_file(filename, content):
    """Inspect file metadata and a few signatures; never execute or retain content."""
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
        ".msi": "Windows executable", ".pdf": "PDF document", ".png": "PNG image",
        ".jpg": "JPEG image", ".jpeg": "JPEG image", ".gif": "GIF image",
        ".zip": "ZIP archive", ".gz": "GZIP archive", ".rar": "RAR archive",
        ".doc": "OLE compound document", ".xls": "OLE compound document", ".ppt": "OLE compound document",
    }
    indicators = []
    if detected_type in executable_types:
        indicators.append("The file signature matches an executable format. Do not run files you do not trust.")
    if suffix in {".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}:
        indicators.append("The file extension can contain executable or script content.")
    expected_type = extension_type.get(suffix)
    if expected_type and expected_type != detected_type:
        indicators.append("The file extension does not match the recognized file signature.")
    if len(PurePath(name).suffixes) > 1 and suffix in {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs"}:
        indicators.append("The filename has multiple extensions ending in an executable or script type.")
    if detected_type in {"ZIP archive", "GZIP archive", "RAR archive"}:
        indicators.append("Archive contents were not opened or inspected.")
    if detected_type == "OLE compound document":
        indicators.append("This legacy document container can hold different content; its internal contents were not inspected.")
    if not indicators:
        indicators.append("Only the file name, size, SHA-256 hash, and a short file signature were checked.")

    caution = any("executable" in item.lower() or "script" in item.lower() or "does not match" in item.lower() for item in indicators)
    return {
        "label": "File needs review" if caution else "Basic file checks — unverified",
        "risk": "Review" if caution else "Unverified",
        "summary": "Basic metadata and file-signature checks only. No antivirus scan was performed, so this file is not confirmed safe.",
        "indicators": indicators,
        "target": name,
        "file_type": detected_type,
        "size": size,
        "sha256": digest,
    }


def analyze_logs(value):
    """Count a few common log phrases locally; never retain submitted log text."""
    if not value or not value.strip():
        raise ValueError("Paste log lines to analyze.")
    if len(value) > 20000:
        raise ValueError("Log text must be 20,000 characters or fewer.")

    lines = [line for line in value.splitlines() if line.strip()]
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
            r"accepted password|accepted publickey|login successful|user authenticated|session opened for user",
            re.IGNORECASE,
        ),
        "privileged_events": re.compile(r"\bsudo\b|privilege escalation|\brunas\b", re.IGNORECASE),
        "account_changes": re.compile(
            r"\buseradd\b|\badduser\b|new user|account (?:created|added|modified)|passwd changed|\bgroupadd\b",
            re.IGNORECASE,
        ),
    }
    counts = {name: sum(bool(pattern.search(line)) for line in lines) for name, pattern in patterns.items()}
    indicators = []
    failed = counts["authentication_failures"]
    if failed:
        indicators.append(f"Found {failed} log line(s) matching common authentication-failure wording.")
        if failed >= 10:
            indicators.append("The number of matching failures is high enough to review against expected activity.")
    if counts["successful_logins"]:
        indicators.append(f"Found {counts['successful_logins']} line(s) matching common successful-login wording.")
    if counts["privileged_events"]:
        indicators.append(f"Found {counts['privileged_events']} line(s) mentioning privileged commands; confirm they were expected.")
    if counts["account_changes"]:
        indicators.append(f"Found {counts['account_changes']} line(s) matching common account or group change wording.")

    needs_review = bool(failed or counts["privileged_events"] or counts["account_changes"])
    if not indicators:
        indicators.append("No configured keyword patterns matched; this does not prove the log is clean.")
    any_match = any(counts.values())
    return {
        "label": (
            "Log activity needs review" if needs_review
            else "Log patterns found — unverified" if any_match
            else "No matching patterns — unverified"
        ),
        "risk": "Review" if needs_review else "Unverified",
        "summary": f"Basic keyword checks reviewed {len(lines)} non-empty log line(s). This is not a complete security analysis.",
        "indicators": indicators,
        "target": f"Pasted log sample ({len(lines)} lines)",
        "line_count": len(lines),
        "counts": counts,
    }
