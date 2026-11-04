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

    if not has_scheme:
        caution_indicators.append("The scheme was omitted; HTTPS was assumed for parsing.")
    elif parsed.scheme.lower() != "https":
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

    if strong_indicators:
        label = "Structural warning"
        risk = "High"
        summary = "Potentially deceptive URL structure found. Do not open it until it has been reviewed."
        recommendations = ["Do not open the URL or enter credentials. Verify the complete hostname with the expected organization through a trusted channel."]
        explanation = "One or more stronger URL-structure warning signs matched. An IP address in place of a domain, hidden user information, or punycode can make a destination harder to recognize. These signs are reasons to inspect the link; they do not prove that the site is malicious."
    elif caution_indicators:
        label = "Needs review"
        risk = "Low"
        summary = "Some structural caution signs were found. No live threat-reputation check was performed."
        recommendations = ["Check the hostname and scheme carefully. Avoid entering passwords until you confirm the destination."]
        explanation = "Some caution signs matched, such as a non-HTTPS scheme, many subdomain levels, or an unusually long URL. These can occur on ordinary sites too, so verify the exact destination before using it."
    else:
        label = "No obvious structural warning — unverified"
        risk = "Normal"
        summary = "No obvious structural warning was found. This does not confirm that the URL is safe."
        indicators.append("No live threat-intelligence lookup was performed.")
        recommendations = ["Confirm the website address independently before signing in or sharing sensitive information."]
        explanation = "The local structure check did not find its configured warning signs. CyberShield did not open the site, check its ownership, or compare it with live threat reports, so this is not a safety verdict."

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
            "HTTPS": "Yes" if parsed.scheme.lower() == "https" else "No",
            "Host is an IP address": "Yes" if host_is_ip else "No",
            "Subdomain levels": str(max(0, len(hostname_labels) - 2)),
            "URL length": f"{len(raw_url)} characters",
        },
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
    strong_caution = any("multiple extensions" in item.lower() for item in indicators) or (
        expected_type and expected_type != detected_type
        and (expected_type in executable_types or detected_type in executable_types)
    )
    risk = "High" if strong_caution else "Low" if caution else "Normal"
    recommendations = (
        ["Do not run this file. Verify where it came from and check it with trusted endpoint-security software."]
        if caution else
        ["No warning was found in the limited checks. Use trusted endpoint-security software before opening an unknown file."]
    )
    if strong_caution:
        explanation = "The file has a stronger name or signature mismatch warning. Multiple extensions or a mismatch involving executable content can disguise what a file may do. This is a warning sign, not proof that the file is malware."
    elif caution:
        explanation = "The file name or short signature indicates executable or script content. Many legitimate programs use these formats, but opening an untrusted program can run its code. No antivirus scan was performed."
    else:
        explanation = "The short signature check did not find a configured executable or extension mismatch warning. CyberShield did not inspect all file contents or run antivirus checks; archives and document internals may not have been examined."
    return {
        "label": "File needs review" if caution else "Basic file checks — no warning found",
        "risk": risk,
        "summary": "Basic metadata and file-signature checks only. No antivirus scan was performed, so this file is not confirmed safe.",
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {"Detected type": detected_type, "File size": f"{size} bytes", "Extension": suffix or "None"},
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
    if failed >= 10:
        recommendations = ["Review the source addresses and times, confirm whether the attempts were expected, and secure affected accounts if they were not."]
        explanation = "Many lines matched common authentication-failure phrases. This can be consistent with repeated guessing, but it could also be expected activity or duplicated logging. Check timing, source addresses, and account context."
    elif needs_review:
        recommendations = ["Review the matching log entries in context and confirm that the account or privileged activity was expected."]
        explanation = "One or more lines matched common failure, privileged-command, or account-change phrases. The analyzer searches words only; it does not validate the event source or determine whether the action was authorized."
    else:
        recommendations = ["No configured warning keywords matched. Compare with other system logs; this does not prove the system is safe."]
        explanation = "No configured high-priority phrases matched. If successful-login phrases were found, they are shown as counts; absence of warning phrases does not prove the system is free of suspicious activity."
    return {
        "label": (
            "Log activity needs review" if needs_review
            else "Log patterns found — no high-priority indicator" if any_match
            else "No matching patterns — no warning found"
        ),
        "risk": "High" if failed >= 10 else "Low" if needs_review else "Normal",
        "summary": f"Basic keyword checks reviewed {len(lines)} non-empty log line(s). This is not a complete security analysis.",
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {
            "Lines reviewed": str(len(lines)),
            "Authentication failures": str(failed),
            "Successful login phrases": str(counts["successful_logins"]),
            "Privileged command phrases": str(counts["privileged_events"]),
            "Account change phrases": str(counts["account_changes"]),
        },
        "target": f"Pasted log sample ({len(lines)} lines)",
        "line_count": len(lines),
        "counts": counts,
    }
