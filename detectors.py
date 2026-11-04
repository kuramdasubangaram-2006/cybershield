"""Local-only analysis helpers. These functions never contact submitted hosts."""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
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
    )
    matched_payload_patterns = [label for label, pattern in payload_patterns if pattern.search(content_text)]
    for label in matched_payload_patterns:
        indicators.append(f"Static content check matched a {label}; this can indicate harmful behavior but may also occur in security tests or documentation.")

    if not indicators:
        indicators.append("Only the file name, size, SHA-256 hash, and a short file signature were checked.")

    caution = any("executable" in item.lower() or "script" in item.lower() or "does not match" in item.lower() for item in indicators)
    strong_caution = any("multiple extensions" in item.lower() for item in indicators) or (
        expected_type and expected_type != detected_type
        and (expected_type in executable_types or detected_type in executable_types)
    )
    risk = "High" if strong_caution or matched_payload_patterns else "Low" if caution else "Normal"
    recommendations = (
        ["Do not run this file. Verify where it came from and check it with trusted endpoint-security software."]
        if caution or matched_payload_patterns else
        ["No warning was found in the limited checks. Use trusted endpoint-security software before opening an unknown file."]
    )
    if matched_payload_patterns:
        explanation = "Static content checks found one or more command or script patterns commonly associated with payload behavior. These pattern matches are heuristic and can be false positives; the file was not executed, and no antivirus or reputation scan was performed."
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
        "summary": "Basic metadata, file signature, printable strings, and limited command or API-pattern combinations were checked. No antivirus scan was performed, so this file is not confirmed safe.",
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "facts": {"Detected type": detected_type, "File size": f"{size} bytes", "Extension": suffix or "None", "Static pattern groups matched": str(len(matched_payload_patterns))},
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
    failure_pattern = patterns["authentication_failures"]
    success_pattern = patterns["successful_logins"]
    source_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    timestamp_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
    failure_sources = {}
    success_sources = {}
    timestamped_lines = 0
    for line_number, line in enumerate(lines, start=1):
        addresses = set()
        for candidate in source_pattern.findall(line):
            try:
                addresses.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        source = next(iter(addresses)) if len(addresses) == 1 else None
        timestamp_match = timestamp_pattern.search(line)
        timestamp = None
        if timestamp_match:
            try:
                timestamp = datetime.fromisoformat(timestamp_match.group(0).replace("Z", "+00:00"))
                if timestamp.tzinfo is not None:
                    timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
                timestamped_lines += 1
            except ValueError:
                timestamp = None
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
        if any(success_line > failure_line for success_line, _ in successes for failure_line, _ in failures):
            failures_then_success.add(source)

    indicators = []
    failed = counts["authentication_failures"]
    if failed:
        indicators.append(f"Found {failed} log line(s) matching common authentication-failure wording.")
        if failed >= 10:
            indicators.append("The number of matching failures is high enough to review against expected activity.")
    if repeated_failure_sources:
        repeated_attempts = sum(len(events) for events in repeated_failure_sources.values())
        indicators.append(f"Repeated authentication failures came from {len(repeated_failure_sources)} source address(es), accounting for {repeated_attempts} failed line(s). Source values are omitted from the saved report.")
    if rapid_failure_sources:
        indicators.append(f"At least 2 authentication failures from the same source occurred within 5 minutes for {len(rapid_failure_sources)} source address(es); the report records source counts only.")
    if burst_failure_sources:
        indicators.append(f"At least 5 authentication failures from the same source occurred within a 5-minute window for {len(burst_failure_sources)} source address(es). This pattern needs prompt review.")
    if failures_then_success:
        indicators.append(f"A successful login followed failed attempts from the same source address for {len(failures_then_success)} source address(es). Confirm the account owner and session activity.")
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
    high_risk = failed >= 10 or bool(burst_failure_sources) or bool(failures_then_success)
    if high_risk:
        recommendations = ["Review the correlated source and timestamps, verify whether the successful session was legitimate, and follow your organization's incident process if it was unexpected."]
        explanation = "The log contains a stronger authentication pattern: a high number of failures, a short burst from one source, or a successful login after failures from that source. This is suspicious activity to investigate, not proof of compromise."
    elif needs_review:
        recommendations = ["Review the matching log entries in context and confirm that the account or privileged activity was expected."]
        if failed and rapid_failure_sources:
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
        "summary": f"Reviewed {len(lines)} non-empty log line(s): {failed} authentication failure(s), {counts['successful_logins']} successful login phrase(s), {counts['privileged_events']} privileged-command phrase(s), and {counts['account_changes']} account-change phrase(s). This is a local pattern review, not a complete security analysis.",
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
        },
        "target": f"Pasted log sample ({len(lines)} lines)",
        "line_count": len(lines),
        "counts": {**counts, "distinct_failure_sources": len(failure_sources), "repeated_failure_sources": len(repeated_failure_sources), "rapid_failure_sources": len(rapid_failure_sources), "failures_then_success": len(failures_then_success), "timestamped_lines": timestamped_lines},
    }
