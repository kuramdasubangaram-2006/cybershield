"""Bounded, read-only public website metadata fetcher for the URL scanner."""

from html.parser import HTMLParser
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import quote, urljoin, urlsplit, urlunsplit


MAX_HTML_BYTES = 512 * 1024
TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 3


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address):
        self.address = address
        super().__init__(host, port, timeout=TIMEOUT_SECONDS)

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address):
        self.address = address
        self.context = ssl.create_default_context()
        super().__init__(host, port, timeout=TIMEOUT_SECONDS, context=self.context)

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self.context.wrap_socket(sock, server_hostname=self.host)


class _PageFacts(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = urlsplit(base_url)
        self.title = ""
        self.description = ""
        self.og_title = ""
        self.og_description = ""
        self.og_image = ""
        self.in_title = False
        self.title_parts = []
        self.links = 0
        self.external_links = 0
        self.forms = 0
        self.password_fields = 0
        self.scripts = 0
        self.iframes = 0
        self.images = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            key = (values.get("name") or values.get("property") or "").lower()
            content = (values.get("content") or "").strip()
            if key == "description": self.description = content[:500]
            elif key == "og:title": self.og_title = content[:300]
            elif key == "og:description": self.og_description = content[:500]
            elif key == "og:image": self.og_image = content[:2048]
        elif tag == "a" and values.get("href"):
            self.links += 1
            destination = urlsplit(urljoin(urlunsplit((self.base.scheme, self.base.netloc, "/", "", "")), values["href"]))
            if destination.hostname and destination.hostname.lower() != (self.base.hostname or "").lower():
                self.external_links += 1
        elif tag == "form": self.forms += 1
        elif tag == "input" and (values.get("type") or "").lower() == "password": self.password_fields += 1
        elif tag == "script" and values.get("src"): self.scripts += 1
        elif tag == "iframe": self.iframes += 1
        elif tag == "img": self.images += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
            self.title = " ".join(" ".join(self.title_parts).split())[:300]

    def handle_data(self, data):
        if self.in_title and len("".join(self.title_parts)) < 300:
            self.title_parts.append(data)


def _validate_public_url(value):
    if not value or "\\" in value or any(ord(char) < 32 or char.isspace() for char in value):
        raise ValueError("URL contains unsupported characters.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL format is not supported for live review.") from error
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Only public HTTP or HTTPS website URLs without embedded credentials can be reviewed.")
    expected_port = 443 if scheme == "https" else 80
    if port not in {None, expected_port}:
        raise ValueError("Live review supports only standard website ports 80 and 443.")
    try:
        try:
            host_ascii = str(ipaddress.ip_address(host))
        except ValueError:
            host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Website hostname could not be read.") from error
    authority = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
    if port:
        authority += f":{port}"
    if len(value) > 2048:
        raise ValueError("Redirected URL is too long for this limited review.")
    normalized = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
    return parsed, host_ascii, expected_port, normalized


def _resolve_public(host, port):
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError("Website hostname could not be resolved.") from error
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not addresses:
        raise ValueError("Website hostname did not resolve to an address.")
    parsed_addresses = [ipaddress.ip_address(address.split("%", 1)[0]) for address in addresses]
    if any(not address.is_global or address.is_multicast or address.is_reserved for address in parsed_addresses):
        raise ValueError("Live review is limited to public website addresses.")
    return addresses[0]


def _fetch_one(value):
    parsed, host, port, normalized = _validate_public_url(value)
    address = _resolve_public(host, port)
    connection = (_PinnedHTTPSConnection(host, port, address) if parsed.scheme.lower() == "https"
                  else _PinnedHTTPConnection(host, port, address))
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="/?%:@!$&'()*+,;=-._~")
    try:
        connection.request("GET", path, headers={
            "User-Agent": "CyberShield-ReadOnly-URL-Review/1.0",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        response = connection.getresponse()
        headers = {key.lower(): value.strip() for key, value in response.getheaders()}
        certificate = connection.sock.getpeercert() if parsed.scheme.lower() == "https" and connection.sock else None
        content_type = headers.get("content-type", "").lower()
        body = response.read(MAX_HTML_BYTES + 1) if content_type.startswith(("text/html", "application/xhtml+xml")) else b""
        truncated = len(body) > MAX_HTML_BYTES
        return {
            "url": normalized,
            "status": response.status,
            "headers": headers,
            "body": body[:MAX_HTML_BYTES],
            "truncated": truncated,
            "certificate": certificate,
            "host": host,
        }
    finally:
        connection.close()


def _report_url(value):
    """Keep query strings and fragments out of saved redirect details."""
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def inspect_public_site(value):
    """Fetch a small HTML response, manually validating each redirect destination."""
    current = value if "://" in value else f"https://{value}"
    chain = []
    page = None
    for _ in range(MAX_REDIRECTS + 1):
        page = _fetch_one(current)
        if page["status"] not in {301, 302, 303, 307, 308}:
            break
        location = page["headers"].get("location")
        if not location:
            break
        if len(chain) >= MAX_REDIRECTS:
            raise ValueError("Website redirected too many times for this limited review.")
        current = urljoin(page["url"], location)
        chain.append(current)

    headers = page["headers"]
    content_type = headers.get("content-type", "unknown")[:160]
    facts = {
        "HTTP status": str(page["status"]),
        "Final URL": _report_url(page["url"])[:2048],
        "Redirects followed": str(len(chain)),
        "Content type": content_type,
        "Response size checked": f"At most {MAX_HTML_BYTES // 1024} KB" + (" (truncated)" if page["truncated"] else ""),
        "HTTPS": "Yes" if page["url"].startswith("https://") else "No",
    }
    tls = page["certificate"]
    if tls:
        issuer = dict(item[0] for item in tls.get("issuer", ()))
        facts["TLS certificate issuer"] = str(issuer.get("organizationName") or issuer.get("commonName") or "Provided")[:160]
        facts["TLS expires"] = str(tls.get("notAfter", "Unknown"))

    security_headers = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy")
    for header in security_headers:
        facts[f"Header: {header}"] = "Present" if header in headers else "Not present"

    indicators = [f"Website returned HTTP {page['status']}." ]
    if chain:
        indicators.append(f"The website redirected {len(chain)} time(s); the final destination is shown above.")
    missing = [header for header in security_headers if header not in headers]
    if missing:
        indicators.append("Some common browser security headers were not present. This alone does not mean the site is malicious.")

    if content_type.lower().startswith(("text/html", "application/xhtml+xml")):
        charset_match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.IGNORECASE)
        encoding = charset_match.group(1) if charset_match else "utf-8"
        parser = _PageFacts(page["url"])
        try:
            parser.feed(page["body"].decode(encoding, errors="replace"))
        except LookupError:
            parser.feed(page["body"].decode("utf-8", errors="replace"))
        facts.update({
            "Page title": parser.title or "Not provided",
            "Meta description": parser.description or "Not provided",
            "Open Graph title": parser.og_title or "Not provided",
            "Open Graph description": parser.og_description or "Not provided",
            "Forms found": str(parser.forms),
            "Password fields found": str(parser.password_fields),
            "Links found": str(parser.links),
            "External links found": str(parser.external_links),
            "Script tags found": str(parser.scripts),
            "Iframes found": str(parser.iframes),
            "Image tags found": str(parser.images),
        })
        if parser.og_image:
            image_host = urlsplit(urljoin(page["url"], parser.og_image)).hostname
            facts["Advertised preview image host"] = image_host or "Not provided"
        if parser.forms:
            indicators.append(f"The page contains {parser.forms} form(s); their behavior was not submitted or tested.")
        if parser.password_fields and not page["url"].startswith("https://"):
            indicators.append("The page has password fields but the final page is not using HTTPS.")
    else:
        facts["Page title"] = "Not an HTML page; body was not analyzed"
        indicators.append("The response was not HTML, so its body was not parsed.")

    return {
        "facts": facts,
        "indicators": indicators,
        "redirect_chain": [_report_url(url)[:2048] for url in chain],
        "password_form_over_http": bool(
            content_type.lower().startswith(("text/html", "application/xhtml+xml"))
            and parser.password_fields and not page["url"].startswith("https://")
        ) if content_type.lower().startswith(("text/html", "application/xhtml+xml")) else False,
        "explanation": "CyberShield made limited read-only HTTP requests and parsed only a small HTML response. It did not run JavaScript, submit forms, download linked files, crawl other pages, or query threat-intelligence sources.",
        "recommendations": ["Verify the domain through a trusted channel before entering sensitive information. Treat these public-page details as context, not a safety verdict."],
    }
