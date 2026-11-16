"""Vulnerability checks.

Every probe is a GET request with a harmless payload (an inert marker tag, a lone
quote, always-true/false conditions). A GET can still change data on a badly built
app, which is why the crawler skips links that look destructive (see crawler.py):
the checks below only ever test endpoints the crawler accepted.
"""

import hashlib
import html
import posixpath
import re
import secrets
from urllib.parse import quote, urlsplit

from .catalog import HEADER_REMEDIATION, make_finding

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]

SQL_ERRORS = [
    "sqlite3.operationalerror",
    "unrecognized token",
    "sql syntax",
    "sqlstate",
    "ora-0",
    "syntax error",
    "unclosed quotation mark",
    "pg_query",
]

# path -> signature the body must match. A 200 alone proves nothing (many apps answer
# every URL with 200), so each file must look like the real thing.
EXPOSURE_PROBES = {
    "/.env": re.compile(r"(?m)^[A-Z][A-Z0-9_]*=\S"),                       # KEY=value lines
    "/.git/HEAD": re.compile(r"\A(?:ref: refs/|[0-9a-f]{40}\s*\Z)"),
    "/backup.zip": re.compile(r"\APK\x03\x04"),                              # zip magic bytes
    "/backup.sql": re.compile(r"(?i)\b(?:CREATE TABLE|INSERT INTO)\b|-- (?:MySQL|PostgreSQL) (?:dump|database dump)"),
    "/config.php.bak": re.compile(r"<\?php"),
    "/phpinfo.php": re.compile(r"PHP Version \d"),
    "/server-status": re.compile(r"(?i)Apache Server Status|Server uptime"),
}
_PASSWORD_INPUT = re.compile(r"""(?i)<input\b[^>]*\btype\s*=\s*["']?password\b""")
ADMIN_PATHS = ["/admin", "/admin/", "/dashboard", "/manage"]
ID_PARAMS = {"id", "uid", "user_id", "userid", "account", "account_id", "order", "order_id", "doc", "file_id"}
IDOR_RANGE = range(1, 7)


class Context:
    def __init__(self, client, crawl_result):
        self.client = client
        self.base = client.base
        self.crawl = crawl_result
        self.notes: list = []

    def is_soft_404(self, path: str, resp) -> bool:
        """True if resp looks like the app's 'not found' page rather than real content.

        Requests a random decoy path of the same shape (same folder, same extension,
        same trailing slash) and compares the two pages after removing the requested
        path from each, so a not-found page that echoes the URL still matches.
        """
        decoy = _decoy_for(path)
        other = self.client.get(decoy, auth=False)
        return _page_signature(resp, path) == _page_signature(other, decoy)


def _decoy_for(path: str) -> str:
    """A path that cannot exist but looks like `path`: /backup.zip -> /wp1a2b3c4d5e6f.zip,
    /.env -> /.wp1a2b3c4d5e6f, /.git/HEAD -> /.git/wp1a2b3c4d5e6f, /admin/ -> /wp1a2b3c4d5e6f/."""
    trailing_slash = path.endswith("/") and path != "/"
    folder, name = posixpath.split(path.rstrip("/"))
    random_name = f"wp{secrets.token_hex(6)}"
    if name.startswith("."):
        decoy = "." + random_name
    else:
        decoy = random_name + posixpath.splitext(name)[1]
    return posixpath.join(folder or "/", decoy) + ("/" if trailing_slash else "")


def _page_signature(resp, path: str) -> tuple:
    body = resp.body
    name = posixpath.basename(path.rstrip("/"))
    # Longest first, so "/dashboard" goes before "dashboard" and leaves no stray "/".
    for echo in sorted({path, quote(path), html.escape(path), path.lstrip("/"), name}, key=len, reverse=True):
        if echo:
            body = body.replace(echo, "")
    return resp.status, hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()


def check_plain_http(ctx):
    if urlsplit(ctx.base).scheme == "http":
        return [make_finding("plain_http", ctx.base + "/", evidence="Target URL uses http:// (no TLS).")]
    return []


def check_headers(ctx):
    out = []
    base_resp = ctx.client.get("/")
    if base_resp.status == 0:
        ctx.notes.append("Header check skipped: base page unreachable.")
        return out
    csp = base_resp.headers.get("content-security-policy", "").lower()
    for name in REQUIRED_HEADERS:
        # CSP frame-ancestors is the modern replacement for X-Frame-Options.
        if name == "X-Frame-Options" and "frame-ancestors" in csp:
            continue
        if name.lower() not in base_resp.headers:
            out.append(
                make_finding(
                    "missing_security_header",
                    ctx.base + "/",
                    parameter=name,
                    title=f"Missing security header: {name}",
                    evidence=f"Response to GET / has no {name} header.",
                    remediation=HEADER_REMEDIATION[name],
                )
            )
    server = base_resp.headers.get("server", "")
    if re.search(r"\d", server):
        out.append(make_finding("server_banner", ctx.base + "/", parameter="Server", evidence=f"Server: {server}"))
    return out


def _cookie_attrs(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    return name, {p.split("=", 1)[0].lower() for p in parts[1:]}


def check_cookies(ctx):
    out, seen = [], set()
    for url, resp in ctx.crawl.pages:
        for raw in resp.set_cookies:
            name, attrs = _cookie_attrs(raw)
            if name in seen:
                continue
            seen.add(name)
            if "httponly" not in attrs:
                out.append(
                    make_finding(
                        "cookie_httponly",
                        url,
                        parameter=name,
                        evidence=f"Set-Cookie for '{name}' has no HttpOnly attribute, so page scripts "
                        f"(and any injected script) can read it. Check whether it holds a session or "
                        f"other sensitive value.",
                    )
                )
    return out


def check_exposed_files(ctx):
    out = []
    for path, signature in EXPOSURE_PROBES.items():
        resp = ctx.client.get(path, auth=False)
        if resp.status != 200 or not signature.search(resp.body):
            continue
        if ctx.is_soft_404(path, resp):
            continue
        out.append(
            make_finding(
                "exposed_file",
                ctx.base + path,
                parameter=path,
                title=f"Sensitive file exposed: {path}",
                evidence=f"GET {path} returned HTTP 200 ({len(resp.body)} bytes). Contents deliberately not recorded.",
            )
        )
    return out


def check_admin_access(ctx):
    out = []
    for path in ADMIN_PATHS:
        resp = ctx.client.get(path, auth=False)  # always anonymous
        if resp.status != 200 or ctx.is_soft_404(path, resp):
            continue
        if _PASSWORD_INPUT.search(resp.body):
            # A login form answering with 200 is the authentication working, not missing.
            ctx.notes.append(f"{path} shows a login form; not reported as missing authentication.")
            continue
        out.append(
            make_finding(
                "broken_access_control",
                ctx.base + path,
                parameter=path,
                evidence=f"Unauthenticated GET {path} returned HTTP 200 with content that is not "
                f"the app's not-found page and not a login form.",
            )
        )
    return out


def check_sqli(ctx):
    out = []
    for ep in ctx.crawl.endpoints:
        for name, value in ep.params.items():
            base_url = ep.url_with(ctx.base, name, value)
            baseline = ctx.client.get(base_url)
            if baseline.status == 0:
                continue
            baseline_text = baseline.body.lower()
            # 1) error-based: a lone quote makes the query invalid and the DB error leaks.
            probe = ctx.client.get(ep.url_with(ctx.base, name, value + "'"))
            leaked = [s for s in SQL_ERRORS if s in probe.body.lower() and s not in baseline_text]
            if leaked:
                out.append(
                    make_finding(
                        "sql_injection",
                        base_url,
                        parameter=name,
                        evidence=f"Appending a single quote to '{name}' produced a database error "
                        f"(signature: '{leaked[0]}', HTTP {probe.status}).",
                    )
                )
                continue
            # 2) boolean-based: "always true" must match the baseline, "always false" must not.
            for true_p, false_p, label in (
                (f"{value} AND 1=1", f"{value} AND 1=2", "numeric"),
                (f"{value}' AND '1'='1", f"{value}' AND '1'='2", "string"),
            ):
                t = ctx.client.get(ep.url_with(ctx.base, name, true_p))
                f = ctx.client.get(ep.url_with(ctx.base, name, false_p))
                if t.status and t.fingerprint == baseline.fingerprint and f.fingerprint != baseline.fingerprint:
                    out.append(
                        make_finding(
                            "sql_injection",
                            base_url,
                            parameter=name,
                            evidence=f"Boolean-based ({label}): '{name}' with an always-true condition "
                            f"matches the normal response, an always-false one does not "
                            f"(HTTP {t.status} vs {f.status}).",
                        )
                    )
                    break
    return out


def check_xss(ctx):
    out = []
    for ep in ctx.crawl.endpoints:
        for name, value in ep.params.items():
            marker = f"wpx{secrets.token_hex(4)}"
            payload = f"<{marker}>"
            resp = ctx.client.get(ep.url_with(ctx.base, name, payload))
            if "html" in resp.content_type.lower() and payload in resp.body:
                out.append(
                    make_finding(
                        "reflected_xss",
                        ep.url(ctx.base),
                        parameter=name,
                        evidence=f"Inert marker tag {payload} sent in '{name}' came back unescaped in an HTML response.",
                    )
                )
    return out


def check_idor(ctx):
    if not ctx.client.cookie:
        ctx.notes.append("IDOR check skipped: no --cookie supplied (it needs an authenticated session).")
        return []
    out = []
    for ep in ctx.crawl.endpoints:
        for name in ep.params:
            if name.lower() not in ID_PARAMS:
                continue
            anon = ctx.client.get(ep.url_with(ctx.base, name, "1"), auth=False)
            if anon.status not in (301, 302, 303, 307, 308, 401, 403):
                continue  # endpoint is public (or broken): not an authenticated-object endpoint
            seen = {}
            for i in IDOR_RANGE:
                resp = ctx.client.get(ep.url_with(ctx.base, name, str(i)))
                if resp.status == 200:
                    seen[i] = resp.fingerprint
            if len(set(seen.values())) >= 2:
                ids = ", ".join(str(i) for i in sorted(seen))
                out.append(
                    make_finding(
                        "idor",
                        ep.url_with(ctx.base, name, "1"),
                        parameter=name,
                        evidence=f"One session cookie read {len(set(seen.values()))} different records "
                        f"via '{name}' (ids {ids}). Confirm manually whether this account should "
                        f"be allowed to see all of them.",
                    )
                )
    return out


ALL_CHECKS = [
    check_plain_http,
    check_headers,
    check_cookies,
    check_exposed_files,
    check_admin_access,
    check_sqli,
    check_xss,
    check_idor,
]
