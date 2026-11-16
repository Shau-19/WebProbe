"""Finding catalog: CWE / OWASP Top 10 (2021) tags, CVSS v3.1 vectors and remediation text."""

from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .cvss import base_score, severity

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

CATALOG = {
    "sql_injection": {
        "title": "SQL injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Use parameterized queries (never string-build SQL) and validate the "
        "expected type of every identifier (for example, cast ids to int).",
    },
    "reflected_xss": {
        "title": "Reflected cross-site scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "remediation": "HTML-escape untrusted input on output (context-aware encoding) and "
        "add a restrictive Content-Security-Policy as defence in depth.",
    },
    "broken_access_control": {
        "title": "Missing authentication on a privileged page",
        "cwe": "CWE-306",
        "owasp": "A01:2021 Broken Access Control",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "remediation": "Require an authenticated session and check the caller's role on the "
        "server for every privileged route (deny by default).",
    },
    "idor": {
        "title": "Insecure direct object reference (IDOR)",
        "cwe": "CWE-639",
        "owasp": "A01:2021 Broken Access Control",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Authorize every object access: verify on the server that the session "
        "owns the requested record (or has an explicit role that allows it).",
    },
    "exposed_file": {
        "title": "Sensitive file exposed",
        "cwe": "CWE-538",
        "owasp": "A05:2021 Security Misconfiguration",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Remove configuration files, backups and VCS metadata from the web root, "
        "or deny access to them in the server configuration. Rotate any exposed secrets.",
    },
    "missing_security_header": {
        "title": "Missing security header",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": "Send the header on every response.",
    },
    "server_banner": {
        "title": "Server banner discloses version information",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Suppress or genericize the Server header so product and version are not disclosed.",
    },
    "cookie_httponly": {
        "title": "Cookie without HttpOnly flag",
        "cwe": "CWE-1004",
        "owasp": "A05:2021 Security Misconfiguration",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": "Set HttpOnly on every cookie that page scripts do not need to read, and always "
        "on session and authentication cookies; add SameSite, plus Secure over HTTPS.",
    },
    "plain_http": {
        "title": "Target served over plain HTTP",
        "cwe": "CWE-319",
        "owasp": "A02:2021 Cryptographic Failures",
        "vector": None,
        "remediation": "Serve the application over HTTPS (TLS) in any non-local deployment.",
    },
    "open_port": {
        "title": "Open TCP port",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "vector": None,
        "remediation": "Confirm the service is intended; close or firewall anything that is not.",
    },
}

HEADER_REMEDIATION = {
    "Content-Security-Policy": "Add a Content-Security-Policy header, for example default-src 'self'.",
    "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff'.",
    "X-Frame-Options": "Add 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking.",
    "Referrer-Policy": "Add 'Referrer-Policy: no-referrer' (or strict-origin-when-cross-origin).",
}


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe: str
    owasp: str
    url: str
    parameter: str
    evidence: str
    remediation: str
    key: str

    def to_dict(self) -> dict:
        return asdict(self)


def make_finding(check, url, parameter="", evidence="", title=None, remediation=None) -> Finding:
    entry = CATALOG[check]
    vector = entry["vector"]
    score = base_score(vector) if vector else 0.0
    path = urlsplit(url).path or "/"
    return Finding(
        check=check,
        title=title or entry["title"],
        severity=severity(score),
        cvss_score=score,
        cvss_vector=vector or "n/a",
        cwe=entry["cwe"],
        owasp=entry["owasp"],
        url=url,
        parameter=parameter,
        evidence=evidence,
        remediation=remediation or entry["remediation"],
        key=f"{check}|{path}|{parameter}",
    )
