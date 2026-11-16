# Vulnerability Assessment Report: http://127.0.0.1:53318

- Tool: WebProbe 1.1.0
- Generated (UTC): 2026-11-15T21:32:36+00:00
- Authenticated scan: yes (one session cookie)
- Pages crawled: 5 | HTTP requests sent: 52 | Duration: 0.67s

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 1 |
| **Total** | **13** |

## Scope and methodology

Target: `http://127.0.0.1:53318` (local only). Endpoints with parameters that were tested:

- `http://127.0.0.1:53318/search?q=hello`
- `http://127.0.0.1:53318/user?id=1`
- `http://127.0.0.1:53318/login?user=alice`
- `http://127.0.0.1:53318/profile?id=1`

Checks: security headers, server banner, cookie flags, exposed sensitive files, unauthenticated privileged pages, SQL injection (error-based and boolean-based), reflected XSS (inert marker), IDOR (needs a session cookie), plain-HTTP, optional port scan. Severity uses CVSS v3.1 base scores; findings are tagged with CWE and OWASP Top 10 (2021) categories.

## Findings

### 1. [CRITICAL] SQL injection

| | |
|---|---|
| CVSS v3.1 | 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| CWE | CWE-89 |
| OWASP | A03:2021 Injection |
| Location | `http://127.0.0.1:53318/user?id=1` |
| Parameter | id |

**Evidence:** Appending a single quote to 'id' produced a database error (signature: 'sqlite3.operationalerror', HTTP 500).

**Remediation:** Use parameterized queries (never string-build SQL) and validate the expected type of every identifier (for example, cast ids to int).

### 2. [CRITICAL] Missing authentication on a privileged page

| | |
|---|---|
| CVSS v3.1 | 9.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| CWE | CWE-306 |
| OWASP | A01:2021 Broken Access Control |
| Location | `http://127.0.0.1:53318/admin` |
| Parameter | /admin |

**Evidence:** Unauthenticated GET /admin returned HTTP 200 with content that is not the app's not-found page and not a login form.

**Remediation:** Require an authenticated session and check the caller's role on the server for every privileged route (deny by default).

### 3. [HIGH] Sensitive file exposed: /.env

| | |
|---|---|
| CVSS v3.1 | 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| CWE | CWE-538 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/.env` |
| Parameter | /.env |

**Evidence:** GET /.env returned HTTP 200 (54 bytes). Contents deliberately not recorded.

**Remediation:** Remove configuration files, backups and VCS metadata from the web root, or deny access to them in the server configuration. Rotate any exposed secrets.

### 4. [HIGH] Sensitive file exposed: /backup.zip

| | |
|---|---|
| CVSS v3.1 | 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| CWE | CWE-538 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/backup.zip` |
| Parameter | /backup.zip |

**Evidence:** GET /backup.zip returned HTTP 200 (28 bytes). Contents deliberately not recorded.

**Remediation:** Remove configuration files, backups and VCS metadata from the web root, or deny access to them in the server configuration. Rotate any exposed secrets.

### 5. [MEDIUM] Insecure direct object reference (IDOR)

| | |
|---|---|
| CVSS v3.1 | 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| CWE | CWE-639 |
| OWASP | A01:2021 Broken Access Control |
| Location | `http://127.0.0.1:53318/profile?id=1` |
| Parameter | id |

**Evidence:** One session cookie read 4 different records via 'id' (ids 1, 2, 3, 4). Confirm manually whether this account should be allowed to see all of them.

**Remediation:** Authorize every object access: verify on the server that the session owns the requested record (or has an explicit role that allows it).

### 6. [MEDIUM] Reflected cross-site scripting (XSS)

| | |
|---|---|
| CVSS v3.1 | 6.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`) |
| CWE | CWE-79 |
| OWASP | A03:2021 Injection |
| Location | `http://127.0.0.1:53318/search?q=hello` |
| Parameter | q |

**Evidence:** Inert marker tag &lt;wpx938a8eb6&gt; sent in 'q' came back unescaped in an HTML response.

**Remediation:** HTML-escape untrusted input on output (context-aware encoding) and add a restrictive Content-Security-Policy as defence in depth.

### 7. [LOW] Server banner discloses version information

| | |
|---|---|
| CVSS v3.1 | 3.7 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| CWE | CWE-200 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/` |
| Parameter | Server |

**Evidence:** Server: LabServer/1.4.2

**Remediation:** Suppress or genericize the Server header so product and version are not disclosed.

### 8. [LOW] Cookie without HttpOnly flag

| | |
|---|---|
| CVSS v3.1 | 3.1 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) |
| CWE | CWE-1004 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/login?user=alice` |
| Parameter | session |

**Evidence:** Set-Cookie for 'session' has no HttpOnly attribute, so page scripts (and any injected script) can read it. Check whether it holds a session or other sensitive value.

**Remediation:** Set HttpOnly on every cookie that page scripts do not need to read, and always on session and authentication cookies; add SameSite, plus Secure over HTTPS.

### 9. [LOW] Missing security header: Content-Security-Policy

| | |
|---|---|
| CVSS v3.1 | 3.1 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) |
| CWE | CWE-693 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/` |
| Parameter | Content-Security-Policy |

**Evidence:** Response to GET / has no Content-Security-Policy header.

**Remediation:** Add a Content-Security-Policy header, for example default-src 'self'.

### 10. [LOW] Missing security header: Referrer-Policy

| | |
|---|---|
| CVSS v3.1 | 3.1 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) |
| CWE | CWE-693 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/` |
| Parameter | Referrer-Policy |

**Evidence:** Response to GET / has no Referrer-Policy header.

**Remediation:** Add 'Referrer-Policy: no-referrer' (or strict-origin-when-cross-origin).

### 11. [LOW] Missing security header: X-Content-Type-Options

| | |
|---|---|
| CVSS v3.1 | 3.1 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) |
| CWE | CWE-693 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/` |
| Parameter | X-Content-Type-Options |

**Evidence:** Response to GET / has no X-Content-Type-Options header.

**Remediation:** Add 'X-Content-Type-Options: nosniff'.

### 12. [LOW] Missing security header: X-Frame-Options

| | |
|---|---|
| CVSS v3.1 | 3.1 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) |
| CWE | CWE-693 |
| OWASP | A05:2021 Security Misconfiguration |
| Location | `http://127.0.0.1:53318/` |
| Parameter | X-Frame-Options |

**Evidence:** Response to GET / has no X-Frame-Options header.

**Remediation:** Add 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking.

### 13. [INFO] Target served over plain HTTP

| | |
|---|---|
| CVSS v3.1 | 0.0 (`n/a`) |
| CWE | CWE-319 |
| OWASP | A02:2021 Cryptographic Failures |
| Location | `http://127.0.0.1:53318/` |
| Parameter | n/a |

**Evidence:** Target URL uses http:// (no TLS).

**Remediation:** Serve the application over HTTPS (TLS) in any non-local deployment.

## Limitations

- Automated GET-based checks only; no POST bodies, file uploads or authenticated crawling beyond one supplied cookie.
- Links that look destructive (logout, delete, remove, reset, ...) are skipped and listed in the notes; the filter is word-based, so a dangerous link with an innocent name could still be requested.
- Heuristic detection: findings are candidates to verify manually, and a clean result does not prove the absence of vulnerabilities.
- Not covered: business-logic flaws, CSRF, SSRF, deserialization, TLS configuration, dependency vulnerabilities.
- Scans local targets only by design (loopback guard).
