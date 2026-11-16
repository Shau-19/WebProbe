# Retest: before vs after

- Before: `http://127.0.0.1:53318` (13 findings)
- After: `http://127.0.0.1:64928` (1 findings)
- **Resolved: 12 | Remaining: 1 | New: 0**

## Resolved

- [CRITICAL] Missing authentication on a privileged page (CWE-306) at `/admin`
- [CRITICAL] SQL injection (CWE-89) at `/user (id)`
- [HIGH] Sensitive file exposed: /.env (CWE-538) at `/.env`
- [HIGH] Sensitive file exposed: /backup.zip (CWE-538) at `/backup.zip`
- [MEDIUM] Insecure direct object reference (IDOR) (CWE-639) at `/profile (id)`
- [MEDIUM] Reflected cross-site scripting (XSS) (CWE-79) at `/search (q)`
- [LOW] Cookie without HttpOnly flag (CWE-1004) at `/login (session)`
- [LOW] Missing security header: Content-Security-Policy (CWE-693) at `/ (Content-Security-Policy)`
- [LOW] Missing security header: Referrer-Policy (CWE-693) at `/ (Referrer-Policy)`
- [LOW] Missing security header: X-Content-Type-Options (CWE-693) at `/ (X-Content-Type-Options)`
- [LOW] Missing security header: X-Frame-Options (CWE-693) at `/ (X-Frame-Options)`
- [LOW] Server banner discloses version information (CWE-200) at `/ (Server)`

## Remaining

- [INFO] Target served over plain HTTP (CWE-319) at `/`

## New

None.
