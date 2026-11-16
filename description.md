# WebProbe: description and how to run

## What it is
A local-only web vulnerability scanner (pure Python standard library) plus a deliberately vulnerable demo web app. It finds SQL injection, reflected XSS, missing authentication, IDOR, exposed files, missing security headers, version disclosure and insecure cookies, scores them with CVSS v3.1, tags CWE/OWASP, and writes a VAPT-style report. A built-in retest compares scans before and after fixes.

## Run it
```
python -m venv .venv
.venv\Scripts\Activate.ps1                  # macOS / Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                   # 66 passed
webprobe demo --out webprobe-out
webprobe lab                                # then in another terminal:
webprobe scan http://127.0.0.1:8080 --cookie session=1
```
Python 3.9+. Only `pytest` is needed for tests.

## Files
- `webprobe/guard.py` scope guard (loopback only)
- `webprobe/client.py` HTTP client (no redirects)
- `webprobe/crawler.py` crawler / endpoint discovery
- `webprobe/checks.py` the vulnerability checks
- `webprobe/cvss.py` CVSS v3.1 calculator
- `webprobe/catalog.py` CWE / OWASP / remediation text
- `webprobe/lab.py` vulnerable + fixed demo app
- `webprobe/report.py`, `scanner.py`, `cli.py`
- `tests/test_webprobe.py` (lab, guard, CVSS, CLI) and `tests/test_realistic_app.py` (soft 404s, login form, destructive links)

## Good to know when talking about it
- It only scans localhost by design; say so up front.
- Boolean-based SQLi works by comparing the true/false/baseline responses.
- The lab app is intentionally insecure and fake; the `--fixed` mode shows the remediation.
