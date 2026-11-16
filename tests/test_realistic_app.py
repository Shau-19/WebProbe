"""Regression tests against a 'realistic' app that behaves like many real sites do.

The bundled lab is well behaved (real 404s, no destructive links), so it could not
catch these problems. This app:
  - answers every unknown URL with HTTP 200 and a "page /x does not exist" message
    that echoes the path (a soft 404),
  - shows a login form at /admin with HTTP 200,
  - links to /logout and /items/delete?id=7 (a GET that deletes data),
  - has a GET form whose action deactivates the account,
  - protects against framing with CSP frame-ancestors instead of X-Frame-Options.
With leaky=True it also has two genuine problems hidden among the soft 404s.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from webprobe import cli
from webprobe.crawler import looks_destructive
from webprobe.ports import scan_ports
from webprobe.report import render_markdown
from webprobe.scanner import run_scan

HOME = """<html><body>
<a href="/logout">Log out</a>
<a href="/items/delete?id=7">Delete item 7</a>
<a href="/items?id=7">View item 7</a>
<form method="get" action="/account/deactivate"><input name="confirm" value="yes"></form>
</body></html>"""
LOGIN = '<html><form method="post" action="/login"><input name="user"><input type="password" name="pw"></form></html>'


def _start(leaky: bool):
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            path = self.path.split("?")[0]
            ctype = "text/html; charset=utf-8"
            if path == "/":
                body = HOME
            elif path == "/items":
                body = "<html><p>Item 7: a teapot</p></html>"
            elif path == "/admin":
                body = LOGIN
            elif leaky and path == "/.git/HEAD":
                body, ctype = "ref: refs/heads/main\n", "text/plain"
            elif leaky and path == "/manage":
                body = "<html><h1>Management</h1><p>All orders: 1, 2, 3</p></html>"
            else:  # soft 404: status 200, and the message echoes the path
                body = f'<html><body><p class="err">Sorry, the page {path} does not exist.</p></body></html>'
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", hits


@pytest.fixture(scope="module")
def realistic():
    srv, url, hits = _start(leaky=False)
    scan = run_scan(url, cookie="session=1")
    yield scan, hits
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def leaky():
    srv, url, hits = _start(leaky=True)
    scan = run_scan(url)
    yield scan
    srv.shutdown()
    srv.server_close()


def checks(scan, name):
    return [f for f in scan["findings"] if f["check"] == name]


# ---------- fix 1: false positives on soft-404 apps ----------
def test_soft_404_pages_are_not_reported_as_exposed_files(realistic):
    scan, _ = realistic
    assert checks(scan, "exposed_file") == []


def test_soft_404_pages_and_login_form_are_not_missing_authentication(realistic):
    scan, _ = realistic
    assert checks(scan, "broken_access_control") == []
    assert any("/admin shows a login form" in n for n in scan["notes"])


def test_real_problems_behind_soft_404s_are_still_found(leaky):
    assert [f["parameter"] for f in checks(leaky, "exposed_file")] == ["/.git/HEAD"]
    assert [f["parameter"] for f in checks(leaky, "broken_access_control")] == ["/manage"]


# ---------- fix 2: never follow destructive links ----------
def test_crawler_never_requests_destructive_links(realistic):
    scan, hits = realistic
    touched = [h for h in hits if any(w in h for w in ("logout", "delete", "deactivate"))]
    assert touched == []  # not by the crawler, and not by any check afterwards
    assert any("/items?id=7" in h for h in hits)  # the harmless link is still tested


def test_skipped_links_are_listed_in_the_report(realistic):
    scan, _ = realistic
    skipped = scan["skipped_destructive_links"]
    assert any(u.endswith("/logout") for u in skipped)
    assert any("/items/delete?id=7" in u for u in skipped)
    assert any("/account/deactivate" in u for u in skipped)
    md = render_markdown(scan)
    assert "Skipped 3 link(s) that look destructive" in md


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/logout", "http://127.0.0.1/log-out", "http://127.0.0.1/items/delete?id=7",
    "http://127.0.0.1/api?action=remove&id=1", "http://127.0.0.1/user/deleteAccount",
    "http://127.0.0.1/settings/reset", "http://127.0.0.1/newsletter?op=Unsubscribe",
])
def test_destructive_urls_are_recognised(url):
    assert looks_destructive(url)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/search?q=hello", "http://127.0.0.1/profile?id=1", "http://127.0.0.1/presets",
    "http://127.0.0.1/ui/dropdown", "http://127.0.0.1/banner.png", "http://127.0.0.1/delivery?id=2",
])
def test_harmless_urls_are_not_skipped(url):
    assert not looks_destructive(url)


# ---------- small fixes ----------
def test_csp_frame_ancestors_satisfies_x_frame_options(realistic):
    scan, _ = realistic
    missing = {f["parameter"] for f in checks(scan, "missing_security_header")}
    assert "X-Frame-Options" not in missing and "Content-Security-Policy" not in missing
    assert missing == {"X-Content-Type-Options", "Referrer-Policy"}  # still reports the rest


def test_port_scan_works_on_ipv6_loopback():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 on this machine")
    try:
        listener = socket.socket(socket.AF_INET6)
        listener.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback not available")
    listener.listen(1)
    import webprobe.ports as ports

    port = listener.getsockname()[1]
    original = dict(ports.COMMON_PORTS)
    ports.COMMON_PORTS[port] = "test-service"
    try:
        found = scan_ports("http://[::1]:1")
    finally:
        ports.COMMON_PORTS.clear()
        ports.COMMON_PORTS.update(original)
        listener.close()
    match = [f for f in found if f.parameter == str(port)]
    assert match and match[0].url == f"tcp://[::1]:{port}"


def test_report_escapes_html_from_the_target():
    result = {
        "target": "http://127.0.0.1:1", "version": "x", "generated": "now", "authenticated": False,
        "pages_crawled": 1, "requests": 1, "duration_s": 0, "endpoints_tested": [],
        "notes": ["page said <script>alert(1)</script>"], "summary": {"LOW": 1},
        "findings": [{"severity": "LOW", "title": "T <b>x</b>", "cvss_score": 1.0, "cvss_vector": "v",
                      "cwe": "CWE-1", "owasp": "A | B", "url": "u", "parameter": "p|q",
                      "evidence": "Inert marker tag <wpx1234> came back", "remediation": "r"}],
    }
    md = render_markdown(result)
    assert "&lt;wpx1234&gt;" in md and "<wpx1234>" not in md  # visible on GitHub, not stripped
    assert "<script>" not in md and "<b>" not in md
    assert "| OWASP | A \\| B |" in md and "p\\|q" in md


@pytest.mark.parametrize("content", [None, "not json {", json.dumps({"something": "else"})])
def test_compare_reports_bad_input_instead_of_crashing(tmp_path, capsys, content):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"target": "t", "findings": []}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    if content is not None:
        bad.write_text(content, encoding="utf-8")
    assert cli.main(["compare", str(good), str(bad)]) == 2
    assert "Cannot compare" in capsys.readouterr().err
