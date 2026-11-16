import json
import socket
import urllib.request
from collections import Counter

import pytest

from webprobe import cli
from webprobe.client import Client
from webprobe.crawler import crawl
from webprobe.cvss import base_score, severity
from webprobe.guard import TargetNotLocal, ensure_local
from webprobe.lab import start_lab
from webprobe.ports import scan_ports
from webprobe.report import compare, render_markdown
from webprobe.scanner import run_scan


# ---------- fixtures ----------
@pytest.fixture(scope="module")
def vuln():
    server, url = start_lab(fixed=False)
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def fixed():
    server, url = start_lab(fixed=True)
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def vuln_scan(vuln):
    return run_scan(vuln, cookie="session=1")


@pytest.fixture(scope="module")
def fixed_scan(fixed):
    return run_scan(fixed, cookie="session=1")


def checks_of(scan):
    return Counter(f["check"] for f in scan["findings"])


# ---------- guard ----------
@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:8080", "http://localhost:3000/x", "https://127.0.0.1", "http://[::1]:9000/"],
)
def test_guard_allows_loopback(url):
    ensure_local(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://192.168.1.10",
        "http://10.0.0.5:8080",
        "http://127.0.0.1@evil.com/",
        "http://user:pw@127.0.0.1/",
        "ftp://127.0.0.1/",
        "file:///etc/passwd",
        "http://localhost.evil.com/",
        "http://0.0.0.0/",
        "http:///nohost",
        "http://127.0.0.1:99999/",
    ],
)
def test_guard_refuses_non_local(url):
    with pytest.raises(TargetNotLocal):
        ensure_local(url)


def test_client_refuses_non_local_without_request(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a network request was attempted")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    with pytest.raises(TargetNotLocal):
        Client("http://example.com")
    assert cli.main(["scan", "http://example.com"]) == 2


# ---------- client ----------
def test_client_does_not_follow_redirects():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://example.com/evil")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = Client(f"http://127.0.0.1:{srv.server_address[1]}")
        resp = client.get("/")
        assert resp.status == 302
        assert len(client.log) == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_client_returns_status_zero_on_connection_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    resp = Client(f"http://127.0.0.1:{port}", timeout=1).get("/")
    assert resp.status == 0 and resp.error


# ---------- CVSS ----------
@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_known_scores(vector, score):
    assert base_score(vector) == score


def test_cvss_rejects_bad_vectors():
    for bad in ("AV:N/AC:L", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
        with pytest.raises(ValueError):
            base_score(bad)


def test_severity_bands():
    assert [severity(x) for x in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == [
        "INFO", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL",
    ]


# ---------- crawler ----------
def test_crawler_finds_pages_and_endpoints(vuln):
    c = Client(vuln)
    result = crawl(c)
    paths = {urllib.request.urlparse(u).path for u, _ in result.pages}
    assert {"/", "/user", "/login", "/profile", "/admin"} <= paths  # /search is only reachable via the GET form
    params = {(e.path, tuple(e.params)) for e in result.endpoints}
    assert ("/search", ("q",)) in params and ("/user", ("id",)) in params


def test_crawler_stays_same_origin_and_respects_page_cap(vuln):
    c = Client(vuln)
    assert len(crawl(c, max_pages=2).pages) == 2
    assert all(u.startswith(vuln) for u, _ in crawl(c).pages)


# ---------- scans of the lab ----------
def test_vulnerable_lab_findings(vuln_scan):
    c = checks_of(vuln_scan)
    assert c == {
        "sql_injection": 1,
        "reflected_xss": 1,
        "broken_access_control": 1,
        "idor": 1,
        "exposed_file": 2,
        "missing_security_header": 4,
        "server_banner": 1,
        "cookie_httponly": 1,
        "plain_http": 1,
    }
    assert len(vuln_scan["findings"]) == 13
    assert vuln_scan["summary"]["CRITICAL"] == 2  # SQLi 9.8, missing auth on admin 9.1
    cookie = next(f for f in vuln_scan["findings"] if f["check"] == "cookie_httponly")
    assert cookie["title"] == "Cookie without HttpOnly flag"  # not every cookie is a session cookie
    assert vuln_scan["skipped_destructive_links"] == []  # the lab has none


def test_vulnerable_lab_finding_locations(vuln_scan):
    by_check = {f["check"]: f for f in vuln_scan["findings"] if f["check"] in ("sql_injection", "reflected_xss", "idor")}
    assert by_check["sql_injection"]["key"] == "sql_injection|/user|id"
    assert by_check["reflected_xss"]["key"] == "reflected_xss|/search|q"
    assert by_check["idor"]["key"] == "idor|/profile|id"


def test_no_false_positives_on_fixed_lab(fixed_scan):
    assert checks_of(fixed_scan) == {"plain_http": 1}
    assert fixed_scan["summary"]["INFO"] == 1


def test_idor_skipped_without_cookie(vuln):
    scan = run_scan(vuln)
    assert "idor" not in checks_of(scan)
    assert any("IDOR check skipped" in n for n in scan["notes"])


def test_exposed_file_evidence_does_not_leak_contents(vuln_scan):
    for f in vuln_scan["findings"]:
        if f["check"] == "exposed_file":
            assert "lab-not-a-real-secret" not in json.dumps(f)


def test_admin_check_is_always_anonymous(fixed):
    # With an ordinary user's cookie the fixed lab still must not report the admin page.
    scan = run_scan(fixed, cookie="session=1")
    assert "broken_access_control" not in checks_of(scan)


def test_fixed_lab_idor_allows_own_record_only(fixed):
    c = Client(fixed, cookie="session=1")
    assert c.get("/profile?id=1").status == 200
    assert c.get("/profile?id=2").status == 403


# ---------- retest ----------
def test_compare_before_after(vuln_scan, fixed_scan):
    cmp = compare(vuln_scan, fixed_scan)
    assert (len(cmp["resolved"]), len(cmp["remaining"]), len(cmp["new"])) == (12, 1, 0)
    assert cmp["remaining"][0]["check"] == "plain_http"


# ---------- ports ----------
def test_port_scan_finds_open_listener():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        import webprobe.ports as ports

        port = listener.getsockname()[1]
        original = dict(ports.COMMON_PORTS)
        ports.COMMON_PORTS[port] = "test-service"
        try:
            found = scan_ports("http://127.0.0.1:1")
        finally:
            ports.COMMON_PORTS.clear()
            ports.COMMON_PORTS.update(original)
        assert any(f.parameter == str(port) for f in found)
    finally:
        listener.close()


def test_port_scan_refuses_non_local():
    with pytest.raises(TargetNotLocal):
        scan_ports("http://example.com")


# ---------- reports & CLI ----------
def test_markdown_report_contents(vuln_scan):
    md = render_markdown(vuln_scan)
    for needle in ("# Vulnerability Assessment Report", "CVSS v3.1", "CWE-89", "A03:2021", "Limitations", "Remediation"):
        assert needle in md
    assert md.index("SQL injection") < md.index("Missing security header")  # highest severity first


def test_cli_demo_writes_reports(tmp_path, capsys):
    assert cli.main(["demo", "--out", str(tmp_path)]) == 0
    for name in ("before.md", "before.json", "after.md", "after.json", "retest.md"):
        assert (tmp_path / name).exists()
    assert "resolved 12, remaining 1, new 0" in capsys.readouterr().out


def test_cli_scan_and_compare(vuln, fixed, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert cli.main(["scan", vuln, "--cookie", "session=1", "--out", str(a)]) == 0
    assert cli.main(["scan", fixed, "--cookie", "session=1", "--out", str(b)]) == 0
    assert cli.main(["compare", str(a / "report.json"), str(b / "report.json"), "--out", str(tmp_path / "c.md")]) == 0
    assert "Resolved: 12" in (tmp_path / "c.md").read_text()


def test_lab_refuses_non_loopback_bind():
    from webprobe.lab import make_server

    with pytest.raises(TargetNotLocal):
        make_server(host="0.0.0.0")
