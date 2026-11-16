"""WebProbe Lab: a deliberately vulnerable demo app (and its fixed twin) to test the scanner on.

Everything here is fake and in-memory. It binds to loopback only. Run it with
``python -m webprobe lab`` (vulnerable) or ``python -m webprobe lab --fixed``.
Never expose it to a network.
"""

import html
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .guard import ensure_local

USERS = [
    (1, "alice", "alice@example.test", "user"),
    (2, "bob", "bob@example.test", "user"),
    (3, "carol", "carol@example.test", "user"),
    (4, "admin", "admin@example.test", "admin"),
]
ADMIN_ID = 4

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

INDEX = """<!doctype html><html><head><title>WebProbe Lab</title></head><body>
<h1>WebProbe Lab</h1><p>Fake data. Deliberately vulnerable unless started with --fixed.</p>
<form method="get" action="/search"><input name="q" value="hello"><input type="submit"></form>
<ul>
<li><a href="/user?id=1">User directory</a></li>
<li><a href="/login?user=alice">Log in as alice</a></li>
<li><a href="/profile?id=1">My profile</a></li>
<li><a href="/admin">Admin</a></li>
</ul></body></html>"""


def _make_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", USERS)
    conn.commit()
    return conn


def _make_handler(fixed: bool):
    db = _make_db()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def version_string(self):  # the Server banner
            return "webserver" if fixed else "LabServer/1.4.2"

        def log_message(self, *args):  # keep test/demo output quiet
            pass

        # --- helpers -------------------------------------------------
        def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if fixed:
                for k, v in SECURITY_HEADERS.items():
                    self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _session_uid(self):
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, val = part.strip().partition("=")
                if name == "session" and val.isdigit():
                    uid = int(val)
                    with lock:
                        if db.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
                            return uid
            return None

        def _row(self, uid):
            with lock:
                return db.execute("SELECT id, name, email FROM users WHERE id = ?", (uid,)).fetchone()

        # --- routes --------------------------------------------------
        def do_GET(self):
            parts = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            route = {
                "/": self.r_index,
                "/search": self.r_search,
                "/user": self.r_user,
                "/login": self.r_login,
                "/profile": self.r_profile,
                "/admin": self.r_admin,
                "/.env": self.r_env,
                "/backup.zip": self.r_backup,
            }.get(parts.path)
            if route is None:
                return self._send(404, "Not found")
            route(q)

        def r_index(self, q):
            self._send(200, INDEX)

        def r_search(self, q):
            term = q.get("q", "")
            shown = html.escape(term) if fixed else term  # VULN: reflected XSS
            self._send(200, f"<html><body><h1>Results for {shown}</h1><p>No results.</p></body></html>")

        def r_user(self, q):
            raw = q.get("id", "")
            if fixed:
                try:
                    uid = int(raw)
                except ValueError:
                    return self._send(400, "<p>Invalid id</p>")
                with lock:
                    row = db.execute("SELECT id, name, email FROM users WHERE id = ?", (uid,)).fetchone()
            else:
                query = f"SELECT id, name, email FROM users WHERE id = {raw}"  # VULN: SQL injection
                try:
                    with lock:
                        row = db.execute(query).fetchone()
                except sqlite3.Error as exc:
                    return self._send(500, f"<p>Database error: sqlite3.{type(exc).__name__}: {exc}</p>")
            if not row:
                return self._send(404, "<p>No such user</p>")
            self._send(200, f"<html><body><h1>{row[1]}</h1><p>{row[2]}</p></body></html>")

        def r_login(self, q):
            with lock:
                row = db.execute("SELECT id FROM users WHERE name = ?", (q.get("user", ""),)).fetchone()
            if not row:
                return self._send(401, "<p>Unknown user</p>")
            cookie = f"session={row[0]}; Path=/"
            if fixed:
                cookie += "; HttpOnly; SameSite=Strict"  # FIX: HttpOnly + SameSite
            self._send(200, "<p>Logged in.</p>", extra={"Set-Cookie": cookie})

        def r_profile(self, q):
            session = self._session_uid()
            if session is None:
                return self._send(401, "<p>Login required</p>")
            try:
                uid = int(q.get("id", ""))
            except ValueError:
                return self._send(400, "<p>Invalid id</p>")
            if fixed and uid != session and session != ADMIN_ID:  # FIX: ownership check
                return self._send(403, "<p>Forbidden</p>")
            row = self._row(uid)  # VULN (vulnerable mode): any logged-in user can read any id
            if not row:
                return self._send(404, "<p>No such profile</p>")
            self._send(200, f"<html><body><h1>Profile {row[0]}</h1><p>{row[1]} / {row[2]}</p></body></html>")

        def r_admin(self, q):
            if fixed:  # FIX: authentication + role check
                session = self._session_uid()
                if session is None:
                    return self._send(401, "<p>Login required</p>")
                if session != ADMIN_ID:
                    return self._send(403, "<p>Forbidden</p>")
            with lock:
                emails = [r[0] for r in db.execute("SELECT email FROM users")]
            self._send(200, "<html><body><h1>Admin panel</h1><p>" + ", ".join(emails) + "</p></body></html>")

        def r_env(self, q):
            if fixed:
                return self._send(404, "Not found")
            self._send(200, "DB_PASSWORD=lab-not-a-real-secret\nSECRET_KEY=lab-only\n", "text/plain")

        def r_backup(self, q):
            if fixed:
                return self._send(404, "Not found")
            self._send(200, b"PK\x03\x04lab-fake-backup-not-real", "application/zip")

    return Handler


def make_server(fixed: bool = False, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    ensure_local(f"http://{host}:{port}")
    return ThreadingHTTPServer((host, port), _make_handler(fixed))


def start_lab(fixed: bool = False, port: int = 0):
    """Start the lab in a background thread. Returns (server, base_url)."""
    server = make_server(fixed=fixed, port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
