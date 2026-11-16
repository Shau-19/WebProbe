"""Minimal HTTP client: local-only, never follows redirects, never raises on HTTP errors."""

import hashlib
import http.client
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .guard import ensure_local

MAX_BODY = 256 * 1024
USER_AGENT = "WebProbe/1.1 (local security testing)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class Response:
    url: str
    status: int  # 0 means the request failed (connection error, timeout, ...)
    headers: dict = field(default_factory=dict)  # lower-cased names
    set_cookies: list = field(default_factory=list)
    body: str = ""
    error: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def fingerprint(self) -> tuple:
        return (self.status, hashlib.sha256(self.body.encode("utf-8", "replace")).hexdigest())


class Client:
    def __init__(self, base_url: str, cookie: str = "", timeout: float = 5.0, delay: float = 0.0):
        ensure_local(base_url)
        parts = urlsplit(base_url)
        self.base = f"{parts.scheme}://{parts.netloc}"
        self.cookie = cookie
        self.timeout = timeout
        self.delay = delay
        self.log: list = []  # (url, status) for every request made
        # ProxyHandler({}) so a system HTTP(S)_PROXY can never be used for loopback traffic.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def get(self, target: str, auth: bool = True) -> Response:
        url = urljoin(self.base + "/", target)
        ensure_local(url)
        if self.delay:
            time.sleep(self.delay)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if auth and self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            try:
                resp = self._opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as err:  # 3xx/4xx/5xx still carry a full response
                resp = err
            with resp:
                raw = resp.read(MAX_BODY)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.get_all("Set-Cookie") or []
                status = resp.status if hasattr(resp, "status") else resp.code
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            self.log.append((url, 0))
            return Response(url, 0, error=str(exc))
        self.log.append((url, status))
        return Response(url, status, headers, cookies, raw.decode("utf-8", "replace"))
