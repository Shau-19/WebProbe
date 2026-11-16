"""Same-origin crawler: collects pages and the GET endpoints (path + parameters) to test.

Safety: a GET should never change data, but on badly built apps it often does
(/logout, /items/delete?id=7). The crawler therefore never requests a link or form
whose URL looks destructive, and every check only tests endpoints the crawler
accepted. Skipped URLs are listed in the report so nothing is silently ignored.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urldefrag, urlencode, urljoin, urlsplit

MAX_PAGES = 30
MAX_DEPTH = 2

# A destructive word standing on its own in a path segment, query name or value
# ("/items/delete", "deleteAccount", "?action=remove", "/log-out"), but not inside
# a longer word ("/dropdown", "/banner", "/preset"). Skipping a harmless link costs
# only coverage; following a harmful one can destroy data.
_DESTRUCTIVE = re.compile(
    r"(?<![A-Za-z])(?i:delete|remove|destroy|drop|truncate|purge|wipe|erase|reset|"
    r"log-?out|log-?off|sign-?out|unsubscribe|deactivate|disable|revoke|cancel|ban|kill)"
    r"(?![a-z])"   # case-sensitive on purpose: "deleteAccount" matches, "dropdown" does not
)


def looks_destructive(url: str) -> bool:
    parts = urlsplit(url)
    return bool(_DESTRUCTIVE.search(unquote(parts.path + "?" + parts.query)))


@dataclass
class Endpoint:
    path: str
    params: dict  # parameter name -> sample value

    def url_with(self, base: str, name: str, value: str) -> str:
        params = dict(self.params)
        params[name] = value
        return f"{base}{self.path}?{urlencode(params)}"

    def url(self, base: str) -> str:
        return f"{base}{self.path}?{urlencode(self.params)}" if self.params else f"{base}{self.path}"


@dataclass
class CrawlResult:
    pages: list = field(default_factory=list)  # [(url, Response)]
    endpoints: list = field(default_factory=list)  # [Endpoint]
    skipped_post_forms: int = 0
    skipped_destructive: list = field(default_factory=list)  # URLs never requested


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list = []
        self.forms: list = []  # {"method", "action", "fields": {name: value}}
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {
                "method": (a.get("method") or "get").lower(),
                "action": a.get("action") or "",
                "fields": {},
            }
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["fields"][a["name"]] = a.get("value") or "test"

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _same_origin(url: str, base: str) -> bool:
    a, b = urlsplit(url), urlsplit(base)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def crawl(client, start: str = "/", max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH) -> CrawlResult:
    result = CrawlResult()
    seen, endpoints = set(), {}
    queue = [(urldefrag(urljoin(client.base + "/", start))[0], 0)]

    def skip_if_destructive(url: str) -> bool:
        if looks_destructive(url):
            if url not in result.skipped_destructive:
                result.skipped_destructive.append(url)
            return True
        return False

    def add_endpoint(url: str, params: dict):
        if not params:
            return
        path = urlsplit(url).path or "/"
        endpoints.setdefault((path, tuple(sorted(params))), Endpoint(path, dict(params)))

    while queue and len(result.pages) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = client.get(url)
        if resp.status == 0:
            continue
        result.pages.append((url, resp))
        add_endpoint(url, dict(parse_qsl(urlsplit(url).query)))
        if "html" not in resp.content_type.lower():
            continue
        parser = _PageParser()
        try:
            parser.feed(resp.body)
        except Exception:  # malformed HTML must never abort a scan
            continue
        for form in parser.forms:
            if form["method"] != "get":
                result.skipped_post_forms += 1
                continue
            action = urldefrag(urljoin(url, form["action"]))[0]
            if _same_origin(action, client.base) and not skip_if_destructive(
                    f"{action.split('?')[0]}?{urlencode(form['fields'])}"):
                add_endpoint(action, form["fields"])
        if depth >= max_depth:
            continue
        for href in parser.links:
            target = urldefrag(urljoin(url, href))[0]
            if urlsplit(target).scheme in ("http", "https") and _same_origin(target, client.base):
                if not skip_if_destructive(target):
                    queue.append((target, depth + 1))

    result.endpoints = list(endpoints.values())
    return result
