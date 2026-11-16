"""Scan orchestration."""

import time
from datetime import datetime, timezone

from . import __version__
from .catalog import SEVERITY_ORDER
from .checks import ALL_CHECKS, Context
from .client import Client
from .crawler import crawl
from .ports import scan_ports


def run_scan(target: str, cookie: str = "", ports: bool = False, max_pages: int = 30, delay: float = 0.0) -> dict:
    """Scan a local target and return a JSON-serialisable result dict.

    Raises TargetNotLocal (before any request is made) for non-local targets.
    """
    client = Client(target, cookie=cookie, delay=delay)
    started = time.time()
    crawled = crawl(client, "/", max_pages=max_pages)
    ctx = Context(client, crawled)
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(ctx))
    if ports:
        findings.extend(scan_ports(target))
    if crawled.skipped_destructive:
        shown = ", ".join(crawled.skipped_destructive[:10])
        more = f" and {len(crawled.skipped_destructive) - 10} more" if len(crawled.skipped_destructive) > 10 else ""
        ctx.notes.append(
            f"Skipped {len(crawled.skipped_destructive)} link(s) that look destructive (logout, delete, "
            f"remove, reset, ...) and never requested them: {shown}{more}. Test these by hand if needed.")
    if crawled.skipped_post_forms:
        ctx.notes.append(f"{crawled.skipped_post_forms} POST form(s) were not tested (WebProbe only sends GET requests).")
    if not crawled.pages:
        ctx.notes.append("No page could be fetched; is the target running?")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.cvss_score, f.key))
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return {
        "tool": "WebProbe",
        "version": __version__,
        "target": client.base,
        "authenticated": bool(cookie),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 2),
        "requests": len(client.log),
        "pages_crawled": len(crawled.pages),
        "endpoints_tested": [e.url(client.base) for e in crawled.endpoints],
        "skipped_destructive_links": crawled.skipped_destructive,
        "notes": ctx.notes,
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }
