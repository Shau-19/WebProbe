"""VAPT-style Markdown report and before/after comparison."""

from .catalog import SEVERITY_ORDER

LIMITATIONS = [
    "Automated GET-based checks only; no POST bodies, file uploads or authenticated crawling beyond one supplied cookie.",
    "Links that look destructive (logout, delete, remove, reset, ...) are skipped and listed in the notes; "
    "the filter is word-based, so a dangerous link with an innocent name could still be requested.",
    "Heuristic detection: findings are candidates to verify manually, and a clean result does not prove the absence of vulnerabilities.",
    "Not covered: business-logic flaws, CSRF, SSRF, deserialization, TLS configuration, dependency vulnerabilities.",
    "Scans local targets only by design (loopback guard).",
]


def _md(text) -> str:
    """Escape text that came from the target so it shows literally in Markdown.

    GitHub and most viewers drop unknown HTML tags, so the XSS marker <wpx...>
    would vanish from the evidence without this; it also stops a hostile page
    from injecting HTML into the report.
    """
    text = " ".join(str(text).split())
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell(text) -> str:
    return _md(text).replace("|", "\\|")


def render_markdown(result: dict) -> str:
    s = result["summary"]
    lines = [
        f"# Vulnerability Assessment Report: {result['target']}",
        "",
        f"- Tool: WebProbe {result['version']}",
        f"- Generated (UTC): {result['generated']}",
        f"- Authenticated scan: {'yes (one session cookie)' if result['authenticated'] else 'no'}",
        f"- Pages crawled: {result['pages_crawled']} | HTTP requests sent: {result['requests']} | Duration: {result['duration_s']}s",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {s.get(sev, 0)} |")
    lines.append(f"| **Total** | **{len(result['findings'])}** |")

    lines += ["", "## Scope and methodology", ""]
    lines.append(f"Target: `{result['target']}` (local only). Endpoints with parameters that were tested:")
    lines.append("")
    for ep in result["endpoints_tested"] or ["(none discovered)"]:
        lines.append(f"- `{ep}`")
    lines += [
        "",
        "Checks: security headers, server banner, cookie flags, exposed sensitive files, unauthenticated "
        "privileged pages, SQL injection (error-based and boolean-based), reflected XSS (inert marker), "
        "IDOR (needs a session cookie), plain-HTTP, optional port scan. Severity uses CVSS v3.1 base scores; "
        "findings are tagged with CWE and OWASP Top 10 (2021) categories.",
    ]
    if result["notes"]:
        lines += ["", "Notes:", ""]
        lines += [f"- {_md(n)}" for n in result["notes"]]

    lines += ["", "## Findings", ""]
    if not result["findings"]:
        lines.append("No findings.")
    for i, f in enumerate(result["findings"], 1):
        lines += [
            f"### {i}. [{f['severity']}] {_md(f['title'])}",
            "",
            "| | |",
            "|---|---|",
            f"| CVSS v3.1 | {f['cvss_score']} (`{f['cvss_vector']}`) |",
            f"| CWE | {f['cwe']} |",
            f"| OWASP | {_cell(f['owasp'])} |",
            f"| Location | `{_cell(f['url'])}` |",
            f"| Parameter | {_cell(f['parameter']) or 'n/a'} |",
            "",
            f"**Evidence:** {_md(f['evidence'])}",
            "",
            f"**Remediation:** {_md(f['remediation'])}",
            "",
        ]
    lines += ["## Limitations", ""] + [f"- {x}" for x in LIMITATIONS] + [""]
    return "\n".join(lines)


def compare(before: dict, after: dict) -> dict:
    b = {f["key"]: f for f in before["findings"]}
    a = {f["key"]: f for f in after["findings"]}
    return {
        "before_target": before["target"],
        "after_target": after["target"],
        "before_total": len(b),
        "after_total": len(a),
        "resolved": [b[k] for k in b if k not in a],
        "remaining": [a[k] for k in a if k in b],
        "new": [a[k] for k in a if k not in b],
    }


def render_compare_markdown(cmp: dict) -> str:
    lines = [
        "# Retest: before vs after",
        "",
        f"- Before: `{cmp['before_target']}` ({cmp['before_total']} findings)",
        f"- After: `{cmp['after_target']}` ({cmp['after_total']} findings)",
        f"- **Resolved: {len(cmp['resolved'])} | Remaining: {len(cmp['remaining'])} | New: {len(cmp['new'])}**",
    ]
    for label, key in (("Resolved", "resolved"), ("Remaining", "remaining"), ("New", "new")):
        lines += ["", f"## {label}", ""]
        items = cmp[key]
        if not items:
            lines.append("None.")
        for f in sorted(items, key=lambda x: (SEVERITY_ORDER[x["severity"]], x["key"])):
            _, path, param = f["key"].split("|", 2)
            where = f"{path} ({param})" if param and param != path else path
            lines.append(f"- [{f['severity']}] {_md(f['title'])} ({f['cwe']}) at `{where}`")
    lines.append("")
    return "\n".join(lines)
