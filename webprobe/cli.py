"""Command line interface: scan, lab, compare, demo."""

import argparse
import json
import sys
from pathlib import Path

from .guard import TargetNotLocal
from .lab import make_server, start_lab
from .report import compare, render_compare_markdown, render_markdown
from .scanner import run_scan


def _write_scan(result: dict, out: Path, stem: str = "report"):
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stem}.md").write_text(render_markdown(result), encoding="utf-8")
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


def _summary_line(result: dict) -> str:
    s = result["summary"]
    parts = ", ".join(f"{k} {v}" for k, v in s.items() if v)
    return f"{len(result['findings'])} findings ({parts or 'none'})"


def cmd_scan(args) -> int:
    try:
        result = run_scan(args.target, cookie=args.cookie or "", ports=args.ports, max_pages=args.max_pages, delay=args.delay)
    except TargetNotLocal as exc:
        print(f"Refusing to scan: {exc}", file=sys.stderr)
        return 2
    _write_scan(result, Path(args.out))
    print(f"{result['target']}: {_summary_line(result)}; {result['requests']} requests")
    print(f"Report written to {Path(args.out) / 'report.md'}")
    return 0


def cmd_lab(args) -> int:
    server = make_server(fixed=args.fixed, port=args.port)
    mode = "FIXED" if args.fixed else "VULNERABLE"
    print(f"WebProbe Lab ({mode}) on http://127.0.0.1:{server.server_address[1]}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _load_scan(path: str) -> dict:
    """Read a report.json written by `webprobe scan`; raise ValueError with a readable reason."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path} is not valid JSON ({exc})") from None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or "target" not in data:
        raise ValueError(f"{path} is not a WebProbe scan report (expected report.json from `webprobe scan`)")
    return data


def cmd_compare(args) -> int:
    try:
        before, after = _load_scan(args.before), _load_scan(args.after)
        cmp = compare(before, after)
    except (ValueError, KeyError) as exc:
        print(f"Cannot compare: {exc}", file=sys.stderr)
        return 2
    text = render_compare_markdown(cmp)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(f"Resolved {len(cmp['resolved'])}, remaining {len(cmp['remaining'])}, new {len(cmp['new'])}")
    return 0


def cmd_demo(args) -> int:
    """Scan the vulnerable lab, scan the fixed lab, and write all three reports."""
    out = Path(args.out)
    results = {}
    for name, fixed in (("before", False), ("after", True)):
        server, url = start_lab(fixed=fixed)
        try:
            results[name] = run_scan(url, cookie="session=1")
        finally:
            server.shutdown()
            server.server_close()
        _write_scan(results[name], out, stem=name)
        print(f"{name} ({'fixed' if fixed else 'vulnerable'} lab): {_summary_line(results[name])}")
    cmp = compare(results["before"], results["after"])
    (out / "retest.md").write_text(render_compare_markdown(cmp), encoding="utf-8")
    print(f"Retest: resolved {len(cmp['resolved'])}, remaining {len(cmp['remaining'])}, new {len(cmp['new'])}")
    print(f"Reports written to {out}/")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="webprobe", description="Local-only web vulnerability scanner.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a local target (localhost / loopback only)")
    s.add_argument("target", help="e.g. http://127.0.0.1:8080")
    s.add_argument("--cookie", help="session cookie for authenticated checks, e.g. session=1")
    s.add_argument("--ports", action="store_true", help="also run a TCP connect scan of common ports")
    s.add_argument("--max-pages", type=int, default=30)
    s.add_argument("--delay", type=float, default=0.0, help="seconds to wait between requests")
    s.add_argument("--out", default="webprobe-out")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("lab", help="run the deliberately vulnerable demo app on 127.0.0.1")
    l.add_argument("--port", type=int, default=8080)
    l.add_argument("--fixed", action="store_true", help="run the patched version")
    l.set_defaults(func=cmd_lab)

    c = sub.add_parser("compare", help="compare two scan JSON files (retest)")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--out")
    c.set_defaults(func=cmd_compare)

    d = sub.add_parser("demo", help="scan vulnerable lab, scan fixed lab, write reports + retest")
    d.add_argument("--out", default="webprobe-out")
    d.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    return args.func(args)
