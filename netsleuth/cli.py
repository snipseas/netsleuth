"""Command-line entry point: `netsleuth serve` and `netsleuth analyze`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__


def _default_data_dir() -> str:
    return os.environ.get("NETSLEUTH_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".local", "share", "netsleuth")


def cmd_serve(args) -> int:
    import uvicorn

    from .server.app import create_app

    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    if not loopback:
        print("WARNING: NetSleuth has no authentication. Binding to a non-loopback address "
              "exposes uploaded captures to everyone who can reach this port.", file=sys.stderr)
    allowed = ["localhost", "127.0.0.1", "[::1]"] if loopback else None
    app = create_app(args.data_dir, workers=args.workers, allowed_hosts=allowed)
    print(f"NetSleuth {__version__} - data directory: {os.path.abspath(args.data_dir)}")
    print(f"Open http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_analyze(args) -> int:
    from .analysis.pipeline import analyze_capture
    from .ingest.reader import CaptureFormatError
    from .report.builder import build_report, render_html, render_markdown
    from .storage.store import CaptureStore

    if not os.path.isfile(args.capture):
        print(f"error: {args.capture}: no such file", file=sys.stderr)
        return 2
    keep = args.db is not None
    db_path = args.db or os.path.join(tempfile.mkdtemp(prefix="netsleuth-"), "analysis.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    def progress(stage: str, frac: float) -> None:
        if not args.quiet and sys.stderr.isatty():
            print(f"\r{stage:<10} {frac * 100:5.1f}%", end="", file=sys.stderr)

    try:
        summary = analyze_capture(args.capture, db_path, progress=progress)
    except CaptureFormatError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return 1
    if not args.quiet and sys.stderr.isatty():
        print("\r" + " " * 30 + "\r", end="", file=sys.stderr)

    with CaptureStore(db_path, readonly=True) as store:
        report = build_report(store)
    if args.report:
        fmt = args.format or os.path.splitext(args.report)[1].lstrip(".").lower()
        if fmt in ("md", "markdown"):
            text = render_markdown(report)
        elif fmt == "json":
            text = json.dumps(report, indent=2)
        else:
            text = render_html(report)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text)

    if args.json:
        print(json.dumps({"summary": summary, "findings": report["findings"]}, indent=2))
    else:
        s = summary
        print(f"{s['filename']}: {s['packets']:,} packets, {s['flows']:,} connections, "
              f"{s['hosts']} hosts, analysed in {s['analysis_seconds']}s")
        for w in s["warnings"]:
            print(f"  note: {w}")
        if not report["findings"]:
            print("No findings.")
        for f in report["findings"]:
            print(f"  [{f['severity'].upper():6}] conf {f['confidence']:.2f}  {f['title']}")
            print(f"           {f['summary']}")
        if args.report:
            print(f"Report written to {args.report}")
    if keep:
        print(f"Analysis database kept at {db_path}", file=sys.stderr)
    else:
        try:
            os.remove(db_path)
            os.rmdir(os.path.dirname(db_path))
        except OSError:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netsleuth", description="Network forensics and threat analysis for PCAP/PCAPNG captures.")
    parser.add_argument("--version", action="version", version=f"netsleuth {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="start the web interface and API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8600)
    p.add_argument("--data-dir", default=_default_data_dir())
    p.add_argument("--workers", type=int, default=2, help="analysis worker processes")
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("analyze", help="analyse one capture from the command line")
    p.add_argument("capture")
    p.add_argument("--report", help="write an investigation report to this path")
    p.add_argument("--format", choices=["html", "md", "json"], help="report format (default: from extension)")
    p.add_argument("--json", action="store_true", help="print summary and findings as JSON")
    p.add_argument("--db", help="keep the analysis database at this path")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_analyze)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
