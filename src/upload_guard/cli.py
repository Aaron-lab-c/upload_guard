"""``upload_guard`` command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from ._version import __version__
from .guard import UploadGuard, detect_type
from .types import Severity


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="upload_guard", description="Validate uploaded files: magic-number sniffing, extension checks, SVG/zip-bomb/path-traversal protection.")
    parser.add_argument("--version", action="version", version="upload_guard %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the full policy against one or more files")
    scan.add_argument("files", nargs="+")
    scan.add_argument("--allow", action="append", default=None, metavar="RULE", help='allowed type rule, e.g. "image/*", "application/pdf", ".docx" (repeatable)')
    scan.add_argument("--block", action="append", default=None, metavar="RULE", help="blocked type rule (repeatable; default blocks executables and scripts)")
    scan.add_argument("--max-size", type=int, default=None, metavar="BYTES")
    scan.add_argument("--threshold", choices=[s.name for s in Severity], default="MEDIUM", help="minimum severity that rejects (default MEDIUM)")
    scan.add_argument("--no-sanitize", action="store_true", help="report SVG problems instead of sanitising")
    scan.add_argument("--lenient-extension", action="store_true", help="do not require the extension to match the detected type")
    scan.add_argument("--json", action="store_true", help="machine readable output")
    scan.add_argument("--write-sanitized", metavar="PATH", help="write the sanitised SVG (single file only)")

    det = sub.add_parser("detect", help="print the detected type only")
    det.add_argument("files", nargs="+")
    det.add_argument("--json", action="store_true")
    return parser


def _print_result(path: str, result) -> None:
    status = "OK  " if result.ok else "FAIL"
    print("%s %s  ->  %s (%s)%s" % (status, path, result.detected.mime, result.detected.description, "" if result.size is None else "  %d bytes" % result.size))
    for f in result.findings:
        tag = "fixed" if f.remediated else f.severity.name.lower()
        print("      [%-8s] %-28s %s" % (tag, f.code, f.message))
    if result.archive:
        a = result.archive
        print("      archive: %s, %d entries, %d -> %d bytes%s" % (a.format, a.entry_count, a.total_compressed, a.total_uncompressed, " (truncated)" if a.truncated else ""))


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "detect":
        out = []
        for path in args.files:
            try:
                t = detect_type(path)
            except OSError as exc:
                print("%s: %s" % (path, exc), file=sys.stderr)
                return 2
            out.append({"file": path, **t.to_dict()})
            if not args.json:
                print("%s: %s (%s)" % (path, t.mime, t.description))
        if args.json:
            print(json.dumps(out, indent=2))
        return 0

    guard = UploadGuard(
        allowed=args.allow,
        blocked=args.block if args.block is not None else ("category:executable", "category:script"),
        max_size=args.max_size,
        reject_threshold=Severity[args.threshold],
        sanitize_svg=not args.no_sanitize,
        strict_extension=not args.lenient_extension,
    )
    exit_code = 0
    results = []
    for path in args.files:
        try:
            result = guard.scan(path)
        except OSError as exc:
            print("%s: %s" % (path, exc), file=sys.stderr)
            exit_code = 2
            continue
        results.append({"file": path, **result.to_dict()})
        if not result.ok:
            exit_code = max(exit_code, 1)
        if not args.json:
            _print_result(path, result)
        if args.write_sanitized and result.sanitized is not None and len(args.files) == 1:
            with open(args.write_sanitized, "wb") as fh:
                fh.write(result.sanitized)
    if args.json:
        print(json.dumps(results, indent=2))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
