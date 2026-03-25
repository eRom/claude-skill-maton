"""CLI entry point for the scanner — `python -m scanner <path>`."""

from __future__ import annotations

import argparse
import sys

from scanner.core import scan_directory
from scanner.reporter import to_json, to_text

_EXIT_CODE = {"OK": 0, "WARNING": 1, "CRITICAL": 2}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description="Scan a directory for security issues in Claude skill definitions.",
    )
    parser.add_argument(
        "path",
        help="Path to the directory to scan.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        dest="format",
        help="Output format: json (default) or text.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write report to FILE instead of stdout.",
    )

    args = parser.parse_args()

    try:
        result = scan_directory(args.path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    report = to_json(result) if args.format == "json" else to_text(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
                if not report.endswith("\n"):
                    fh.write("\n")
        except OSError as exc:
            print(f"Error writing to {args.output!r}: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print(report)

    sys.exit(_EXIT_CODE.get(result.verdict, 0))


if __name__ == "__main__":
    main()
