"""Command-line interface for local audits."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .engine import scan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-boundary-audit")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--policy", type=Path)
    scan_parser.add_argument("--format", choices=("terminal", "json"), default="terminal")
    scan_parser.add_argument("--fail-on", choices=("high",), default=None)
    args = parser.parse_args(argv)
    result = scan(args.path, args.policy)
    payload = result.to_dict()
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for finding in payload["findings"]:
            print(f"[{finding['severity'].upper()}] {finding['rule_id']}: {finding['message']}")
        print(f"Findings: {len(payload['findings'])}")
    return 2 if args.fail_on == "high" and payload["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
