"""Offline scan orchestration."""

from __future__ import annotations

from pathlib import Path

from .discovery import discover_files
from .javascript import analyze_javascript
from .model import ScanResult
from .policy import Policy, load_policy
from .python_ast import analyze_python
from .rules import evaluate_tool


def scan(root: Path, policy_path: Path | None = None) -> ScanResult:
    discovered = discover_files(root)
    policy: Policy | None = load_policy(policy_path) if policy_path else None
    findings = []
    for relative in discovered.files:
        path = discovered.root / relative
        if path.suffix == ".py":
            analysis = analyze_python(relative.as_posix(), path.read_text(encoding="utf-8"))
        elif path.suffix in {".js", ".ts"}:
            analysis = analyze_javascript(relative.as_posix(), path.read_text(encoding="utf-8"))
        else:
            continue
        for tool in analysis.tools:
            findings.extend(evaluate_tool(tool, analysis.sinks, policy))
    return ScanResult(tuple(findings))
