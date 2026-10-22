"""Deliberately narrow, non-executing JavaScript/TypeScript recognition."""

from __future__ import annotations

import re

from .model import Sink, SourceLocation, Tool
from .python_ast import ModuleAnalysis

_TOOL = re.compile(r"(?:server|mcp)\.tool\(\s*['\"]([^'\"]+)['\"]")


def analyze_javascript(path: str, source: str) -> ModuleAnalysis:
    """Recognize literal direct tool names and known visible sink tokens only."""
    matches = tuple(_TOOL.finditer(source))
    tools = tuple(
        Tool(
            match.group(1),
            match.group(1),
            SourceLocation(path, source[: match.start()].count("\n") + 1),
        )
        for match in matches
    )
    sinks = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        body = source[match.end() : end]
        for token, capability in (
            ("fetch(", "network.outbound"),
            ("process.env", "credentials.environment"),
            ("exec(", "process.execute"),
        ):
            offset = body.find(token)
            if offset >= 0:
                line = source[: match.end() + offset].count("\n") + 1
                sinks.append(Sink(match.group(1), capability, SourceLocation(path, line)))
    unresolved = () if tools else (SourceLocation(path, 1),)
    return ModuleAnalysis(tools, (), tuple(sinks), unresolved)
