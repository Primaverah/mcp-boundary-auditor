"""Deliberately narrow, non-executing JavaScript/TypeScript recognition."""
from __future__ import annotations

import re

from .model import Sink, SourceLocation, Tool
from .python_ast import ModuleAnalysis

_TOOL = re.compile(r"(?:server|mcp)\.tool\(\s*['\"]([^'\"]+)['\"]")


def analyze_javascript(path: str, source: str) -> ModuleAnalysis:
    """Recognize literal direct tool names and known visible sink tokens only."""
    tools = tuple(
        Tool(match.group(1), match.group(1), SourceLocation(path, source[: match.start()].count("\n") + 1))
        for match in _TOOL.finditer(source)
    )
    sinks = []
    for token, capability in (("fetch(", "network.outbound"), ("process.env", "credentials.environment"), ("exec(", "process.execute")):
        index = source.find(token)
        if index >= 0:
            sinks.append(Sink(tools[0].callback if tools else "<unknown>", capability, SourceLocation(path, source[:index].count("\n") + 1)))
    unresolved = () if tools else (SourceLocation(path, 1),)
    return ModuleAnalysis(tools, (), tuple(sinks), unresolved)
