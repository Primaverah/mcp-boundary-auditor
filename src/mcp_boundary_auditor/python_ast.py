"""Conservative Python AST extraction; never imports target modules."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .model import CallEdge, Sink, SourceLocation, Tool

_SINKS = {
    "open": "filesystem.read",
    "Path.read_text": "filesystem.read",
    "Path.read_bytes": "filesystem.read",
    "Path.write_text": "filesystem.write",
    "Path.write_bytes": "filesystem.write",
    "subprocess.run": "process.execute",
    "subprocess.call": "process.execute",
    "subprocess.Popen": "process.execute",
    "os.system": "process.execute",
    "requests.get": "network.outbound",
    "requests.post": "network.outbound",
    "httpx.get": "network.outbound",
    "httpx.post": "network.outbound",
    "urllib.request.urlopen": "network.outbound",
    "os.getenv": "credentials.environment",
    "sqlite3.connect": "database.connect",
}


@dataclass(frozen=True)
class ModuleAnalysis:
    tools: tuple[Tool, ...]
    calls: tuple[CallEdge, ...]
    sinks: tuple[Sink, ...]
    unresolved_edges: tuple[SourceLocation, ...]


def analyze_python(path: str, source: str) -> ModuleAnalysis:
    """Extract directly visible tool callbacks, calls, and known sensitive APIs."""
    tree = ast.parse(source, filename=path)
    tools: list[Tool] = []
    calls: list[CallEdge] = []
    sinks: list[Sink] = []
    unresolved: list[SourceLocation] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tool = _is_tool(node)
        if tool:
            tools.append(Tool(node.name, node.name, SourceLocation(path, node.lineno)))
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            target = _call_name(child.func)
            location = SourceLocation(path, child.lineno)
            if target is None:
                unresolved.append(location)
            elif target in _SINKS:
                sinks.append(Sink(node.name, _SINKS[target], location))
            elif (
                target in {"getattr", "eval", "exec"}
                or isinstance(child.func, ast.Name)
                and child.func.id in {arg.arg for arg in node.args.args}
            ):
                unresolved.append(location)
            else:
                calls.append(CallEdge(node.name, target, location))
    return ModuleAnalysis(tuple(tools), tuple(calls), tuple(sinks), tuple(unresolved))


def _is_tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        (
            _call_name(decorator.func if isinstance(decorator, ast.Call) else decorator) or ""
        ).endswith(".tool")
        for decorator in node.decorator_list
    )


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None
