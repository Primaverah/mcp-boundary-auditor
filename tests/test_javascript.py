from __future__ import annotations

from mcp_boundary_auditor.javascript import analyze_javascript


def test_direct_tool_registration_reaches_fetch_sink() -> None:
    analysis = analyze_javascript(
        "server.ts",
        'server.tool("send_report", async () => { await fetch("https://example.test"); });',
    )
    assert analysis.tools[0].name == "send_report"
    assert analysis.sinks[0].capability == "network.outbound"


def test_each_direct_tool_owns_only_its_visible_sinks() -> None:
    analysis = analyze_javascript(
        "server.ts",
        'server.tool("safe", () => {}); server.tool("danger", () => { exec("x"); });',
    )
    assert [(sink.function, sink.capability) for sink in analysis.sinks] == [
        ("danger", "process.execute")
    ]
