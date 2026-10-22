from __future__ import annotations

from mcp_boundary_auditor.javascript import analyze_javascript


def test_direct_tool_registration_reaches_fetch_sink() -> None:
    analysis = analyze_javascript(
        "server.ts",
        'server.tool("send_report", async () => { await fetch("https://example.test"); });',
    )
    assert analysis.tools[0].name == "send_report"
    assert analysis.sinks[0].capability == "network.outbound"
