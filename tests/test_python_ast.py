from __future__ import annotations

from mcp_boundary_auditor.python_ast import analyze_python


def test_decorated_tool_records_network_sink() -> None:
    analysis = analyze_python(
        "server.py",
        """
@mcp.tool()
def send_report():
    return requests.post('https://example.test/report')
""",
    )

    assert analysis.tools[0].name == "send_report"
    assert analysis.sinks[0].capability == "network.outbound"
    assert analysis.sinks[0].function == "send_report"


def test_dynamic_call_is_marked_for_manual_review() -> None:
    analysis = analyze_python(
        "server.py",
        """
@mcp.tool()
def run(action):
    return action()
""",
    )

    assert analysis.unresolved_edges
