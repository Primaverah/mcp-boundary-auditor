"""Policy mismatch findings over statically observed tool capabilities."""

from __future__ import annotations

from .model import Evidence, Finding, Sink, Tool
from .policy import Policy, evaluate_capability


def evaluate_tool(tool: Tool, sinks: tuple[Sink, ...], policy: Policy | None) -> list[Finding]:
    findings: list[Finding] = []
    for sink in sinks:
        if sink.function != tool.callback:
            continue
        decision = evaluate_capability(policy, tool.name, sink.capability)
        if decision.status not in {"denied", "undeclared"}:
            continue
        rule_id = "MBA-BOUNDARY-001" if decision.status == "denied" else "MBA-BOUNDARY-002"
        findings.append(
            Finding(
                rule_id=rule_id,
                severity="high",
                confidence="high",
                subject_kind="tool",
                subject_name=tool.name,
                capability=sink.capability,
                message=f"Exposed tool reaches {sink.capability} but policy does not permit it.",
                evidence=(
                    Evidence(tool.location, "tool_registration"),
                    Evidence(sink.location, "sink", sink.capability),
                ),
                limitations=("Static same-file analysis only.",),
                remediation="Remove the capability or add a reviewed policy allowance.",
            )
        )
    return findings
