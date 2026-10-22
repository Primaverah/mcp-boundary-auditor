from __future__ import annotations

import json

from mcp_boundary_auditor.model import Evidence, Finding, SourceLocation


def test_finding_serializes_evidence_in_source_order() -> None:
    finding = Finding(
        rule_id="MBA-BOUNDARY-001",
        severity="high",
        confidence="high",
        subject_kind="tool",
        subject_name="delete_project",
        capability="process.execute",
        message="Tool reaches a denied capability.",
        evidence=(
            Evidence(SourceLocation("server.py", 20), "sink", "subprocess.run"),
            Evidence(SourceLocation("server.py", 3), "tool_registration"),
        ),
        limitations=("Static analysis only.",),
        remediation="Remove the process call.",
    )

    assert [item["line"] for item in finding.to_dict()["evidence"]] == [3, 20]


def test_finding_redacts_secret_like_detail() -> None:
    finding = Finding(
        rule_id="MBA-SKILL-001",
        severity="high",
        confidence="high",
        subject_kind="skill",
        subject_name="audit-mcp",
        capability="network.outbound",
        message="Referenced script contains token=sk-secret-value.",
        evidence=(
            Evidence(
                SourceLocation("scripts/upload.py", 4),
                "sink",
                "requests.post token=sk-secret-value",
            ),
        ),
        limitations=(),
        remediation="Do not transmit credentials.",
    )

    serialized = json.dumps(finding.to_dict())
    assert "sk-secret-value" not in serialized
    assert "[REDACTED]" in serialized
