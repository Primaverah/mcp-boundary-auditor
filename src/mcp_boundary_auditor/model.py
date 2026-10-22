"""Normalized, deterministic data types shared by the scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Capability = Literal[
    "filesystem.read",
    "filesystem.write",
    "process.execute",
    "network.outbound",
    "credentials.environment",
    "database.connect",
]

CAPABILITIES: frozenset[str] = frozenset(
    {
        "filesystem.read",
        "filesystem.write",
        "process.execute",
        "network.outbound",
        "credentials.environment",
        "database.connect",
    }
)

_SECRET_VALUE = re.compile(
    r"(?i)(?:sk-|gh[pousr]_)[A-Za-z0-9_\-]{8,}|(?i:token|secret|password)=[^\s,;]+"
)


def redact_text(value: str) -> str:
    """Redact token-shaped material while retaining useful sink evidence."""
    return _SECRET_VALUE.sub("[REDACTED]", value)


@dataclass(frozen=True, order=True)
class SourceLocation:
    path: str
    line: int

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path.replace("\\", "/"), "line": self.line}


@dataclass(frozen=True)
class Evidence:
    location: SourceLocation
    kind: str
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        result = self.location.to_dict() | {"kind": self.kind}
        if self.detail:
            result["detail"] = redact_text(self.detail)
        return result


@dataclass(frozen=True)
class Tool:
    name: str
    callback: str
    location: SourceLocation


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    location: SourceLocation


@dataclass(frozen=True)
class Sink:
    function: str
    capability: Capability
    location: SourceLocation


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    subject_kind: str
    subject_name: str
    capability: str
    message: str
    evidence: tuple[Evidence, ...]
    limitations: tuple[str, ...]
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "subject": {"kind": self.subject_kind, "name": self.subject_name},
            "capability": self.capability,
            "message": redact_text(self.message),
            "evidence": [
                item.to_dict() for item in sorted(self.evidence, key=lambda item: item.location)
            ],
            "limitations": list(self.limitations),
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "findings": [
                finding.to_dict()
                for finding in sorted(
                    self.findings,
                    key=lambda item: (
                        item.evidence[0].location.path if item.evidence else "",
                        item.evidence[0].location.line if item.evidence else 0,
                        item.rule_id,
                    ),
                )
            ],
        }
