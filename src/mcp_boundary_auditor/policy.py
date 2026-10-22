"""Explicit, local capability-boundary policy support."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .discovery import DiscoveryError, load_data_file
from .model import CAPABILITIES

DecisionStatus = Literal["allowed", "denied", "undeclared", "not_enforced"]


class PolicyError(ValueError):
    """A boundary policy does not satisfy the version-1 contract."""


@dataclass(frozen=True)
class ToolBoundary:
    allow: frozenset[str] | None = None
    deny: frozenset[str] = frozenset()
    justification: str | None = None


@dataclass(frozen=True)
class Policy:
    tools: dict[str, ToolBoundary]
    defaults: ToolBoundary
    skill_boundaries: dict[str, ToolBoundary]
    require_explicit_policy: bool = False


@dataclass(frozen=True)
class BoundaryDecision:
    status: DecisionStatus


def load_policy(path: Path) -> Policy:
    try:
        data = load_data_file(path)
    except DiscoveryError as error:
        raise PolicyError(str(error)) from error
    if data.get("version") != 1:
        raise PolicyError(f"{path}: policy version must be 1")
    return Policy(
        tools=_boundaries(path, data.get("tools", {}), "tools"),
        defaults=_boundary(path, data.get("defaults", {}), "defaults"),
        skill_boundaries=_boundaries(path, data.get("skill_boundaries", {}), "skill_boundaries"),
        require_explicit_policy=_bool(path, data.get("require_explicit_policy", False)),
    )


def evaluate_capability(policy: Policy | None, tool_name: str, capability: str) -> BoundaryDecision:
    if policy is None:
        return BoundaryDecision("not_enforced")
    boundary = policy.tools.get(tool_name, policy.defaults)
    if capability in boundary.deny:
        return BoundaryDecision("denied")
    if boundary.allow is not None and capability not in boundary.allow:
        return BoundaryDecision("undeclared")
    if boundary.allow is not None:
        return BoundaryDecision("allowed")
    return BoundaryDecision("not_enforced")


def _boundaries(path: Path, value: object, label: str) -> dict[str, ToolBoundary]:
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: {label} must be a mapping")
    return {
        str(name): _boundary(path, boundary, f"{label}.{name}") for name, boundary in value.items()
    }


def _boundary(path: Path, value: object, label: str) -> ToolBoundary:
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: {label} must be a mapping")
    allow = _capabilities(path, value["allow"], f"{label}.allow") if "allow" in value else None
    deny = _capabilities(path, value.get("deny", []), f"{label}.deny")
    justification = value.get("justification")
    if justification is not None and not isinstance(justification, str):
        raise PolicyError(f"{path}: {label}.justification must be a string")
    return ToolBoundary(allow=allow, deny=deny, justification=justification)


def _capabilities(path: Path, value: object, label: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{path}: {label} must be a list of capabilities")
    unknown = sorted(set(value) - CAPABILITIES)
    if unknown:
        raise PolicyError(f"{path}: unknown capability: {', '.join(unknown)}")
    return frozenset(value)


def _bool(path: Path, value: object) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{path}: require_explicit_policy must be a boolean")
    return value
