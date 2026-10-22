from __future__ import annotations

from pathlib import Path

import pytest

from mcp_boundary_auditor.policy import PolicyError, evaluate_capability, load_policy


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_explicit_deny_wins_over_allow(tmp_path: Path) -> None:
    policy = load_policy(
        _write_policy(
            tmp_path,
            "version: 1\ntools:\n  delete_project:\n    allow: [process.execute]\n    deny: [process.execute]\n",
        )
    )
    assert evaluate_capability(policy, "delete_project", "process.execute").status == "denied"


def test_unknown_capability_is_rejected_at_load_time(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "version: 1\ndefaults:\n  allow: [magic.teleport]\n")
    with pytest.raises(PolicyError, match="unknown capability"):
        load_policy(path)


def test_omitted_allow_list_does_not_enforce_other_capabilities(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, "version: 1\ntools:\n  read:\n    deny: [process.execute]\n"))
    assert evaluate_capability(policy, "read", "filesystem.read").status == "not_enforced"
