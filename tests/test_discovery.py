from __future__ import annotations

from pathlib import Path

import pytest

from mcp_boundary_auditor.discovery import DiscoveryError, discover_files, load_data_file


def test_discovery_finds_known_config_and_excludes_vendor_tree(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "server.py").write_text("not python source to scan", encoding="utf-8")

    result = discover_files(tmp_path)

    assert ".mcp.json" in {path.as_posix() for path in result.files}
    assert all("node_modules" not in path.parts for path in result.files)


def test_loader_rejects_malformed_policy_with_its_path(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("tools: [", encoding="utf-8")

    with pytest.raises(DiscoveryError, match="policy.yaml"):
        load_data_file(policy)


def test_discovery_skips_symlink_outside_selected_root(tmp_path: Path) -> None:
    external = tmp_path.parent / "external.py"
    external.write_text("print('outside')", encoding="utf-8")
    link = tmp_path / "outside.py"
    try:
        link.symlink_to(external)
    except OSError:
        pytest.skip("symlinks unavailable")

    result = discover_files(tmp_path)

    assert link not in result.files
    assert result.truncated
