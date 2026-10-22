from __future__ import annotations

import json
from pathlib import Path

from mcp_boundary_auditor.cli import main


def test_scan_reports_denied_process_capability(tmp_path: Path, capsys) -> None:
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef dangerous():\n    return subprocess.run(['echo', 'x'])\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\ntools:\n  dangerous:\n    deny: [process.execute]\n", encoding="utf-8"
    )

    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--policy",
                str(policy),
                "--format",
                "json",
                "--fail-on",
                "high",
            ]
        )
        == 2
    )
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["rule_id"] == "MBA-BOUNDARY-001"


def test_scan_follows_same_file_helper_call(tmp_path: Path, capsys) -> None:
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef dangerous():\n    return run_command()\n\ndef run_command():\n    return subprocess.run(['echo', 'x'])\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\ntools:\n  dangerous:\n    deny: [process.execute]\n", encoding="utf-8"
    )

    assert main(["scan", str(tmp_path), "--policy", str(policy), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["subject"]["name"] == "dangerous"
