from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_portable_skill_has_only_portable_frontmatter() -> None:
    text = (ROOT / "skills/mcp-boundary-audit/SKILL.md").read_text(encoding="utf-8")
    frontmatter = text.split("---", 2)[1]
    assert "name:" in frontmatter and "description:" in frontmatter
    assert "allowed-tools:" not in frontmatter


def test_readme_declares_static_analysis_limits() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "does not execute" in readme
    assert "mcp-boundary-audit scan" in readme
