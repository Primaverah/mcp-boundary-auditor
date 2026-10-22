# MCP Boundary Auditor

An offline static CLI for reviewing which exposed MCP tools visibly reach sensitive local capabilities, and whether an explicit policy permits that reach.

```powershell
python -m pip install -e .
mcp-boundary-audit scan . --policy policy.yaml --format json --fail-on high
```

## What it checks

- Python decorators such as `@mcp.tool()` and direct JavaScript/TypeScript `server.tool("name", ...)` registrations.
- Directly visible filesystem, process, network, environment, and database sink APIs.
- Local policy mismatches with source-located evidence.

## Safety and limits

The scanner does not execute or import target code, run package managers, or make network requests. It is static, same-file analysis in v0.1: dynamic dispatch, cross-module calls, reflection, and unknown language forms require human review and must not be treated as a clean result.

## Portable Skill

Copy `skills/mcp-boundary-audit/` into `.claude/skills/` (Claude Code) or `.codex/skills/` (Codex). The `SKILL.md` is host-neutral and invokes only the local CLI.

## Provenance

This is an independent implementation. GitHub's MIT-licensed `awesome-copilot` `mcp-security-audit` Skill is acknowledged as a configuration-audit inspiration and comparison baseline; no upstream code or prose is included.
