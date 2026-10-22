# Baseline comparison protocol

This project compares its scope against GitHub `awesome-copilot`'s MIT-licensed `mcp-security-audit` Skill. The upstream baseline is a configuration-review workflow; this project is not an execution benchmark against it.

| Synthetic case | Configuration review baseline | MCP Boundary Auditor v0.1 |
| --- | --- | --- |
| Hard-coded config secret | In scope | Out of scope for current CLI |
| Unpinned package launcher | In scope | Out of scope for current CLI |
| Decorated Python tool directly calls `subprocess.run` | No source call-chain check | `MBA-BOUNDARY-001` when policy denies it |
| Direct TypeScript tool calls `fetch` | No source call-chain check | Capability inventory/policy evidence |
| Dynamic/cross-module call | Not modeled | Manual human review; never a clean verdict |

Reproduce local CLI cases with:

```text
mcp-boundary-audit scan tests/fixtures --format json
```

Results must be recorded from committed synthetic fixtures only. Do not claim runtime protection, universal detection, or an upstream measurement not actually run.
