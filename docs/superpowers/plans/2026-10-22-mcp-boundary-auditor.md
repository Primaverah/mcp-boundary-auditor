# MCP Boundary Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline Python CLI and portable Skill that provides source-located MCP tool-to-capability evidence and policy-boundary findings without executing target code.

**Architecture:** The scanner discovers local configuration, Skills, and source files; language adapters normalize tool registrations, function calls, and sensitive sinks into immutable models. A bounded graph analyzer derives reachable capabilities, policy rules create findings, and report adapters render the same finding set as terminal text, JSON, or Markdown.

**Tech Stack:** Python 3.11+, `argparse`, `ast`, `dataclasses`, `pathlib`, `json`, PyYAML, pytest, Ruff, and GitHub Actions. JavaScript/TypeScript support is conservative text-based recognition; Node.js is never invoked.

**Spec:** `docs/superpowers/specs/2026-10-22-mcp-boundary-auditor-design.md`

## Global Constraints

- Scan local, user-supplied paths only; do not execute, import, install, or sandbox target code.
- Make no network requests, registry lookups, package-manager calls, or subprocess calls against a target.
- Support Python 3.11 and 3.12; keep the runtime dependency set to PyYAML only.
- Ignore `.git`, `node_modules`, `.venv`, `venv`, `dist`, `build`, and `__pycache__` while discovering files.
- Bound per-file reads, number of files, and graph depth; emit a visible manual-review finding on truncation.
- Redact secret-like values from all report formats and test assertions.
- Treat dynamic dispatch and unsupported syntax as manual-review evidence, never a clean verdict.
- The shipped `SKILL.md` must use host-neutral frontmatter (`name`, `description`) and must not direct Codex or Claude Code to mutate targets or publish results.
- Do not copy code or prose from the upstream baseline; document it only as an MIT-licensed inspiration/comparison source in `NOTICE` and evaluation material.

## Review Focus

- Malformed JSON/YAML and invalid policy capabilities must fail with a path-specific diagnostic, never a traceback or permissive policy.
- A target source file containing a real-looking token must not cause that value to appear in terminal, JSON, or Markdown reports.
- A tool that reaches an unresolved dynamic call must produce manual review rather than an incorrect `pass` result.
- Source outside the selected root, including a symlink escape, must not be scanned or reported as target content.
- An exact JSON result must remain deterministic: stable ordering of tools, findings, evidence, and capability names across runs.

---

## File structure

```text
pyproject.toml                              # packaging, console script, pytest/Ruff configuration
src/mcp_boundary_auditor/__init__.py        # version constant
src/mcp_boundary_auditor/cli.py             # argparse commands and exit-code mapping
src/mcp_boundary_auditor/model.py           # immutable normalized analysis/result types
src/mcp_boundary_auditor/discovery.py       # bounded, root-contained file discovery
src/mcp_boundary_auditor/policy.py          # YAML/JSON policy parsing and matching
src/mcp_boundary_auditor/python_ast.py      # Python AST extraction and sink classification
src/mcp_boundary_auditor/javascript.py      # conservative direct JS/TS extraction
src/mcp_boundary_auditor/graph.py           # local call-chain traversal
src/mcp_boundary_auditor/skill.py           # SKILL.md/script reference analysis
src/mcp_boundary_auditor/rules.py           # boundary and Skill findings
src/mcp_boundary_auditor/reporting.py       # terminal, JSON, Markdown renderers
src/mcp_boundary_auditor/engine.py          # orchestration with no CLI concerns
skills/mcp-boundary-audit/SKILL.md          # portable Codex/Claude Code workflow
tests/                                      # unit and integration tests
tests/fixtures/                             # synthetic static-only source/config/policy fixtures
docs/evaluation/baseline-comparison.md      # reproducible comparison protocol/results
README.md, SECURITY.md, NOTICE, LICENSE     # publication and safe-use material
.github/workflows/ci.yml                    # Python 3.11/3.12 quality gate
```

### Task 1: Package skeleton and deterministic model

**Files:**
- Create: `pyproject.toml`
- Create: `src/mcp_boundary_auditor/__init__.py`
- Create: `src/mcp_boundary_auditor/model.py`
- Create: `tests/test_model.py`

**Interfaces:**
- Produces: frozen dataclasses `SourceLocation`, `Evidence`, `Tool`, `CallEdge`, `Sink`, `Finding`, and `ScanResult`.
- Produces: `Capability` literal values: `filesystem.read`, `filesystem.write`, `process.execute`, `network.outbound`, `credentials.environment`, `database.connect`.
- Produces: `Finding.to_dict() -> dict[str, object]`, with stable, redacted serialization.

- [ ] **Step 1: Write failing model tests**

```python
def test_finding_serializes_evidence_in_source_order() -> None:
    finding = Finding(...)
    assert finding.to_dict()["evidence"][0]["line"] == 3

def test_finding_redacts_secret_like_detail() -> None:
    finding = Finding(...detail="token=sk-secret-value")
    assert "sk-secret-value" not in json.dumps(finding.to_dict())
```

- [ ] **Step 2: Run the focused test to verify failure**

Run: `python -m pytest tests/test_model.py -q`

Expected: FAIL because the package/model symbols do not exist.

- [ ] **Step 3: Implement normalized immutable models**

Implement the types above in `model.py`; normalize paths to root-relative POSIX strings, sort serialized collections by `(path, line, rule_id)`, and centralize redaction in `redact_text(value: str) -> str`.

- [ ] **Step 4: Verify the focused model tests pass**

Run: `python -m pytest tests/test_model.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the foundation**

```bash
git add pyproject.toml src/mcp_boundary_auditor tests/test_model.py
git commit -m "feat: add normalized audit models"
```

### Task 2: Safe bounded discovery and configuration loading

**Files:**
- Create: `src/mcp_boundary_auditor/discovery.py`
- Create: `tests/test_discovery.py`
- Create: `tests/fixtures/discovery/.mcp.json`
- Create: `tests/fixtures/discovery/ignored/node_modules/ignored.py`

**Interfaces:**
- Consumes: `SourceLocation` and path helpers from Task 1.
- Produces: `discover_files(root: Path) -> DiscoveryResult` and `load_data_file(path: Path) -> dict[str, object]`.
- Produces: `DiscoveryResult.files`, `DiscoveryResult.truncated`, and path-specific `DiscoveryError`.

- [ ] **Step 1: Write failing discovery tests**

```python
def test_discovery_finds_known_config_and_excludes_vendor_tree(tmp_path: Path) -> None:
    result = discover_files(tmp_path)
    assert ".mcp.json" in result.files
    assert all("node_modules" not in path for path in result.files)

def test_loader_rejects_malformed_policy_with_its_path(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError, match="policy.yaml"):
        load_data_file(tmp_path / "policy.yaml")
```

- [ ] **Step 2: Run the discovery test to verify failure**

Run: `python -m pytest tests/test_discovery.py -q`

Expected: FAIL because discovery APIs do not exist.

- [ ] **Step 3: Implement root-contained discovery**

Implement fixed exclusion directory names, maximum-file and maximum-byte limits, and `Path.resolve()` containment checks. Parse JSON by suffix and YAML only through `yaml.safe_load`; require mapping roots. A symlink resolving outside the root is skipped and recorded as truncation/manual-review metadata.

- [ ] **Step 4: Add the review-focus cases**

Add tests for an out-of-root symlink and a read-limit breach; assert neither target file is read and each condition becomes a visible truncation record.

- [ ] **Step 5: Verify discovery behavior**

Run: `python -m pytest tests/test_discovery.py -q`

Expected: PASS.

- [ ] **Step 6: Commit discovery**

```bash
git add src/mcp_boundary_auditor/discovery.py tests/test_discovery.py tests/fixtures/discovery
git commit -m "feat: discover MCP audit inputs safely"
```

### Task 3: Policy parsing and capability-boundary matching

**Files:**
- Create: `src/mcp_boundary_auditor/policy.py`
- Create: `tests/test_policy.py`
- Create: `tests/fixtures/policies/valid.yaml`
- Create: `tests/fixtures/policies/invalid-capability.yaml`

**Interfaces:**
- Consumes: `Capability` from Task 1 and `load_data_file()` from Task 2.
- Produces: `Policy`, `ToolBoundary`, `load_policy(path: Path) -> Policy`, and `evaluate_capability(policy: Policy, tool_name: str, capability: str) -> BoundaryDecision`.
- `BoundaryDecision` values are `allowed`, `denied`, `undeclared`, and `not_enforced`.

- [ ] **Step 1: Write failing policy tests**

```python
def test_explicit_deny_wins_over_allow() -> None:
    assert evaluate_capability(policy, "delete_project", "process.execute").status == "denied"

def test_unknown_capability_is_rejected_at_load_time() -> None:
    with pytest.raises(PolicyError, match="unknown capability"):
        load_policy(INVALID_POLICY)
```

- [ ] **Step 2: Run the focused policy tests to verify failure**

Run: `python -m pytest tests/test_policy.py -q`

Expected: FAIL because policy APIs do not exist.

- [ ] **Step 3: Implement the version-1 policy contract**

Validate `version: 1`, mapping-shaped `tools`, `defaults`, and `skill_boundaries`, accepted capability strings, optional `justification`, and the `require_explicit_policy` boolean. Apply tool entries before defaults; a matching deny takes precedence over allow.

- [ ] **Step 4: Add default/omitted-policy tests**

Add tests proving no policy yields `not_enforced`, an allow list yields `undeclared` for other capabilities, and invalid scalar/list shapes raise `PolicyError` with source path context.

- [ ] **Step 5: Verify policy behavior**

Run: `python -m pytest tests/test_policy.py -q`

Expected: PASS.

- [ ] **Step 6: Commit policy support**

```bash
git add src/mcp_boundary_auditor/policy.py tests/test_policy.py tests/fixtures/policies
git commit -m "feat: add auditable capability policies"
```

### Task 4: Python tool/sink extraction and local graph traversal

**Files:**
- Create: `src/mcp_boundary_auditor/python_ast.py`
- Create: `src/mcp_boundary_auditor/graph.py`
- Create: `tests/test_python_ast.py`
- Create: `tests/test_graph.py`
- Create: `tests/fixtures/python_tools/server.py`
- Create: `tests/fixtures/python_tools/helpers.py`

**Interfaces:**
- Consumes: normalized models from Task 1.
- Produces: `analyze_python(path: Path, source: str) -> ModuleAnalysis` and `reachable_sinks(tool: Tool, modules: Mapping[str, ModuleAnalysis], max_depth: int = 12) -> ReachabilityResult`.
- `ModuleAnalysis` contains tool callbacks, local functions, call edges, sinks, and unresolved edges.

- [ ] **Step 1: Write failing Python extraction tests**

```python
def test_decorated_tool_reaches_helper_network_sink() -> None:
    analysis = analyze_python(SERVER_PATH, SERVER_SOURCE)
    result = reachable_sinks(analysis.tools[0], modules)
    assert result.sinks[0].capability == "network.outbound"
    assert [item.kind for item in result.evidence] == ["tool_registration", "call", "sink"]

def test_dynamic_dispatch_is_manual_review() -> None:
    assert result.unresolved_edges
```

- [ ] **Step 2: Run extraction/graph tests to verify failure**

Run: `python -m pytest tests/test_python_ast.py tests/test_graph.py -q`

Expected: FAIL because analyzer modules do not exist.

- [ ] **Step 3: Implement conservative Python AST extraction**

Recognize `@mcp.tool`, `@server.tool`, and `@app.tool` decorators; record function calls and classify only the documented v0.1 sink APIs. Resolve same-module calls and explicit local imports. Do not follow wildcard imports, dynamic attributes, or third-party source.

- [ ] **Step 4: Implement bounded graph traversal**

Traverse deterministic local edges to depth 12. Preserve every source location along a path. On a cycle or depth limit, add an unresolved-edge record and no fabricated sink.

- [ ] **Step 5: Add sink and graph coverage**

Add parameterized tests for read/write/process/network/environment/database sinks, an import cycle, and a depth-limit case. Assert boolean/dynamic constructs are classified as manual review where static identity is unavailable.

- [ ] **Step 6: Verify Python extraction and graph tests**

Run: `python -m pytest tests/test_python_ast.py tests/test_graph.py -q`

Expected: PASS.

- [ ] **Step 7: Commit Python analysis**

```bash
git add src/mcp_boundary_auditor/python_ast.py src/mcp_boundary_auditor/graph.py tests/test_python_ast.py tests/test_graph.py tests/fixtures/python_tools
git commit -m "feat: trace Python MCP tools to sensitive sinks"
```

### Task 5: Conservative JavaScript/TypeScript extraction

**Files:**
- Create: `src/mcp_boundary_auditor/javascript.py`
- Create: `tests/test_javascript.py`
- Create: `tests/fixtures/javascript_tools/server.ts`

**Interfaces:**
- Consumes: normalized models from Task 1.
- Produces: `analyze_javascript(path: Path, source: str) -> ModuleAnalysis` compatible with Task 4 graph traversal.

- [ ] **Step 1: Write failing direct-registration tests**

```python
def test_direct_tool_registration_reaches_fetch_sink() -> None:
    analysis = analyze_javascript(SERVER_PATH, SERVER_SOURCE)
    assert analysis.tools[0].name == "send_report"
    assert analysis.sinks[0].capability == "network.outbound"

def test_indirect_or_dynamic_registration_requests_manual_review() -> None:
    assert analysis.unresolved_edges
```

- [ ] **Step 2: Run JavaScript tests to verify failure**

Run: `python -m pytest tests/test_javascript.py -q`

Expected: FAIL because the adapter does not exist.

- [ ] **Step 3: Implement only statically visible direct forms**

Recognize literal-name `server.tool(...)` and `mcp.tool(...)` registrations plus callback bodies visible in the same file. Classify `fetch`, Node child-process APIs, filesystem read/write APIs, `process.env`, and selected database client constructors. Return manual-review metadata for computed names, unknown callbacks, or unsupported syntax; do not parse/evaluate JavaScript.

- [ ] **Step 4: Verify the JavaScript adapter**

Run: `python -m pytest tests/test_javascript.py -q`

Expected: PASS.

- [ ] **Step 5: Commit JavaScript support**

```bash
git add src/mcp_boundary_auditor/javascript.py tests/test_javascript.py tests/fixtures/javascript_tools
git commit -m "feat: inspect direct JavaScript MCP tool boundaries"
```

### Task 6: Rules engine and Skill-to-script boundary analysis

**Files:**
- Create: `src/mcp_boundary_auditor/rules.py`
- Create: `src/mcp_boundary_auditor/skill.py`
- Create: `tests/test_rules.py`
- Create: `tests/test_skill.py`
- Create: `tests/fixtures/skill_script_exfiltration/SKILL.md`
- Create: `tests/fixtures/skill_script_exfiltration/scripts/upload.py`

**Interfaces:**
- Consumes: `ReachabilityResult`, `Policy`, and normalized models from Tasks 1–5.
- Produces: `evaluate_tools(...) -> list[Finding]` and `analyze_skill(path: Path, policy: Policy | None, analyses: Mapping[str, ModuleAnalysis]) -> list[Finding]`.

- [ ] **Step 1: Write failing rule tests**

```python
def test_denied_capability_has_high_confidence_call_chain() -> None:
    finding = evaluate_tools(...)[0]
    assert finding.rule_id == "MBA-BOUNDARY-001"
    assert finding.severity == "high"

def test_skill_script_exceeds_declared_boundary() -> None:
    assert {f.rule_id for f in analyze_skill(...)} == {"MBA-SKILL-001"}
```

- [ ] **Step 2: Run rule tests to verify failure**

Run: `python -m pytest tests/test_rules.py tests/test_skill.py -q`

Expected: FAIL because rules/Skill analyzers do not exist.

- [ ] **Step 3: Implement boundary rules `MBA-BOUNDARY-001` through `003`**

Map policy decisions to the specified rule IDs. A deny/undeclared mismatch with complete evidence is high severity/high confidence; incomplete or dynamic evidence remains manual review. `require_explicit_policy` controls `MBA-BOUNDARY-003`.

- [ ] **Step 4: Implement safe Skill reference analysis**

Parse Markdown text without following URLs. Resolve only explicit relative references that remain inside the Skill directory. Analyze referenced Python/JS scripts with Tasks 4–5 adapters, compare capabilities with `skill_boundaries`, and emit `MBA-SKILL-001`/`002` without executing scripts.

- [ ] **Step 5: Add review-focus and redaction tests**

Add tests for missing local references, an external URL that is deliberately not fetched, and a referenced script containing `token=sk-test-secret`; assert all formats preserve rule evidence but not token value.

- [ ] **Step 6: Verify rules and Skill analysis**

Run: `python -m pytest tests/test_rules.py tests/test_skill.py -q`

Expected: PASS.

- [ ] **Step 7: Commit boundary rules**

```bash
git add src/mcp_boundary_auditor/rules.py src/mcp_boundary_auditor/skill.py tests/test_rules.py tests/test_skill.py tests/fixtures/skill_script_exfiltration
git commit -m "feat: audit tool and Skill permission boundaries"
```

### Task 7: Engine, reports, and CLI exit contract

**Files:**
- Create: `src/mcp_boundary_auditor/engine.py`
- Create: `src/mcp_boundary_auditor/reporting.py`
- Create: `src/mcp_boundary_auditor/cli.py`
- Create: `tests/test_engine.py`
- Create: `tests/test_reporting.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: discovery, policy, adapters, graph, and rules from Tasks 2–6.
- Produces: `scan(root: Path, config_paths: Sequence[Path], policy_path: Path | None) -> ScanResult`, `main(argv: Sequence[str] | None = None) -> int`, and console command `mcp-boundary-audit`.

- [ ] **Step 1: Write failing end-to-end CLI tests**

```python
def test_scan_json_is_stable_and_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(FIXTURE), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == "1.0"

def test_fail_on_returns_two_for_high_finding() -> None:
    assert main(["scan", str(DENIED_FIXTURE), "--fail-on", "high"]) == 2
```

- [ ] **Step 2: Run CLI/report tests to verify failure**

Run: `python -m pytest tests/test_engine.py tests/test_reporting.py tests/test_cli.py -q`

Expected: FAIL because the engine and console command do not exist.

- [ ] **Step 3: Implement orchestration without target execution**

`scan()` loads only discovered/explicit files, chooses adapters by suffix, builds reachability, invokes rules, and returns sorted results. It must surface parse/truncation states as findings/diagnostics, not suppress them.

- [ ] **Step 4: Implement report formats and commands**

Provide terminal, JSON, and Markdown renderers from `ScanResult`; implement `scan`, `explain RULE_ID`, `schema policy`, and `version` through `argparse`. Map usage/parse errors to 1 and `--fail-on` matched findings to 2.

- [ ] **Step 5: Add non-execution safety integration test**

Monkeypatch process/network entry points in the scanner process to raise, scan every fixture, and assert the scan still succeeds. Also assert repeated JSON scans are byte-identical.

- [ ] **Step 6: Verify CLI behavior**

Run: `python -m pytest tests/test_engine.py tests/test_reporting.py tests/test_cli.py -q`

Expected: PASS.

- [ ] **Step 7: Commit runnable CLI**

```bash
git add src/mcp_boundary_auditor/engine.py src/mcp_boundary_auditor/reporting.py src/mcp_boundary_auditor/cli.py tests/test_engine.py tests/test_reporting.py tests/test_cli.py pyproject.toml
git commit -m "feat: add offline MCP boundary audit CLI"
```

### Task 8: Portable Skill, evaluation material, and publication baseline

**Files:**
- Create: `skills/mcp-boundary-audit/SKILL.md`
- Create: `docs/evaluation/baseline-comparison.md`
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `NOTICE`
- Create: `LICENSE`
- Create: `.github/workflows/ci.yml`
- Create: `tests/test_publication_assets.py`
- Modify: `tests/fixtures/` to add `safe_readonly_tool`, `undeclared_network`, `denied_process`, `dynamic_dispatch`, and `secret_like_arguments` if not already represented.

**Interfaces:**
- Consumes: installed `mcp-boundary-audit` CLI and committed fixture paths.
- Produces: a host-neutral agent workflow, public reproduction instructions, legal attribution, and CI proof on Python 3.11/3.12.

- [ ] **Step 1: Write failing packaging/documentation checks**

```python
def test_portable_skill_has_only_portable_frontmatter() -> None:
    metadata = parse_frontmatter(SKILL_PATH)
    assert set(metadata) == {"name", "description"}

def test_evaluation_commands_run_against_committed_fixtures() -> None:
    assert "mcp-boundary-audit scan tests/fixtures" in EVALUATION.read_text()
```

- [ ] **Step 2: Run documentation checks to verify failure**

Run: `python -m pytest tests/test_publication_assets.py -q`

Expected: FAIL because Skill and publication assets do not exist.

- [ ] **Step 3: Create the portable Skill and public documentation**

The Skill must enforce untrusted-content handling, local-only scanner invocation, evidence/limitation separation, and no mutation/publication. The README documents Python versions, install command, CLI examples, policy example, exact supported patterns, limitations, and distinct Codex/Claude copy locations for the same Skill contents.

- [ ] **Step 4: Create reproducible baseline comparison and notices**

Write a comparison table using only synthetic fixtures. State that GitHub `awesome-copilot` `mcp-security-audit` is an MIT-licensed inspiration/configuration baseline; do not claim an upstream execution result the project did not measure. Put original MIT license text in `LICENSE`; `NOTICE` records comparison provenance and no copied material.

- [ ] **Step 5: Add CI and final fixture coverage**

Set GitHub Actions to run `python -m pytest` and `ruff check .` on 3.11/3.12. Add fixture assertions for safe allowed read, undeclared network, denied process, dynamic manual review, and secret redaction.

- [ ] **Step 6: Run project verification**

Run: `python -m pytest -q && python -m ruff check . && python -m ruff format --check .`

Expected: all tests and checks PASS.

- [ ] **Step 7: Commit release-ready assets**

```bash
git add skills docs/evaluation README.md SECURITY.md NOTICE LICENSE .github tests pyproject.toml
git commit -m "docs: publish portable audit Skill and evaluation"
```

### Task 9: Final reproducibility review

**Files:**
- Modify: `README.md` only if verification exposes an inaccurate command or output claim.
- Modify: `docs/evaluation/baseline-comparison.md` only if actual fixture results differ from expected results.
- Test: entire repository.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: evidence-backed release checklist and a clean working tree.

- [ ] **Step 1: Recreate a clean environment and install the package**

Run: `python -m venv .venv-verify && .venv-verify/bin/python -m pip install .[dev]`

On Windows, use `.venv-verify\\Scripts\\python.exe` rather than shell activation.

- [ ] **Step 2: Run the documented fixture examples with the clean interpreter**

Run: `.venv-verify/bin/mcp-boundary-audit scan tests/fixtures/denied_process --policy tests/fixtures/policies/valid.yaml --format json --fail-on high`

Expected: deterministic JSON and exit status 2; no fixture command/network action executes.

- [ ] **Step 3: Run full quality checks with the clean interpreter**

Run: `.venv-verify/bin/python -m pytest -q && .venv-verify/bin/python -m ruff check . && .venv-verify/bin/python -m ruff format --check .`

Expected: PASS.

- [ ] **Step 4: Review public claims against observed output**

Check README, `SKILL.md`, and evaluation text contain no claims of universal detection, runtime enforcement, external scans, or unexecuted platform compatibility.

- [ ] **Step 5: Commit only verification-driven corrections**

```bash
git add README.md docs/evaluation/baseline-comparison.md
git commit -m "docs: align audit documentation with verification"
```

Skip this commit if no corrections are needed.
