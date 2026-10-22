"""Local-only, bounded discovery and structured-data loading."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import yaml

EXCLUDED_DIRECTORIES = frozenset(
    {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
)
MAX_FILES = 1_000
MAX_FILE_BYTES = 1_000_000


class DiscoveryError(ValueError):
    """A local input could not be safely discovered or parsed."""


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path
    files: tuple[Path, ...]
    truncated: tuple[str, ...] = ()


def discover_files(root: Path, *, max_files: int = MAX_FILES) -> DiscoveryResult:
    """Return root-relative source/config/Skill paths without escaping *root*."""
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise DiscoveryError(f"scan root is not a directory: {root}")

    files: list[Path] = []
    truncated: list[str] = []
    for path in sorted(resolved_root.rglob("*")):
        relative = path.relative_to(resolved_root)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        try:
            resolved_path = path.resolve()
        except OSError:
            truncated.append(f"could not resolve {relative.as_posix()}")
            continue
        if not _is_within(resolved_path, resolved_root):
            truncated.append(f"skipped path outside root: {relative.as_posix()}")
            continue
        if not resolved_path.is_file():
            continue
        if len(files) >= max_files:
            truncated.append(f"file limit reached ({max_files})")
            break
        files.append(relative)
    return DiscoveryResult(resolved_root, tuple(files), tuple(truncated))


def load_data_file(path: Path) -> dict[str, object]:
    """Load a JSON/YAML mapping using safe parsers and useful diagnostics."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise DiscoveryError(f"{path}: exceeds {MAX_FILE_BYTES} byte read limit")
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        raise DiscoveryError(f"{path}: could not read file: {error}") from error

    try:
        value: Any
        if path.suffix.lower() == ".json":
            value = json.loads(content)
        elif path.suffix.lower() in {".yaml", ".yml"}:
            value = yaml.safe_load(content)
        else:
            raise DiscoveryError(f"{path}: unsupported structured-data suffix")
    except (json.JSONDecodeError, yaml.YAMLError) as error:
        raise DiscoveryError(f"{path}: invalid structured data: {error}") from error
    if not isinstance(value, dict):
        raise DiscoveryError(f"{path}: expected a mapping at document root")
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
