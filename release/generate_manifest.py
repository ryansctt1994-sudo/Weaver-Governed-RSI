#!/usr/bin/env python3
"""Generate a deterministic SHA-256 manifest while rejecting unsafe file types."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from collections.abc import Iterable
from pathlib import Path

DEFAULT_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "mutants",
    }
)


class ManifestError(RuntimeError):
    """Raised when the payload cannot be identified safely."""


def iter_payload_files(
    root: Path,
    *,
    excluded_parts: Iterable[str] = DEFAULT_EXCLUDED_PARTS,
    excluded_paths: Iterable[Path] = (),
) -> tuple[Path, ...]:
    root = root.resolve()
    excluded = frozenset(excluded_parts)
    excluded_absolute = {path.resolve() for path in excluded_paths}
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts):
            continue
        if path.resolve() in excluded_absolute:
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ManifestError(f"symlink rejected: {relative.as_posix()}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ManifestError(f"non-regular file rejected: {relative.as_posix()}")
        files.append(path)
    return tuple(sorted(files, key=lambda item: item.relative_to(root).as_posix()))


def manifest_bytes(root: Path, files: Iterable[Path]) -> bytes:
    root = root.resolve()
    lines = []
    for path in files:
        relative = path.resolve().relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}\n")
    return "".join(lines).encode("utf-8")


def generate_manifest(
    root: Path,
    output: Path,
    *,
    excluded_paths: Iterable[Path] = (),
) -> bytes:
    output_absolute = output.resolve()
    files = iter_payload_files(root, excluded_paths=(output_absolute, *excluded_paths))
    data = manifest_bytes(root, files)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    os.chmod(output, 0o644)
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="path to exclude; relative paths are resolved beneath --root",
    )
    args = parser.parse_args()
    excluded = tuple(
        path if path.is_absolute() else args.root / path for path in map(Path, args.exclude)
    )
    try:
        data = generate_manifest(args.root, args.output, excluded_paths=excluded)
    except (OSError, ManifestError) as exc:
        print(f"INDETERMINATE: {exc}", file=sys.stderr)
        return 3
    print(f"wrote {len(data.splitlines())} manifest entries to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
