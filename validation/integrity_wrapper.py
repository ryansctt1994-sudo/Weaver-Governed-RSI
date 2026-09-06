#!/usr/bin/env python3
"""Run a validation command and detect mutation of the identified artifact tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os

# This module intentionally wraps an explicit argument vector.
import subprocess  # nosec B404
import sys
from collections.abc import Iterable
from pathlib import Path

EXCLUDED_PARTS = {
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

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INDETERMINATE = 3
EXIT_ARTIFACT_MUTATION = 4


def snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            result[relative.as_posix()] = "symlink:" + os.readlink(path)
        elif path.is_file():
            result[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def run_wrapped(root: Path, command: Iterable[str]) -> tuple[int, dict[str, object]]:
    before = snapshot(root)
    try:
        # The caller deliberately supplies argv; shell execution is disabled.
        completed = subprocess.run(tuple(command), cwd=root, check=False)  # nosec
    except OSError as exc:
        return EXIT_INDETERMINATE, {
            "status": "INDETERMINATE_INSTRUMENT",
            "reason": type(exc).__name__,
        }
    after = snapshot(root)
    if before != after:
        changed = sorted(set(before) | set(after))
        changed = [path for path in changed if before.get(path) != after.get(path)]
        return EXIT_ARTIFACT_MUTATION, {
            "status": "INDETERMINATE_ARTIFACT_MUTATION",
            "changed": changed,
        }
    if completed.returncode != 0:
        return EXIT_FAIL, {"status": "FAIL", "wrapped_exit": completed.returncode}
    return EXIT_PASS, {"status": "PASS", "wrapped_exit": 0}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("a command is required after --")
    command = args.command[1:] if args.command[0] == "--" else args.command
    code, report = run_wrapped(args.root.resolve(), command)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
