#!/usr/bin/env python3
"""Execute the replication runner and emit a machine-captured receipt fragment."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess  # nosec B404
import sys
from pathlib import Path

RESULT_BY_EXIT = {
    0: "PASS",
    1: "FAIL",
    3: "INDETERMINATE",
    4: "INDETERMINATE_ARTIFACT_MUTATION",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture(root: Path, argv: list[str]) -> tuple[int, dict[str, object]]:
    try:
        completed = subprocess.run(  # nosec B603
            argv,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        fragment: dict[str, object] = {
            "result": "INDETERMINATE",
            "commands": [
                {
                    "argv": argv,
                    "exit_code": 3,
                    "stdout_sha256": sha256_bytes(b""),
                    "stderr_sha256": sha256_bytes(type(exc).__name__.encode("utf-8")),
                }
            ],
            "capture_error": type(exc).__name__,
        }
        return 3, fragment

    result = RESULT_BY_EXIT.get(completed.returncode, "FAIL")
    fragment = {
        "result": result,
        "commands": [
            {
                "argv": argv,
                "exit_code": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr_sha256": sha256_bytes(completed.stderr),
            }
        ],
    }
    return completed.returncode, fragment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    argv = [str(root / "replication" / "run_all.sh")]
    code, fragment = capture(root, argv)
    encoded = json.dumps(fragment, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
