#!/usr/bin/env python3
"""Execute the replication runner and emit machine-captured evidence outside the artifact tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess  # nosec B404
from pathlib import Path

RESULT_BY_EXIT = {
    0: "PASS",
    1: "FAIL",
    3: "INDETERMINATE",
    4: "INDETERMINATE_ARTIFACT_MUTATION",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture(root: Path, argv: list[str]) -> tuple[int, dict[str, object], bytes, bytes]:
    """Capture an operator-selected command; argv is trusted and no shell is used."""
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            argv,
            cwd=root,
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        stderr = type(exc).__name__.encode("utf-8")
        fragment: dict[str, object] = {
            "result": "INDETERMINATE",
            "commands": [
                {
                    "argv": argv,
                    "exit_code": 3,
                    "stdout_sha256": sha256_bytes(b""),
                    "stderr_sha256": sha256_bytes(stderr),
                }
            ],
            "capture_error": type(exc).__name__,
        }
        return 3, fragment, b"", stderr

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
    return completed.returncode, fragment, completed.stdout, completed.stderr


def is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if evidence_dir == root or is_within(evidence_dir, root):
        parser.error("--evidence-dir must be outside the artifact root")

    evidence_dir.mkdir(parents=True, exist_ok=True)
    argv = [str(root / "replication" / "run_all.sh")]
    code, fragment, stdout, stderr = capture(root, argv)

    stdout_path = evidence_dir / "replication.stdout.log"
    stderr_path = evidence_dir / "replication.stderr.log"
    fragment_path = evidence_dir / "replication-run.json"

    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    fragment_path.write_text(
        json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
