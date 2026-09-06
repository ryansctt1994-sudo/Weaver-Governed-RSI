from __future__ import annotations

import hashlib
from pathlib import Path

from replication.capture_run import RESULT_BY_EXIT, capture, is_within, sha256_bytes


def test_result_exit_mapping_is_total_for_declared_replication_states() -> None:
    assert RESULT_BY_EXIT == {
        0: "PASS",
        1: "FAIL",
        3: "INDETERMINATE",
        4: "INDETERMINATE_ARTIFACT_MUTATION",
    }


def test_capture_hashes_and_returns_raw_stdout_stderr(tmp_path: Path) -> None:
    script = tmp_path / "probe.py"
    script.write_text(
        "import sys\nprint('hello')\nprint('warning', file=sys.stderr)\nsys.exit(1)\n",
        encoding="utf-8",
    )

    code, fragment, stdout, stderr = capture(tmp_path, ["python", str(script)])
    command = fragment["commands"][0]

    assert code == 1
    assert fragment["result"] == "FAIL"
    assert stdout == b"hello\n"
    assert stderr == b"warning\n"
    assert command["exit_code"] == 1
    assert command["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert command["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()


def test_evidence_directory_containment_guard(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    assert is_within(root / "evidence", root)
    assert not is_within(tmp_path / "evidence", root)


def test_sha256_bytes_empty_digest_is_stable() -> None:
    assert sha256_bytes(b"") == hashlib.sha256(b"").hexdigest()
