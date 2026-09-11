from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from validation.evidence_registry import load_registry


def test_registry_utf8_is_independent_of_process_locale(tmp_path: Path) -> None:
    document = {"claim_id": "preuve-é-Δ", "note": "原始证据"}
    path = tmp_path / "registry.json"
    path.write_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    assert load_registry(path) == document

    # Exercise actual decoding in an ASCII-locale interpreter, including when the
    # parent runs in Python UTF-8 mode. No mock of Path.read_text is involved.
    probe = """
import json
import locale
import sys
from pathlib import Path
from validation.evidence_registry import load_registry

assert sys.flags.utf8_mode == 0
assert locale.setlocale(locale.LC_CTYPE) == "C"
path = Path(sys.argv[1])
try:
    path.read_text(encoding=None)
except UnicodeDecodeError:
    pass
else:
    raise AssertionError("negative control: default decoding must reject UTF-8 bytes")
print(json.dumps(load_registry(path), ensure_ascii=True))
"""
    completed = subprocess.run(
        [sys.executable, "-X", "utf8=0", "-c", probe, str(path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "LC_ALL": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == document
