from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_RESULTS = {
    "PASS",
    "FAIL",
    "INDETERMINATE",
    "INDETERMINATE_ARTIFACT_MUTATION",
}


def test_replication_result_vocabulary_is_consistent() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "replication_receipt.schema.json").read_text(encoding="utf-8")
    )
    documented = (ROOT / "replication" / "README_replication.md").read_text(encoding="utf-8")
    runner = (ROOT / "replication" / "run_all.sh").read_text(encoding="utf-8")

    schema_results = set(schema["properties"]["result"]["enum"])
    assert schema_results == EXPECTED_RESULTS

    for result in EXPECTED_RESULTS:
        assert result in documented
        assert result in runner


def test_replication_runner_covers_validation_and_repository_tests() -> None:
    runner = (ROOT / "replication" / "run_all.sh").read_text(encoding="utf-8")
    assert "python -m pytest validation tests" in runner
