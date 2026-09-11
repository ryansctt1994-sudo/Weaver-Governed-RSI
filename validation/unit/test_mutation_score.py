from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from validation.mutation.check_mutation_score import assess, classify


class MutationScoreTests(unittest.TestCase):
    def test_status_classification_is_fail_closed(self) -> None:
        self.assertEqual("survived", classify(0))
        self.assertEqual("killed", classify(1))
        self.assertEqual("not_checked", classify(None))
        self.assertEqual("timeout", classify(152))
        self.assertEqual("suspicious", classify(99))

    def test_score_gate_passes_only_complete_sufficient_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.meta").write_text(
                json.dumps({"exit_code_by_key": {"a": 1, "b": 1, "c": 1, "d": 0}}),
                encoding="utf-8",
            )
            report = assess(root, 75.0)
            self.assertTrue(report.passed)
            self.assertEqual(75.0, report.score)

    def test_unchecked_mutant_blocks_even_with_high_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.meta").write_text(
                json.dumps({"exit_code_by_key": {"a": 1, "b": 1, "c": None}}),
                encoding="utf-8",
            )
            report = assess(root, 50.0)
            self.assertFalse(report.passed)
            self.assertIn("1 mutant(s) have blocking status not_checked", report.reasons)


if __name__ == "__main__":
    unittest.main()
