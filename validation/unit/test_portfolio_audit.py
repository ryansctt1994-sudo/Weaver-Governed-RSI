from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from validation.portfolio_audit import audit


def registry(*, ceiling: str, claims: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "repository_evidence_ceiling": ceiling,
        "claims": claims,
        "known_findings": [],
    }


class PortfolioAuditTests(unittest.TestCase):
    def _audit(self, document: dict[str, object]) -> tuple[int, dict[str, object]]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return audit(path)

    def test_ceiling_without_accepted_claim_is_rejected(self) -> None:
        code, report = self._audit(registry(ceiling="E3", claims=[]))
        self.assertEqual(1, code)
        self.assertEqual("repository ceiling is not supported by accepted claims", report["reason"])
        self.assertEqual("E0", report["supported_ceiling"])

    def test_highest_identified_accepted_claim_supports_ceiling(self) -> None:
        claims: list[dict[str, object]] = [
            {
                "claim_id": "C-E2",
                "status": "ACCEPTED",
                "target_tier": "E2",
                "artifact_sha256": "a" * 64,
                "receipt_sha256": "b" * 64,
            },
            {
                "claim_id": "C-E3",
                "status": "ACCEPTED",
                "target_tier": "E3",
                "artifact_sha256": "c" * 64,
                "receipt_sha256": "d" * 64,
            },
        ]
        code, report = self._audit(registry(ceiling="E3", claims=claims))
        self.assertEqual(0, code)
        self.assertEqual(2, report["accepted_claim_count"])


if __name__ == "__main__":
    unittest.main()
