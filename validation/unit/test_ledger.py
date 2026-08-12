from __future__ import annotations

import unittest
from dataclasses import replace

from kernel.ledger import AppendOnlyLedger, canonical_json


class LedgerTests(unittest.TestCase):
    def test_canonical_json_has_exact_stable_encoding(self) -> None:
        self.assertEqual(b'{"a":"\xc3\xa9","z":1}', canonical_json({"z": 1, "a": "é"}))
        with self.assertRaises(ValueError):
            canonical_json({"not_a_number": float("nan")})

    def test_chain_verifies(self) -> None:
        ledger = AppendOnlyLedger()
        ledger.append({"event": "one"}, recorded_at="2026-08-12T00:00:00Z")
        ledger.append({"event": "two"}, recorded_at="2026-08-12T00:00:01Z")
        self.assertTrue(ledger.verify().valid)

    def test_event_mutation_is_detected(self) -> None:
        ledger = AppendOnlyLedger()
        record = ledger.append({"event": "one"}, recorded_at="2026-08-12T00:00:00Z")
        altered = replace(record, event={"event": "forged"})
        verification = AppendOnlyLedger([altered]).verify()
        self.assertIs(verification.valid, False)
        self.assertEqual(0, verification.failure_index)
        self.assertEqual("record hash mismatch", verification.reason)

    def test_previous_hash_mutation_reports_exact_location(self) -> None:
        ledger = AppendOnlyLedger()
        first = ledger.append({"event": "one"}, recorded_at="2026-08-12T00:00:00Z")
        second = ledger.append({"event": "two"}, recorded_at="2026-08-12T00:00:01Z")
        forged = AppendOnlyLedger([first, replace(second, previous_hash="f" * 64)])
        verification = forged.verify()
        self.assertIs(verification.valid, False)
        self.assertEqual(1, verification.failure_index)
        self.assertEqual("previous hash mismatch", verification.reason)


if __name__ == "__main__":
    unittest.main()
