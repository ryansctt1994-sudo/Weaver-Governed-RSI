from __future__ import annotations

import concurrent.futures
import unittest

from kernel.ledger import AppendOnlyLedger


class LedgerSerializationTests(unittest.TestCase):
    def test_concurrent_appends_are_contiguous_and_valid(self) -> None:
        ledger = AppendOnlyLedger()

        def append(index: int) -> None:
            ledger.append(
                {"index": index},
                recorded_at=f"2026-08-12T00:00:{index % 60:02d}Z",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(append, range(100)))

        self.assertEqual(list(range(100)), [record.sequence for record in ledger.records])
        self.assertTrue(ledger.verify().valid)


if __name__ == "__main__":
    unittest.main()
