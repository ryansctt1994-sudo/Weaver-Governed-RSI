from __future__ import annotations

import unittest
from dataclasses import replace

from kernel.authority_registry import AuthorityRegistry, Permission, Principal
from kernel.ledger import AppendOnlyLedger
from kernel.mgre_kernel import GovernedKernel, Proposal, ValidationResult, sha256_changes
from kernel.replay import ReplayError, replay
from kernel.state_machine import ProposalState


class MgreAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = AuthorityRegistry(
            [
                Principal.build("proposer", [Permission.PROPOSE]),
                Principal.build("validator", [Permission.VALIDATE]),
                Principal.build("ratifier", [Permission.RATIFY]),
                Principal.build("applicator", [Permission.APPLY]),
            ]
        )
        self.kernel = GovernedKernel(registry)

    def test_undeclared_protected_change_is_blocked(self) -> None:
        proposal = Proposal(
            "ADV-01",
            "proposer",
            "Modify the recursion firewall.",
            sha256_changes([("kernel/recursion_firewall.py", b"allow everything")]),
        )
        receipt = self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.assertEqual(ProposalState.REJECTED, receipt.state)

    def test_payload_substitution_becomes_indeterminate(self) -> None:
        proposal = Proposal(
            "ADV-02",
            "proposer",
            "Ordinary change.",
            sha256_changes([("examples/change.txt", b"original")]),
        )
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            "ADV-02",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        self.kernel.ratify(
            "ADV-02",
            ratifier_id="ratifier",
            approve=True,
            recorded_at="2026-08-12T00:00:02Z",
        )
        result = self.kernel.apply(
            "ADV-02",
            applicator_id="applicator",
            observed_proposal_digest="f" * 64,
            recorded_at="2026-08-12T00:00:03Z",
        )
        self.assertEqual(ProposalState.INDETERMINATE, result.state)

    def test_reordered_ledger_fails_replay(self) -> None:
        proposal = Proposal(
            "ADV-03",
            "proposer",
            "Ordinary change.",
            sha256_changes([("examples/change.txt", b"original")]),
        )
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            "ADV-03",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        first, second = self.kernel.ledger.records
        forged = AppendOnlyLedger([replace(second, sequence=0), replace(first, sequence=1)])
        with self.assertRaisesRegex(
            ReplayError, "ledger verification failed at 0: previous hash mismatch"
        ):
            replay(forged)

    def test_each_missing_replay_field_is_rejected_as_missing(self) -> None:
        for event in (
            {"transition": "submit"},
            {"proposal_id": "ADV-MISSING"},
        ):
            with self.subTest(event=event):
                ledger = AppendOnlyLedger()
                ledger.append(event, recorded_at="2026-08-12T00:00:00Z")
                with self.assertRaisesRegex(ReplayError, "record 0 lacks replay fields"):
                    replay(ledger)


if __name__ == "__main__":
    unittest.main()
