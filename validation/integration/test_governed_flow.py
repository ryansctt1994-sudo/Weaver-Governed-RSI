from __future__ import annotations

import unittest

from kernel.authority_registry import AuthorityRegistry, Permission, Principal
from kernel.mgre_kernel import GovernedKernel, Proposal, ValidationResult, sha256_changes
from kernel.replay import replay
from kernel.state_machine import ProposalState


class GovernedFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = AuthorityRegistry(
            [
                Principal.build("proposer", [Permission.PROPOSE]),
                Principal.build("validator", [Permission.VALIDATE]),
                Principal.build("ratifier", [Permission.RATIFY]),
                Principal.build("applicator", [Permission.APPLY]),
                Principal.build("revoker", [Permission.REVOKE]),
            ]
        )
        self.kernel = GovernedKernel(registry)
        self.proposal = Proposal(
            "P-001",
            "proposer",
            "Change a non-protected example.",
            sha256_changes([("examples/heuristic.txt", b"bounded improvement")]),
        )

    def test_end_to_end_flow_and_replay(self) -> None:
        submitted = self.kernel.submit(self.proposal, recorded_at="2026-08-12T00:00:00Z")
        self.assertEqual(ProposalState.SUBMITTED, submitted.state)
        self.assertEqual("P-001", submitted.proposal_id)
        self.assertEqual(ProposalState.SUBMITTED, self.kernel.state("P-001"))
        self.assertEqual(
            {"proposal_id", "proposal_digest", "transition", "actor_id", "details"},
            set(submitted.record.event),
        )
        self.assertEqual("proposer", submitted.record.event["actor_id"])
        self.assertEqual(self.proposal.digest, submitted.record.event["proposal_digest"])
        self.assertEqual([], submitted.record.event["details"]["finding_codes"])
        self.assertEqual([], submitted.record.event["details"]["protected_paths"])
        validated = self.kernel.validate(
            "P-001",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        self.assertEqual("P-001", validated.proposal_id)
        self.assertEqual(ProposalState.VALIDATED, validated.state)
        self.assertEqual(ProposalState.VALIDATED, self.kernel.state("P-001"))
        self.assertEqual("validator", validated.record.event["actor_id"])
        self.assertEqual("PASS", validated.record.event["details"]["validation_result"])
        ratified = self.kernel.ratify(
            "P-001",
            ratifier_id="ratifier",
            approve=True,
            recorded_at="2026-08-12T00:00:02Z",
        )
        self.assertEqual("P-001", ratified.proposal_id)
        self.assertEqual(ProposalState.RATIFIED, ratified.state)
        self.assertEqual(ProposalState.RATIFIED, self.kernel.state("P-001"))
        self.assertEqual("ratifier", ratified.record.event["actor_id"])
        self.assertIs(ratified.record.event["details"]["approved"], True)
        receipt = self.kernel.apply(
            "P-001",
            applicator_id="applicator",
            observed_proposal_digest=self.proposal.digest,
            recorded_at="2026-08-12T00:00:03Z",
        )
        self.assertEqual("P-001", receipt.proposal_id)
        self.assertEqual(ProposalState.APPLIED, receipt.state)
        self.assertEqual(ProposalState.APPLIED, self.kernel.state("P-001"))
        self.assertEqual("applicator", receipt.record.event["actor_id"])
        self.assertEqual(
            self.proposal.digest,
            receipt.record.event["details"]["observed_proposal_digest"],
        )
        result = replay(self.kernel.ledger)
        self.assertEqual(ProposalState.APPLIED, result.states["P-001"])
        self.assertEqual(4, result.record_count)

    def test_declared_protected_change_enters_validation_not_execution(self) -> None:
        proposal = Proposal(
            "P-PROTECTED",
            "proposer",
            "Propose a separately reviewed constitutional amendment.",
            sha256_changes([("constitution/invariants.yaml", b"candidate")]),
            protected_change_declared=True,
        )
        receipt = self.kernel.submit(proposal, recorded_at="2026-08-12T00:01:00Z")
        self.assertEqual(ProposalState.SUBMITTED, receipt.state)
        self.assertIsNotNone(receipt.firewall)
        assert receipt.firewall is not None
        self.assertEqual(("constitution/invariants.yaml",), receipt.firewall.protected_paths)


if __name__ == "__main__":
    unittest.main()
