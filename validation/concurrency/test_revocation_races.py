from __future__ import annotations

import unittest

from kernel.authority_registry import AuthorityRegistry, Permission, Principal
from kernel.mgre_kernel import GovernedKernel, Proposal, ValidationResult, sha256_changes
from kernel.state_machine import ProposalState


class RevocationRaceTests(unittest.TestCase):
    def test_revocation_before_apply_prevents_transition(self) -> None:
        registry = AuthorityRegistry(
            [
                Principal.build("proposer", [Permission.PROPOSE]),
                Principal.build("validator", [Permission.VALIDATE]),
                Principal.build("ratifier", [Permission.RATIFY]),
                Principal.build("applicator", [Permission.APPLY]),
                Principal.build("revoker", [Permission.REVOKE]),
            ]
        )
        kernel = GovernedKernel(registry)
        proposal = Proposal(
            "RACE-001",
            "proposer",
            "Ordinary change.",
            sha256_changes([("examples/change.txt", b"x")]),
        )
        kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        kernel.validate(
            proposal.proposal_id,
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        kernel.ratify(
            proposal.proposal_id,
            ratifier_id="ratifier",
            approve=True,
            recorded_at="2026-08-12T00:00:02Z",
        )
        receipt = kernel.revoke(
            proposal.proposal_id,
            revoker_id="revoker",
            recorded_at="2026-08-12T00:00:03Z",
        )
        self.assertEqual("RACE-001", receipt.proposal_id)
        self.assertEqual(ProposalState.REJECTED, receipt.state)
        self.assertEqual(ProposalState.REJECTED, kernel.state("RACE-001"))
        self.assertEqual("RACE-001", receipt.record.event["proposal_id"])
        self.assertEqual("revoke", receipt.record.event["transition"])
        self.assertEqual("revoker", receipt.record.event["actor_id"])
        with self.assertRaisesRegex(PermissionError, "proposal authority was revoked"):
            kernel.apply(
                proposal.proposal_id,
                applicator_id="applicator",
                observed_proposal_digest=proposal.digest,
                recorded_at="2026-08-12T00:00:04Z",
            )


if __name__ == "__main__":
    unittest.main()
