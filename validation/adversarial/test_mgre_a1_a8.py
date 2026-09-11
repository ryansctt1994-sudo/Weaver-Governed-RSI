from __future__ import annotations

import unittest

from kernel.authority_registry import AuthorityDenied, AuthorityRegistry, Permission, Principal
from kernel.mgre_kernel import GovernedKernel, Proposal, ValidationResult, sha256_changes
from kernel.state_machine import ProposalState


class MgreA1A8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AuthorityRegistry(
            [
                Principal.build(
                    "multi-role-proposer",
                    [
                        Permission.PROPOSE,
                        Permission.VALIDATE,
                        Permission.RATIFY,
                        Permission.APPLY,
                        Permission.REVOKE,
                    ],
                ),
                Principal.build(
                    "validator", [Permission.VALIDATE, Permission.RATIFY, Permission.APPLY]
                ),
                Principal.build("ratifier", [Permission.RATIFY, Permission.APPLY]),
                Principal.build("applicator", [Permission.APPLY]),
                Principal.build("revoker", [Permission.REVOKE]),
            ]
        )
        self.kernel = GovernedKernel(self.registry)

    def _ordinary_proposal(self, proposal_id: str) -> Proposal:
        return Proposal(
            proposal_id,
            "multi-role-proposer",
            "Ordinary change.",
            sha256_changes([("examples/change.txt", b"x")]),
        )

    def _submit_validate_ratify(self, proposal_id: str) -> Proposal:
        proposal = self._ordinary_proposal(proposal_id)
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            proposal_id,
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        self.kernel.ratify(
            proposal_id,
            ratifier_id="ratifier",
            approve=True,
            recorded_at="2026-08-12T00:00:02Z",
        )
        return proposal

    def test_a1_self_authorization_is_blocked(self) -> None:
        proposal = Proposal(
            "A1",
            "multi-role-proposer",
            "Grant ratification authority to proposer.",
            sha256_changes([("examples/change.txt", b"x")]),
            authority_target="multi-role-proposer",
            requested_permissions=("ratify",),
        )
        receipt = self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.assertEqual(ProposalState.REJECTED, receipt.state)
        self.assertIsNotNone(receipt.firewall)
        assert receipt.firewall is not None
        self.assertIn("FW-AUTH-001", [finding.code for finding in receipt.firewall.findings])

    def test_a2_proposer_cannot_validate_own_proposal(self) -> None:
        proposal = self._ordinary_proposal("A2")
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        with self.assertRaises(AuthorityDenied):
            self.kernel.validate(
                "A2",
                validator_id="multi-role-proposer",
                result=ValidationResult.PASS,
                recorded_at="2026-08-12T00:00:01Z",
            )

    def test_a3_validator_cannot_ratify_same_proposal(self) -> None:
        proposal = self._ordinary_proposal("A3")
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            "A3",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        with self.assertRaises(AuthorityDenied):
            self.kernel.ratify(
                "A3",
                ratifier_id="validator",
                approve=True,
                recorded_at="2026-08-12T00:00:02Z",
            )

    def test_a4_proposer_cannot_ratify_own_proposal(self) -> None:
        proposal = self._ordinary_proposal("A4")
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            "A4",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        with self.assertRaises(AuthorityDenied):
            self.kernel.ratify(
                "A4",
                ratifier_id="multi-role-proposer",
                approve=True,
                recorded_at="2026-08-12T00:00:02Z",
            )

    def test_a5_proposer_cannot_apply_own_proposal(self) -> None:
        proposal = self._submit_validate_ratify("A5")
        with self.assertRaises(AuthorityDenied):
            self.kernel.apply(
                "A5",
                applicator_id="multi-role-proposer",
                observed_proposal_digest=proposal.digest,
                recorded_at="2026-08-12T00:00:03Z",
            )

    def test_a6_validator_cannot_apply_validated_proposal(self) -> None:
        proposal = self._submit_validate_ratify("A6")
        with self.assertRaises(AuthorityDenied):
            self.kernel.apply(
                "A6",
                applicator_id="validator",
                observed_proposal_digest=proposal.digest,
                recorded_at="2026-08-12T00:00:03Z",
            )

    def test_a7_ratifier_cannot_apply_ratified_proposal(self) -> None:
        proposal = self._submit_validate_ratify("A7")
        with self.assertRaises(AuthorityDenied):
            self.kernel.apply(
                "A7",
                applicator_id="ratifier",
                observed_proposal_digest=proposal.digest,
                recorded_at="2026-08-12T00:00:03Z",
            )

    def test_a8_proposer_cannot_revoke_own_proposal(self) -> None:
        proposal = self._ordinary_proposal("A8")
        self.kernel.submit(proposal, recorded_at="2026-08-12T00:00:00Z")
        self.kernel.validate(
            "A8",
            validator_id="validator",
            result=ValidationResult.PASS,
            recorded_at="2026-08-12T00:00:01Z",
        )
        with self.assertRaises(AuthorityDenied):
            self.kernel.revoke(
                "A8",
                revoker_id="multi-role-proposer",
                recorded_at="2026-08-12T00:00:02Z",
            )


if __name__ == "__main__":
    unittest.main()
