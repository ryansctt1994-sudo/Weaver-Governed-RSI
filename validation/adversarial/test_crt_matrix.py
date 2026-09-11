from __future__ import annotations

import unittest

from validation.evidence_registry import (
    ClaimResult,
    DecisionStatus,
    EvidenceClaim,
    EvidenceTier,
    evaluate_claim,
)


def claim(**overrides: object) -> EvidenceClaim:
    values: dict[str, object] = {
        "claim_id": "C-001",
        "artifact_sha256": "a" * 64,
        "producer_id": "producer",
        "evaluator_id": "evaluator",
        "target_tier": EvidenceTier.E3,
        "result": ClaimResult.PASS,
        "receipt_sha256": "b" * 64,
        "environment_fingerprint": "env:clean-room",
        "independent": False,
        "heterogeneous": False,
    }
    values.update(overrides)
    return EvidenceClaim(**values)  # type: ignore[arg-type]


class ConstitutionalMatrixTests(unittest.TestCase):
    def test_valid_e3_claim_is_accepted_with_target_preserved(self) -> None:
        decision = evaluate_claim(claim(), current_tier=EvidenceTier.E2)
        self.assertEqual(DecisionStatus.ACCEPTED, decision.status)
        self.assertEqual(EvidenceTier.E3, decision.target_tier)
        self.assertEqual((), decision.reason_codes)
        self.assertTrue(decision.authorizes_promotion)

    def test_indeterminate_claim_never_authorizes(self) -> None:
        decision = evaluate_claim(
            claim(result=ClaimResult.INDETERMINATE), current_tier=EvidenceTier.E2
        )
        self.assertEqual(DecisionStatus.INDETERMINATE, decision.status)
        self.assertEqual(("ER-CLAIM-INDETERMINATE",), decision.reason_codes)
        self.assertFalse(decision.authorizes_promotion)

    def test_missing_artifact_receipt_and_environment_are_indeterminate(self) -> None:
        decision = evaluate_claim(
            claim(
                artifact_sha256="not-a-digest",
                receipt_sha256=None,
                environment_fingerprint=None,
            ),
            current_tier=EvidenceTier.E2,
        )
        self.assertEqual(DecisionStatus.INDETERMINATE, decision.status)
        self.assertEqual(
            (
                "ER-ARTIFACT-IDENTITY-MISSING",
                "ER-RECEIPT-IDENTITY-MISSING",
                "ER-ENVIRONMENT-MISSING",
            ),
            decision.reason_codes,
        )

    def test_non_promotion_is_rejected(self) -> None:
        decision = evaluate_claim(claim(target_tier=EvidenceTier.E2), current_tier=EvidenceTier.E2)
        self.assertEqual(DecisionStatus.REJECTED, decision.status)
        self.assertEqual(("ER-NON-PROMOTION",), decision.reason_codes)

    def test_self_evaluation_is_rejected(self) -> None:
        decision = evaluate_claim(claim(evaluator_id="producer"), current_tier=EvidenceTier.E2)
        self.assertEqual(DecisionStatus.REJECTED, decision.status)
        self.assertEqual(EvidenceTier.E3, decision.target_tier)
        self.assertIn("ER-SELF-EVALUATION", decision.reason_codes)

    def test_e1_may_record_producer_evaluated_observation(self) -> None:
        decision = evaluate_claim(
            claim(target_tier=EvidenceTier.E1, evaluator_id="producer"),
            current_tier=EvidenceTier.E0,
        )
        self.assertEqual(DecisionStatus.ACCEPTED, decision.status)
        self.assertEqual(EvidenceTier.E1, decision.target_tier)
        self.assertEqual((), decision.reason_codes)

    def test_e4_without_independence_is_indeterminate(self) -> None:
        decision = evaluate_claim(claim(target_tier=EvidenceTier.E4), current_tier=EvidenceTier.E3)
        self.assertEqual(DecisionStatus.INDETERMINATE, decision.status)
        self.assertEqual(EvidenceTier.E4, decision.target_tier)
        self.assertEqual(
            (
                "ER-INDEPENDENCE-NOT-ESTABLISHED",
                "ER-HETEROGENEITY-NOT-ESTABLISHED",
            ),
            decision.reason_codes,
        )
        self.assertFalse(decision.authorizes_promotion)

    def test_e4_requires_heterogeneity_after_independence(self) -> None:
        decision = evaluate_claim(
            claim(target_tier=EvidenceTier.E4, independent=True),
            current_tier=EvidenceTier.E3,
        )
        self.assertEqual(DecisionStatus.INDETERMINATE, decision.status)
        self.assertEqual(("ER-HETEROGENEITY-NOT-ESTABLISHED",), decision.reason_codes)

    def test_complete_e4_claim_is_accepted(self) -> None:
        decision = evaluate_claim(
            claim(target_tier=EvidenceTier.E4, independent=True, heterogeneous=True),
            current_tier=EvidenceTier.E3,
        )
        self.assertEqual(DecisionStatus.ACCEPTED, decision.status)

    def test_e5_requires_independence_but_not_e4_heterogeneity_flag(self) -> None:
        decision = evaluate_claim(
            claim(target_tier=EvidenceTier.E5, independent=True, heterogeneous=False),
            current_tier=EvidenceTier.E4,
        )
        self.assertEqual(DecisionStatus.ACCEPTED, decision.status)

    def test_e5_without_independence_preserves_tier_and_reason(self) -> None:
        decision = evaluate_claim(
            claim(target_tier=EvidenceTier.E5),
            current_tier=EvidenceTier.E4,
        )
        self.assertEqual(DecisionStatus.INDETERMINATE, decision.status)
        self.assertEqual(EvidenceTier.E5, decision.target_tier)
        self.assertEqual(("ER-INDEPENDENCE-NOT-ESTABLISHED",), decision.reason_codes)

    def test_blocking_findings_reject_otherwise_valid_claim(self) -> None:
        decision = evaluate_claim(
            claim(),
            current_tier=EvidenceTier.E2,
            unresolved_blocking_findings=("F-TEST",),
        )
        self.assertEqual(DecisionStatus.REJECTED, decision.status)
        self.assertEqual(("ER-BLOCKING-FINDINGS",), decision.reason_codes)

    def test_known_failure_precedes_indeterminacy(self) -> None:
        decision = evaluate_claim(
            claim(
                target_tier=EvidenceTier.E4,
                result=ClaimResult.FAIL,
                receipt_sha256=None,
            ),
            current_tier=EvidenceTier.E3,
        )
        self.assertEqual(DecisionStatus.REJECTED, decision.status)
        self.assertIn("ER-KNOWN-FAILURE", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
