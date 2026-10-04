"""Deterministic WGRSI-RC3 demonstration."""

from __future__ import annotations

import json

from experiments.wgrsi_rc3 import (
    FailureEvidence,
    Insight,
    InsightAdmissionPolicy,
    InternalizationEvaluation,
    InternalizationGate,
    sha256_text,
)


def main() -> int:
    failure = FailureEvidence(
        task_sha256=sha256_text("rc3-task"),
        attempt_sha256=sha256_text("rc3-failed-attempt"),
        verifier_output_sha256=sha256_text("rc3-verifier-output"),
        verifier_identity_sha256=sha256_text("rc2-isolated-evaluator"),
        failure_code="BOUNDARY_CASE_FAILURE",
    )
    candidate_insight = Insight(
        insight_id="rc3-insight-001",
        generation=1,
        text="Check boundary conditions and validate the final state before submission.",
        source_failure_sha256=failure.digest,
        generator_sha256=sha256_text("rc3-insight-generator-v1"),
    )
    assessment = InsightAdmissionPolicy().assess(
        candidate_insight,
        known_failure_sha256=failure.digest,
        max_generation=1,
    )
    eval_result = InternalizationEvaluation(
        assisted_score=0.80,
        no_context_score=0.67,
        heldout_score=0.61,
        next_cycle_gain=0.08,
    )
    internalized, reasons = InternalizationGate().evaluate(
        baseline_no_context=0.50,
        baseline_heldout=0.50,
        result=eval_result,
    )
    passed = assessment.status.value == "ADMITTED" and internalized
    print(json.dumps({
        "status": "PASS" if passed else "FAIL",
        "experiment": "WGRSI-RC3",
        "failure_evidence_sha256": failure.digest,
        "insight_sha256": candidate_insight.digest,
        "insight_status": assessment.status.value,
        "insight_reasons": assessment.reasons,
        "no_context_score": eval_result.no_context_score,
        "heldout_score": eval_result.heldout_score,
        "recursive_gain": eval_result.recursive_gain,
        "internalization_reasons": reasons,
        "claim_boundary": "bounded-insight-internalization-experiment",
    }, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
