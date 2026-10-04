"""Run a deterministic two-generation WGRSI-RC1 demonstration."""

from __future__ import annotations

import json

from experiments.wgrsi_rc1 import (
    BestStateLedger,
    CandidateMetrics,
    CandidateSystem,
    RetentionGate,
    SufficiencyEvidence,
    sha256_label,
)


def main() -> int:
    gate = RetentionGate()
    sufficiency = SufficiencyEvidence(
        coverage=0.95,
        independence=0.95,
        detection_power=0.90,
        latency_margin=0.90,
        uncertainty=0.05,
    )
    m0 = CandidateSystem(
        artifact_sha256=sha256_label("WGRSI-RC1-M0"),
        parent_sha256=sha256_label("WGRSI-RC1-GENESIS"),
        generation=0,
        metrics=CandidateMetrics(capability=0.50, recursive_gain=0.30),
    )
    ledger = BestStateLedger(m0)
    evaluator = sha256_label("WGRSI-RC1-EVALUATOR-v1")
    hidden = sha256_label("WGRSI-RC1-HIDDEN-EVAL-v1")

    summaries: list[dict[str, object]] = []
    for generation, capability, recursive_gain in ((1, 0.58, 0.39), (2, 0.64, 0.46)):
        baseline = ledger.current
        candidate = CandidateSystem(
            artifact_sha256=sha256_label(f"WGRSI-RC1-M{generation}"),
            parent_sha256=baseline.artifact_sha256,
            generation=generation,
            metrics=CandidateMetrics(
                capability=capability,
                recursive_gain=recursive_gain,
            ),
        )
        decision = gate.evaluate(baseline, candidate, sufficiency)
        if not decision.accepted:
            print(json.dumps({"status": "FAIL", "generation": generation, "reasons": decision.reasons}))
            return 1
        receipt = ledger.adopt(
            candidate,
            decision,
            evaluator_sha256=evaluator,
            hidden_eval_sha256=hidden,
        )
        summaries.append(
            {
                "generation": generation,
                "candidate_sha256": candidate.artifact_sha256,
                "capability_delta": decision.capability_delta,
                "recursive_gain_delta": decision.recursive_gain_delta,
                "sufficiency_score": decision.sufficiency_score,
                "receipt_sha256": receipt.receipt_sha256,
                "receipt_valid": receipt.verify(),
                "successor_evidence": candidate.evidence_tier,
                "successor_authority": candidate.authority,
            }
        )

    print(
        json.dumps(
            {
                "status": "PASS",
                "experiment": "WGRSI-RC1",
                "active_generation": ledger.current.generation,
                "cycles": summaries,
                "claim_boundary": "bounded-governance-experiment-not-autonomous-rsi",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
