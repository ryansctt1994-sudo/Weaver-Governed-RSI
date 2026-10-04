"""Acceptance tests for the bounded WGRSI-RC1 recursive-gain experiment."""

from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.wgrsi_rc1 import (
    BestStateLedger,
    CandidateMetrics,
    CandidateSystem,
    RetentionGate,
    RetentionVerdict,
    SufficiencyEvidence,
    sha256_label,
)


def system(
    label: str,
    *,
    parent: str,
    generation: int,
    capability: float,
    recursive_gain: float,
    regression: float = 0.0,
    security_violations: tuple[str, ...] = (),
) -> CandidateSystem:
    return CandidateSystem(
        artifact_sha256=sha256_label(label),
        parent_sha256=parent,
        generation=generation,
        metrics=CandidateMetrics(
            capability=capability,
            recursive_gain=recursive_gain,
            regression=regression,
            security_violations=security_violations,
        ),
    )


def sufficient() -> SufficiencyEvidence:
    return SufficiencyEvidence(
        coverage=0.95,
        independence=0.95,
        detection_power=0.90,
        latency_margin=0.90,
        uncertainty=0.05,
    )


def baseline() -> CandidateSystem:
    return system(
        "M0",
        parent=sha256_label("genesis-parent"),
        generation=0,
        capability=0.50,
        recursive_gain=0.30,
    )


def test_accepts_bounded_recursive_gain() -> None:
    base = baseline()
    candidate = system(
        "M1",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.58,
        recursive_gain=0.39,
    )
    decision = RetentionGate().evaluate(base, candidate, sufficient())
    assert decision.verdict is RetentionVerdict.ACCEPT
    assert decision.capability_delta > 0
    assert decision.recursive_gain_delta > 0


def test_sufficiency_lock_withholds_even_good_candidate() -> None:
    base = baseline()
    candidate = system(
        "M1",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.58,
        recursive_gain=0.39,
    )
    weak = replace(sufficient(), independence=0.60)
    decision = RetentionGate().evaluate(base, candidate, weak)
    assert decision.verdict is RetentionVerdict.WITHHOLD
    assert decision.reasons == ("SUFFICIENCY_LOCK",)


def test_security_violation_rejects_candidate() -> None:
    base = baseline()
    candidate = system(
        "M1",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.90,
        recursive_gain=0.90,
        security_violations=("EVALUATOR_TAMPERING",),
    )
    decision = RetentionGate().evaluate(base, candidate, sufficient())
    assert decision.verdict is RetentionVerdict.REJECT
    assert "SECURITY_VIOLATION" in decision.reasons


def test_capability_gain_without_recursive_gain_is_not_rsi_acceptance() -> None:
    base = baseline()
    candidate = system(
        "M1",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.70,
        recursive_gain=0.30,
    )
    decision = RetentionGate().evaluate(base, candidate, sufficient())
    assert decision.verdict is RetentionVerdict.REJECT
    assert "INSUFFICIENT_RECURSIVE_GAIN" in decision.reasons


def test_successor_cannot_inherit_evidence_or_authority() -> None:
    base = baseline()
    with pytest.raises(ValueError, match="evidence"):
        CandidateSystem(
            artifact_sha256=sha256_label("bad-evidence"),
            parent_sha256=base.artifact_sha256,
            generation=1,
            metrics=CandidateMetrics(0.60, 0.40),
            evidence_tier="E3",
        )
    with pytest.raises(ValueError, match="authority"):
        CandidateSystem(
            artifact_sha256=sha256_label("bad-authority"),
            parent_sha256=base.artifact_sha256,
            generation=1,
            metrics=CandidateMetrics(0.60, 0.40),
            authority="APPLY",
        )


def test_receipt_chain_and_rollback() -> None:
    base = baseline()
    ledger = BestStateLedger(base)
    gate = RetentionGate()
    m1 = system(
        "M1",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.58,
        recursive_gain=0.39,
    )
    d1 = gate.evaluate(base, m1, sufficient())
    r1 = ledger.adopt(
        m1,
        d1,
        evaluator_sha256=sha256_label("evaluator-v1"),
        hidden_eval_sha256=sha256_label("hidden-suite-v1"),
    )
    assert r1.verify()
    assert ledger.current == m1

    m2 = system(
        "M2",
        parent=m1.artifact_sha256,
        generation=2,
        capability=0.64,
        recursive_gain=0.46,
    )
    d2 = gate.evaluate(m1, m2, sufficient())
    r2 = ledger.adopt(
        m2,
        d2,
        evaluator_sha256=sha256_label("evaluator-v1"),
        hidden_eval_sha256=sha256_label("hidden-suite-v1"),
    )
    assert r2.previous_receipt_sha256 == r1.receipt_sha256
    assert r2.verify()

    restored = ledger.rollback()
    assert restored == m1
    assert ledger.current == m1


def test_rejected_candidate_cannot_change_active_state() -> None:
    base = baseline()
    ledger = BestStateLedger(base)
    candidate = system(
        "M1-bad",
        parent=base.artifact_sha256,
        generation=1,
        capability=0.49,
        recursive_gain=0.20,
    )
    decision = RetentionGate().evaluate(base, candidate, sufficient())
    with pytest.raises(PermissionError):
        ledger.adopt(
            candidate,
            decision,
            evaluator_sha256=sha256_label("evaluator-v1"),
            hidden_eval_sha256=sha256_label("hidden-suite-v1"),
        )
    assert ledger.current == base


def test_parent_substitution_is_rejected() -> None:
    base = baseline()
    candidate = system(
        "M1",
        parent=sha256_label("wrong-parent"),
        generation=1,
        capability=0.60,
        recursive_gain=0.40,
    )
    decision = RetentionGate().evaluate(base, candidate, sufficient())
    assert decision.verdict is RetentionVerdict.REJECT
    assert "PARENT_MISMATCH" in decision.reasons
