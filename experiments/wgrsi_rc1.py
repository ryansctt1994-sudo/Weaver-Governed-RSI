"""Bounded WGRSI-RC1 recursive-gain experiment primitives.

This module models candidate improvement while keeping evaluation, retention,
evidence, and authority outside the recursive proposer.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GENESIS_RECEIPT = "0" * 64


def _require_sha256(value: str, field: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")


def _unit_interval(value: float, field: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field} must be between 0 and 1")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RetentionVerdict(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    WITHHOLD = "WITHHOLD"


@dataclass(frozen=True, slots=True)
class CandidateMetrics:
    capability: float
    recursive_gain: float
    regression: float = 0.0
    security_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _unit_interval(self.capability, "capability")
        _unit_interval(self.recursive_gain, "recursive_gain")
        _unit_interval(self.regression, "regression")


@dataclass(frozen=True, slots=True)
class SufficiencyEvidence:
    coverage: float
    independence: float
    detection_power: float
    latency_margin: float
    uncertainty: float

    def __post_init__(self) -> None:
        for field in (
            "coverage",
            "independence",
            "detection_power",
            "latency_margin",
            "uncertainty",
        ):
            _unit_interval(getattr(self, field), field)

    @property
    def score(self) -> float:
        """Weakest-link sufficiency score; uncertainty reduces admissibility."""
        return min(
            self.coverage,
            self.independence,
            self.detection_power,
            self.latency_margin,
            1.0 - self.uncertainty,
        )

    def passes(self, threshold: float) -> bool:
        _unit_interval(threshold, "threshold")
        return self.score >= threshold


@dataclass(frozen=True, slots=True)
class CandidateSystem:
    artifact_sha256: str
    parent_sha256: str
    generation: int
    metrics: CandidateMetrics
    evidence_tier: str = "E0"
    authority: str = "NONE"

    def __post_init__(self) -> None:
        _require_sha256(self.artifact_sha256, "artifact_sha256")
        _require_sha256(self.parent_sha256, "parent_sha256")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        if self.evidence_tier != "E0":
            raise ValueError("successor evidence must reset to E0")
        if self.authority != "NONE":
            raise ValueError("successor authority must reset to NONE")


@dataclass(frozen=True, slots=True)
class RetentionDecision:
    verdict: RetentionVerdict
    reasons: tuple[str, ...]
    capability_delta: float
    recursive_gain_delta: float
    sufficiency_score: float

    @property
    def accepted(self) -> bool:
        return self.verdict is RetentionVerdict.ACCEPT


@dataclass(frozen=True, slots=True)
class RetentionGate:
    min_capability_delta: float = 0.01
    min_recursive_gain_delta: float = 0.01
    max_regression: float = 0.0
    sufficiency_threshold: float = 0.80

    def evaluate(
        self,
        baseline: CandidateSystem,
        candidate: CandidateSystem,
        sufficiency: SufficiencyEvidence,
    ) -> RetentionDecision:
        reasons: list[str] = []
        capability_delta = candidate.metrics.capability - baseline.metrics.capability
        recursive_delta = candidate.metrics.recursive_gain - baseline.metrics.recursive_gain

        if candidate.parent_sha256 != baseline.artifact_sha256:
            reasons.append("PARENT_MISMATCH")
        if candidate.generation != baseline.generation + 1:
            reasons.append("GENERATION_MISMATCH")
        if candidate.metrics.security_violations:
            reasons.append("SECURITY_VIOLATION")
        if candidate.metrics.regression > self.max_regression:
            reasons.append("REGRESSION_LIMIT_EXCEEDED")
        if capability_delta < self.min_capability_delta:
            reasons.append("INSUFFICIENT_CAPABILITY_GAIN")
        if recursive_delta < self.min_recursive_gain_delta:
            reasons.append("INSUFFICIENT_RECURSIVE_GAIN")

        if reasons:
            verdict = RetentionVerdict.REJECT
        elif not sufficiency.passes(self.sufficiency_threshold):
            reasons.append("SUFFICIENCY_LOCK")
            verdict = RetentionVerdict.WITHHOLD
        else:
            verdict = RetentionVerdict.ACCEPT

        return RetentionDecision(
            verdict=verdict,
            reasons=tuple(reasons),
            capability_delta=capability_delta,
            recursive_gain_delta=recursive_delta,
            sufficiency_score=sufficiency.score,
        )


@dataclass(frozen=True, slots=True)
class CycleReceipt:
    previous_receipt_sha256: str
    baseline_sha256: str
    candidate_sha256: str
    evaluator_sha256: str
    hidden_eval_sha256: str
    verdict: str
    reasons: tuple[str, ...]
    capability_delta: float
    recursive_gain_delta: float
    sufficiency_score: float
    receipt_sha256: str

    @classmethod
    def create(
        cls,
        *,
        previous_receipt_sha256: str,
        baseline: CandidateSystem,
        candidate: CandidateSystem,
        evaluator_sha256: str,
        hidden_eval_sha256: str,
        decision: RetentionDecision,
    ) -> CycleReceipt:
        for value, field in (
            (previous_receipt_sha256, "previous_receipt_sha256"),
            (evaluator_sha256, "evaluator_sha256"),
            (hidden_eval_sha256, "hidden_eval_sha256"),
        ):
            _require_sha256(value, field)

        body = {
            "previous_receipt_sha256": previous_receipt_sha256,
            "baseline_sha256": baseline.artifact_sha256,
            "candidate_sha256": candidate.artifact_sha256,
            "evaluator_sha256": evaluator_sha256,
            "hidden_eval_sha256": hidden_eval_sha256,
            "verdict": decision.verdict.value,
            "reasons": list(decision.reasons),
            "capability_delta": decision.capability_delta,
            "recursive_gain_delta": decision.recursive_gain_delta,
            "sufficiency_score": decision.sufficiency_score,
        }
        digest = hashlib.sha256(_canonical_json(body)).hexdigest()
        return cls(
            previous_receipt_sha256=previous_receipt_sha256,
            baseline_sha256=baseline.artifact_sha256,
            candidate_sha256=candidate.artifact_sha256,
            evaluator_sha256=evaluator_sha256,
            hidden_eval_sha256=hidden_eval_sha256,
            verdict=decision.verdict.value,
            reasons=decision.reasons,
            capability_delta=decision.capability_delta,
            recursive_gain_delta=decision.recursive_gain_delta,
            sufficiency_score=decision.sufficiency_score,
            receipt_sha256=digest,
        )

    def verify(self) -> bool:
        body = asdict(self)
        body.pop("receipt_sha256")
        return hashlib.sha256(_canonical_json(body)).hexdigest() == self.receipt_sha256


class BestStateLedger:
    """Admit only accepted successors and support explicit rollback."""

    def __init__(self, baseline: CandidateSystem) -> None:
        self._accepted: list[CandidateSystem] = [baseline]
        self._active_index = 0
        self._receipts: list[CycleReceipt] = []

    @property
    def current(self) -> CandidateSystem:
        return self._accepted[self._active_index]

    @property
    def receipts(self) -> tuple[CycleReceipt, ...]:
        return tuple(self._receipts)

    def adopt(
        self,
        candidate: CandidateSystem,
        decision: RetentionDecision,
        *,
        evaluator_sha256: str,
        hidden_eval_sha256: str,
    ) -> CycleReceipt:
        if not decision.accepted:
            raise PermissionError("only ACCEPT decisions may change active state")
        if candidate.parent_sha256 != self.current.artifact_sha256:
            raise ValueError("candidate is not a child of the active state")

        previous = self._receipts[-1].receipt_sha256 if self._receipts else GENESIS_RECEIPT
        receipt = CycleReceipt.create(
            previous_receipt_sha256=previous,
            baseline=self.current,
            candidate=candidate,
            evaluator_sha256=evaluator_sha256,
            hidden_eval_sha256=hidden_eval_sha256,
            decision=decision,
        )
        del self._accepted[self._active_index + 1 :]
        self._accepted.append(candidate)
        self._active_index += 1
        self._receipts.append(receipt)
        return receipt

    def rollback(self) -> CandidateSystem:
        if self._active_index == 0:
            raise RuntimeError("no prior accepted state exists")
        self._active_index -= 1
        return self.current


def sha256_label(label: str) -> str:
    """Deterministic helper for fixtures and bounded experiments."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()
