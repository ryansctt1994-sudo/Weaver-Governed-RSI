"""WGRSI-RC3 governed insight internalization primitives."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_sha(value: str, field: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")


class InsightStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    ADMITTED = "ADMITTED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class FailureEvidence:
    task_sha256: str
    attempt_sha256: str
    verifier_output_sha256: str
    verifier_identity_sha256: str
    failure_code: str

    def __post_init__(self) -> None:
        for field in (
            "task_sha256",
            "attempt_sha256",
            "verifier_output_sha256",
            "verifier_identity_sha256",
        ):
            _require_sha(getattr(self, field), field)
        if not self.failure_code.strip():
            raise ValueError("failure_code is required")

    @property
    def digest(self) -> str:
        return _sha256_bytes(_canonical_json({
            "task_sha256": self.task_sha256,
            "attempt_sha256": self.attempt_sha256,
            "verifier_output_sha256": self.verifier_output_sha256,
            "verifier_identity_sha256": self.verifier_identity_sha256,
            "failure_code": self.failure_code,
        }))


@dataclass(frozen=True, slots=True)
class Insight:
    insight_id: str
    generation: int
    text: str
    source_failure_sha256: str
    generator_sha256: str
    parent_insight_sha256s: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.insight_id.strip() or not self.text.strip():
            raise ValueError("insight_id and text are required")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        _require_sha(self.source_failure_sha256, "source_failure_sha256")
        _require_sha(self.generator_sha256, "generator_sha256")
        for parent in self.parent_insight_sha256s:
            _require_sha(parent, "parent_insight_sha256s")

    @property
    def digest(self) -> str:
        return _sha256_bytes(_canonical_json({
            "insight_id": self.insight_id,
            "generation": self.generation,
            "text": self.text,
            "source_failure_sha256": self.source_failure_sha256,
            "generator_sha256": self.generator_sha256,
            "parent_insight_sha256s": list(self.parent_insight_sha256s),
        }))


@dataclass(frozen=True, slots=True)
class InsightAssessment:
    status: InsightStatus
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InsightAdmissionPolicy:
    banned_markers: tuple[str, ...] = (
        "ignore evaluator",
        "read hidden",
        "modify grader",
        "self-authorize",
        "grant authority",
    )

    def assess(
        self,
        insight: Insight,
        *,
        known_failure_sha256: str,
        max_generation: int,
    ) -> InsightAssessment:
        reasons: list[str] = []
        if insight.source_failure_sha256 != known_failure_sha256:
            reasons.append("UNBOUND_FAILURE_EVIDENCE")
        if insight.generation > max_generation:
            reasons.append("GENERATION_AHEAD_OF_ACTIVE_LINEAGE")
        lowered = insight.text.lower()
        if any(marker in lowered for marker in self.banned_markers):
            reasons.append("POISONED_OR_AUTHORITY_SEEKING_INSIGHT")

        status = InsightStatus.ADMITTED if not reasons else InsightStatus.REJECTED
        return InsightAssessment(status=status, reasons=tuple(reasons))


@dataclass(frozen=True, slots=True)
class InternalizationEvaluation:
    assisted_score: float
    no_context_score: float
    heldout_score: float
    next_cycle_gain: float

    def __post_init__(self) -> None:
        for field in ("assisted_score", "no_context_score", "heldout_score", "next_cycle_gain"):
            value = getattr(self, field)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{field} must be between 0 and 1")

    @property
    def internalized(self) -> bool:
        return self.no_context_score > 0.0 and self.heldout_score > 0.0

    @property
    def recursive_gain(self) -> float:
        return self.next_cycle_gain


@dataclass(frozen=True, slots=True)
class InternalizationGate:
    min_no_context_gain: float = 0.05
    min_heldout_gain: float = 0.03
    min_recursive_gain: float = 0.01

    def evaluate(
        self,
        *,
        baseline_no_context: float,
        baseline_heldout: float,
        result: InternalizationEvaluation,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if result.no_context_score - baseline_no_context < self.min_no_context_gain:
            reasons.append("NO_CONTEXT_GAIN_TOO_SMALL")
        if result.heldout_score - baseline_heldout < self.min_heldout_gain:
            reasons.append("HELDOUT_TRANSFER_TOO_SMALL")
        if result.next_cycle_gain < self.min_recursive_gain:
            reasons.append("NO_RECURSIVE_GAIN")
        if (
            result.assisted_score > result.no_context_score
            and result.no_context_score <= baseline_no_context
        ):
            reasons.append("HINT_DEPENDENCE")
        return (not reasons, tuple(reasons))


def sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))
