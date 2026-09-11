"""Evidence promotion evaluator, separate from evidence production."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceTier(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"


_TIER_ORDER = {tier: index for index, tier in enumerate(EvidenceTier)}


class ClaimResult(StrEnum):
    # Result label, not a credential.
    PASS = "PASS"  # nosec B105
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


class DecisionStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class EvidenceClaim:
    claim_id: str
    artifact_sha256: str
    producer_id: str
    evaluator_id: str
    target_tier: EvidenceTier
    result: ClaimResult
    receipt_sha256: str | None
    environment_fingerprint: str | None
    independent: bool = False
    heterogeneous: bool = False


@dataclass(frozen=True, slots=True)
class RegistryDecision:
    status: DecisionStatus
    target_tier: EvidenceTier
    reason_codes: tuple[str, ...]

    @property
    def authorizes_promotion(self) -> bool:
        return self.status is DecisionStatus.ACCEPTED


def evaluate_claim(
    claim: EvidenceClaim,
    *,
    current_tier: EvidenceTier,
    unresolved_blocking_findings: tuple[str, ...] = (),
) -> RegistryDecision:
    """Evaluate prerequisites without modifying any registry artifact."""

    rejection: list[str] = []
    indeterminate: list[str] = []

    if claim.result is ClaimResult.FAIL:
        rejection.append("ER-KNOWN-FAILURE")
    elif claim.result is ClaimResult.INDETERMINATE:
        indeterminate.append("ER-CLAIM-INDETERMINATE")

    if not _SHA256.fullmatch(claim.artifact_sha256):
        indeterminate.append("ER-ARTIFACT-IDENTITY-MISSING")
    if claim.receipt_sha256 is None or not _SHA256.fullmatch(claim.receipt_sha256):
        indeterminate.append("ER-RECEIPT-IDENTITY-MISSING")
    if not claim.environment_fingerprint:
        indeterminate.append("ER-ENVIRONMENT-MISSING")
    if _TIER_ORDER[claim.target_tier] <= _TIER_ORDER[current_tier]:
        rejection.append("ER-NON-PROMOTION")
    if (
        _TIER_ORDER[claim.target_tier] > _TIER_ORDER[EvidenceTier.E1]
        and claim.producer_id == claim.evaluator_id
    ):
        rejection.append("ER-SELF-EVALUATION")
    if claim.target_tier in {EvidenceTier.E4, EvidenceTier.E5} and not claim.independent:
        indeterminate.append("ER-INDEPENDENCE-NOT-ESTABLISHED")
    if claim.target_tier is EvidenceTier.E4 and not claim.heterogeneous:
        indeterminate.append("ER-HETEROGENEITY-NOT-ESTABLISHED")
    if unresolved_blocking_findings:
        rejection.append("ER-BLOCKING-FINDINGS")

    if rejection:
        return RegistryDecision(
            DecisionStatus.REJECTED,
            claim.target_tier,
            tuple(dict.fromkeys(rejection + indeterminate)),
        )
    if indeterminate:
        return RegistryDecision(
            DecisionStatus.INDETERMINATE,
            claim.target_tier,
            tuple(dict.fromkeys(indeterminate)),
        )
    return RegistryDecision(DecisionStatus.ACCEPTED, claim.target_tier, ())


def load_registry(path: Path) -> Mapping[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("registry root must be an object")
    return raw


def validate_registry_document(registry: Mapping[str, Any]) -> tuple[str, ...]:
    """Return structural error codes; do not infer or repair missing evidence."""

    errors: list[str] = []
    if registry.get("schema_version") != "1.0":
        errors.append("ER-DOC-SCHEMA")
    try:
        EvidenceTier(str(registry["repository_evidence_ceiling"]))
    except (KeyError, ValueError):
        errors.append("ER-DOC-TIER")
    claims = registry.get("claims")
    if not isinstance(claims, list):
        errors.append("ER-DOC-CLAIMS")
    findings = registry.get("known_findings")
    if not isinstance(findings, list):
        errors.append("ER-DOC-FINDINGS")
    return tuple(errors)
