#!/usr/bin/env python3
"""Audit the static Evidence Registry without changing it."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from validation.evidence_registry import (  # noqa: E402
    EvidenceTier,
    load_registry,
    validate_registry_document,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIER_ORDER = {tier.value: index for index, tier in enumerate(EvidenceTier)}


def audit(path: Path) -> tuple[int, dict[str, object]]:
    try:
        registry = load_registry(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return 3, {"status": "INDETERMINATE", "reason": type(exc).__name__}

    errors = validate_registry_document(registry)
    if errors:
        return 1, {"status": "FAIL", "reason_codes": list(errors)}

    accepted_claims = [
        claim
        for claim in registry["claims"]
        if isinstance(claim, dict) and claim.get("status") == "ACCEPTED"
    ]
    malformed_claims = [
        claim.get("claim_id", "UNKNOWN")
        for claim in accepted_claims
        if not isinstance(claim.get("receipt_sha256"), str)
        or _SHA256.fullmatch(claim["receipt_sha256"]) is None
        or not isinstance(claim.get("artifact_sha256"), str)
        or _SHA256.fullmatch(claim["artifact_sha256"]) is None
        or claim.get("target_tier") not in _TIER_ORDER
    ]
    if malformed_claims:
        return 1, {
            "status": "FAIL",
            "reason": "accepted claims lack required identity or tier fields",
            "claim_ids": malformed_claims,
        }

    declared_ceiling = str(registry["repository_evidence_ceiling"])
    supported_ceiling = "E0"
    if accepted_claims:
        supported_ceiling = max(
            (str(claim["target_tier"]) for claim in accepted_claims),
            key=_TIER_ORDER.__getitem__,
        )
    if declared_ceiling != supported_ceiling:
        return 1, {
            "status": "FAIL",
            "reason": "repository ceiling is not supported by accepted claims",
            "declared_ceiling": declared_ceiling,
            "supported_ceiling": supported_ceiling,
        }

    return 0, {
        "status": "PASS",
        "repository_evidence_ceiling": registry["repository_evidence_ceiling"],
        "accepted_claim_count": len(accepted_claims),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=Path("evidence/registry.json"))
    args = parser.parse_args()
    code, report = audit(args.registry)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
