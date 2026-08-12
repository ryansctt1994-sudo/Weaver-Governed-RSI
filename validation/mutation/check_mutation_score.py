#!/usr/bin/env python3
"""Apply a transparent score and status gate to Mutmut metadata."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

_TIMEOUT_CODES = {-24, 24, 36, 152, 255}
_SEGFAULT_CODES = {-11, -9}


def classify(exit_code: int | None) -> str:
    if exit_code is None:
        return "not_checked"
    if exit_code == 0:
        return "survived"
    if exit_code in {1, 3}:
        return "killed"
    if exit_code in {5, 33}:
        return "no_tests"
    if exit_code == 2:
        return "interrupted"
    if exit_code == 34:
        return "skipped"
    if exit_code == 37:
        return "caught_by_type_check"
    if exit_code in _TIMEOUT_CODES:
        return "timeout"
    if exit_code in _SEGFAULT_CODES:
        return "segfault"
    return "suspicious"


@dataclass(frozen=True, slots=True)
class MutationReport:
    minimum_score: float
    score: float
    counts: dict[str, int]
    passed: bool
    reasons: tuple[str, ...]


def assess(mutants_root: Path, minimum_score: float) -> MutationReport:
    counts: Counter[str] = Counter()
    metadata_files = tuple(mutants_root.rglob("*.meta"))
    for path in metadata_files:
        raw = json.loads(path.read_text(encoding="utf-8"))
        for exit_code in raw.get("exit_code_by_key", {}).values():
            counts[classify(exit_code)] += 1

    killed = counts["killed"] + counts["caught_by_type_check"]
    evaluated = killed + counts["survived"]
    score = 100.0 * killed / evaluated if evaluated else 0.0
    reasons: list[str] = []
    if not metadata_files or not evaluated:
        reasons.append("no evaluated mutants")
    if score < minimum_score:
        reasons.append(f"mutation score {score:.2f} is below {minimum_score:.2f}")
    for status in (
        "not_checked",
        "no_tests",
        "timeout",
        "suspicious",
        "interrupted",
        "segfault",
    ):
        if counts[status]:
            reasons.append(f"{counts[status]} mutant(s) have blocking status {status}")
    return MutationReport(
        minimum_score=minimum_score,
        score=round(score, 2),
        counts=dict(sorted(counts.items())),
        passed=not reasons,
        reasons=tuple(reasons),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutants-root", type=Path, default=Path("mutants"))
    parser.add_argument("--minimum-score", type=float, default=75.0)
    args = parser.parse_args()
    report = assess(args.mutants_root, args.minimum_score)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
