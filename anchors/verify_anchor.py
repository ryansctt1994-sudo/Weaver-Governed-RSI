#!/usr/bin/env python3
"""Perform provider-neutral structural checks on an anchor record."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def verify(record: dict[str, object], expected_digest: str) -> tuple[bool, str]:
    if not _SHA256.fullmatch(expected_digest):
        return False, "expected digest is malformed"
    if record.get("digest") != expected_digest:
        return False, "anchor digest mismatch"
    if not record.get("provider") or not record.get("anchored_at") or not record.get("proof"):
        return False, "anchor record is incomplete"
    return (
        True,
        "structure and digest match; provider proof still requires provider-specific verification",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    try:
        raw = json.loads(args.anchor.read_text(encoding="utf-8"))
        valid, reason = verify(raw, args.expected_digest)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INDETERMINATE: {type(exc).__name__}", file=sys.stderr)
        return 3
    print(reason)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
