#!/usr/bin/env python3
"""Inspect a JSON receipt and print its canonical digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kernel.ledger import canonical_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    raw = json.loads(args.receipt.read_text(encoding="utf-8"))
    canonical = canonical_json(raw)
    print(json.dumps({"sha256": hashlib.sha256(canonical).hexdigest(), "receipt": raw}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
