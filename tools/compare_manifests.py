#!/usr/bin/env python3
"""Compare two SHA-256 manifests by path and digest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", maxsplit=1)
        if relative in entries:
            raise ValueError(f"duplicate path in {path}: {relative}")
        entries[relative] = digest
    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()
    left, right = load(args.left), load(args.right)
    report = {
        "added": sorted(right.keys() - left.keys()),
        "removed": sorted(left.keys() - right.keys()),
        "changed": sorted(path for path in left.keys() & right.keys() if left[path] != right[path]),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if any(report.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
