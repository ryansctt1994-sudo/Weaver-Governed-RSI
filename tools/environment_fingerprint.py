#!/usr/bin/env python3
"""Create a non-secret runtime fingerprint for replication receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from importlib import metadata
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kernel.ledger import canonical_json  # noqa: E402


def environment() -> dict[str, object]:
    distributions = sorted(
        (distribution.metadata["Name"], distribution.version)
        for distribution in metadata.distributions()
        if distribution.metadata["Name"]
    )
    payload: dict[str, object] = {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "dependencies": distributions,
    }
    payload["fingerprint"] = hashlib.sha256(canonical_json(payload)).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.dumps(environment(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        sys.stdout.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
