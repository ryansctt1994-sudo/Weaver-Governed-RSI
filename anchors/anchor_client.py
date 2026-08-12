#!/usr/bin/env python3
"""Create a provider-neutral anchor request document without network side effects."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def create_request(digest: str, provider: str) -> dict[str, str]:
    if not _SHA256.fullmatch(digest):
        raise ValueError("digest must be lowercase SHA-256 hexadecimal")
    if not provider.strip():
        raise ValueError("provider is required")
    return {"schema_version": "1.0", "algorithm": "sha256", "digest": digest, "provider": provider}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        request = create_request(args.digest, args.provider)
        args.output.write_text(
            json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError) as exc:
        print(f"cannot create anchor request: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
