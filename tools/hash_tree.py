#!/usr/bin/env python3
"""Print the deterministic manifest digest for a tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.generate_manifest import iter_payload_files, manifest_bytes  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    files = iter_payload_files(args.root)
    data = manifest_bytes(args.root, files)
    print(
        json.dumps({"file_count": len(files), "manifest_sha256": hashlib.sha256(data).hexdigest()})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
