#!/usr/bin/env python3
"""Create a compact digest of a deterministic payload manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.generate_manifest import iter_payload_files, manifest_bytes  # noqa: E402


def snapshot(root: Path) -> dict[str, object]:
    files = iter_payload_files(root)
    manifest = manifest_bytes(root, files)
    return {
        "algorithm": "sha256",
        "file_count": len(files),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        print(json.dumps(snapshot(args.root), sort_keys=True))
    except OSError as exc:
        print(json.dumps({"status": "INDETERMINATE", "reason": type(exc).__name__}))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
