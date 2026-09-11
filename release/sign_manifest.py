#!/usr/bin/env python3
"""Sign an existing manifest with an externally supplied Ed25519 private key."""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sign(manifest: Path, private_key_path: Path, output: Path) -> None:
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    signature = key.sign(manifest.read_bytes())
    output.write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    os.chmod(output, 0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        sign(args.manifest, args.private_key, args.output)
    except (OSError, TypeError, ValueError) as exc:
        print(f"INDETERMINATE: {type(exc).__name__}", file=sys.stderr)
        return 3
    print(f"wrote signature to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
