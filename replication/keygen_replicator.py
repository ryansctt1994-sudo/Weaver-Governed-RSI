#!/usr/bin/env python3
"""Generate a local Ed25519 identity for a replicator."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing key")
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(public_path, 0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        generate(args.private_key, args.public_key)
    except OSError as exc:
        print(f"key generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"private key: {args.private_key} (keep secret; never submit)")
    print(f"public key: {args.public_key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
