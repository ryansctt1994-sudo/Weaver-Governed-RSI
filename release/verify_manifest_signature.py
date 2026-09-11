#!/usr/bin/env python3
"""Verify a detached base64 Ed25519 signature for a manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kernel.verifier import load_public_key  # noqa: E402


def verify(manifest: Path, public_key: Path, signature: Path) -> bool:
    encoded = signature.read_text(encoding="ascii").strip()
    raw_signature = base64.b64decode(encoded, validate=True)
    load_public_key(public_key.read_bytes()).verify(raw_signature, manifest.read_bytes())
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.manifest, args.public_key, args.signature)
    except InvalidSignature:
        print("FAIL: invalid signature", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, binascii.Error) as exc:
        print(f"INDETERMINATE: {type(exc).__name__}", file=sys.stderr)
        return 3
    print("PASS: signature valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
