#!/usr/bin/env python3
"""Verify a replication receipt's schema and detached public-key signature."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kernel.ledger import canonical_json  # noqa: E402
from kernel.verifier import load_public_key, public_key_fingerprint  # noqa: E402


def verify(receipt_path: Path, schema_path: Path, public_key_path: Path) -> tuple[bool, str]:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(receipt), key=lambda item: list(item.path)
    )
    if errors:
        return False, f"schema error: {errors[0].message}"
    public_key_pem = public_key_path.read_bytes()
    claimed_fingerprint = receipt["replicator"]["public_key_fingerprint"]
    if claimed_fingerprint != public_key_fingerprint(public_key_pem):
        return False, "replicator public key fingerprint mismatch"
    unsigned = dict(receipt)
    signature_object = unsigned.pop("signature")
    signature = base64.b64decode(signature_object["value_base64"], validate=True)
    load_public_key(public_key_pem).verify(signature, canonical_json(unsigned))
    return True, "valid receipt"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument(
        "--schema", type=Path, default=Path("schemas/replication_receipt.schema.json")
    )
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        valid, reason = verify(args.receipt, args.schema, args.public_key)
    except InvalidSignature:
        print("FAIL: invalid receipt signature", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"INDETERMINATE: {type(exc).__name__}", file=sys.stderr)
        return 3
    print(("PASS: " if valid else "FAIL: ") + reason)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
