"""Verification helpers for WGRSI-RC2 signed evaluation receipts."""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_receipt(receipt: dict[str, object]) -> bool:
    try:
        if receipt.get("schema") != "wgrsi-rc2-evaluation-receipt-1":
            return False
        body = receipt["body"]
        public_key_b64 = receipt["public_key_b64"]
        signature_b64 = receipt["signature_b64"]
        if not isinstance(body, dict):
            return False
        if not isinstance(public_key_b64, str) or not isinstance(signature_b64, str):
            return False

        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, canonical_json(body))
        return True
    except (KeyError, ValueError, InvalidSignature):
        return False
