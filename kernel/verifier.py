"""Public-key-only Ed25519 verification helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel.ledger import canonical_json


@dataclass(frozen=True, slots=True)
class SignedEnvelope:
    key_id: str
    payload: Mapping[str, Any]
    signature_base64: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    key_fingerprint: str
    reason: str | None = None


def load_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    return key


def public_key_fingerprint(public_key_pem: bytes) -> str:
    key = load_public_key(public_key_pem)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def verify_envelope(envelope: SignedEnvelope, public_key_pem: bytes) -> VerificationResult:
    fingerprint = public_key_fingerprint(public_key_pem)
    try:
        signature = base64.b64decode(envelope.signature_base64, validate=True)
        load_public_key(public_key_pem).verify(signature, canonical_json(envelope.payload))
    except InvalidSignature as exc:
        return VerificationResult(False, fingerprint, type(exc).__name__)
    except (ValueError, binascii.Error) as exc:
        return VerificationResult(False, fingerprint, type(exc).__name__)
    return VerificationResult(True, fingerprint)
