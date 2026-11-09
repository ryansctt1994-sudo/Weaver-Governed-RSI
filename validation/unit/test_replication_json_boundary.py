"""Strict receipt parser negative controls; signer is test-only and ephemeral.

Successful signature verification establishes only receipt bytes signed by the
test key. It does not establish replicator independence or evidence promotion.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kernel.ledger import canonical_json
from kernel.verifier import public_key_fingerprint
from replication.verify_replication import verify

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def signed_receipt(tmp_path: Path) -> tuple[Path, Path, Path]:
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_path = tmp_path / "test-public-key.pem"
    key_path.write_bytes(public_pem)
    schema_path = ROOT / "schemas" / "replication_receipt.schema.json"
    receipt = json.loads(
        (ROOT / "replication" / "replication_receipt.example.json").read_text(encoding="utf-8")
    )
    receipt["replicator"]["public_key_fingerprint"] = public_key_fingerprint(public_pem)
    body = {name: value for name, value in receipt.items() if name != "signature"}
    receipt["signature"]["value_base64"] = base64.b64encode(
        private.sign(canonical_json(body))
    ).decode("ascii")
    receipt_path = tmp_path / "signed.json"
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return receipt_path, schema_path, key_path


def test_test_key_signature_and_frozen_receipt_schema_still_verify(
    signed_receipt: tuple[Path, Path, Path],
) -> None:
    assert verify(*signed_receipt) == (True, "valid receipt")


@pytest.mark.parametrize(
    ("original", "injected"),
    [
        ('"result": "INDETERMINATE"', '"result": "PASS", "result": "INDETERMINATE"'),
        ('"algorithm": "Ed25519"', '"algorithm": "RSA", "algorithm": "Ed25519"'),
        (
            '"relationship_disclosure": "REPLACE-WITH-COMPLETE-DISCLOSURE"',
            '"relationship_disclosure": "none", '
            '"relationship_disclosure": "REPLACE-WITH-COMPLETE-DISCLOSURE"',
        ),
    ],
)
def test_signed_receipt_with_shadowed_duplicate_field_is_rejected(
    signed_receipt: tuple[Path, Path, Path], original: str, injected: str
) -> None:
    receipt_path, schema_path, key_path = signed_receipt
    source = receipt_path.read_text(encoding="utf-8")
    assert original in source
    receipt_path.write_text(source.replace(original, injected, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        verify(receipt_path, schema_path, key_path)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_receipt_json_is_refused_before_signature_check(
    signed_receipt: tuple[Path, Path, Path], token: str
) -> None:
    receipt_path, schema_path, key_path = signed_receipt
    source = receipt_path.read_text(encoding="utf-8")
    original = '"result": "INDETERMINATE"'
    assert original in source
    injected = original + ', "untrusted": ' + token
    receipt_path.write_text(source.replace(original, injected, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="nonfinite JSON constant"):
        verify(receipt_path, schema_path, key_path)


def test_ambiguous_schema_file_is_rejected_before_validation(
    signed_receipt: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    receipt_path, schema_path, key_path = signed_receipt
    original = schema_path.read_text(encoding="utf-8")
    modified = original.replace(
        '"title": "Independent replication receipt"',
        '"title": "anything", "title": "Independent replication receipt"',
        1,
    )
    assert modified != original
    new_schema = tmp_path / "ambiguous-schema.json"
    new_schema.write_text(modified, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        verify(receipt_path, new_schema, key_path)
