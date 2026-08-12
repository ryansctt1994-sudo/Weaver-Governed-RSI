from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kernel.ledger import canonical_json
from kernel.verifier import SignedEnvelope, public_key_fingerprint, verify_envelope
from replication.verify_replication import verify as verify_replication


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class CryptoAdversarialTests(unittest.TestCase):
    def test_wrong_key_is_rejected(self) -> None:
        producer = Ed25519PrivateKey.generate()
        attacker = Ed25519PrivateKey.generate()
        payload = {"claim": "identified bytes", "digest": "0" * 64}
        signature = producer.sign(canonical_json(payload))
        envelope = SignedEnvelope("producer", payload, base64.b64encode(signature).decode())
        self.assertFalse(verify_envelope(envelope, public_pem(attacker)).valid)

    def test_payload_mutation_is_rejected(self) -> None:
        producer = Ed25519PrivateKey.generate()
        original = {"claim": "original"}
        signature = producer.sign(canonical_json(original))
        forged = SignedEnvelope(
            "producer", {"claim": "mutated"}, base64.b64encode(signature).decode()
        )
        self.assertFalse(verify_envelope(forged, public_pem(producer)).valid)

    def test_malformed_base64_is_rejected(self) -> None:
        key = Ed25519PrivateKey.generate()
        envelope = SignedEnvelope("producer", {"claim": "x"}, "not base64!!!")
        self.assertFalse(verify_envelope(envelope, public_pem(key)).valid)

    def test_replication_receipt_signature_is_bound_to_claimed_key_fingerprint(self) -> None:
        signer = Ed25519PrivateKey.generate()
        claimed = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = Path("schemas/replication_receipt.schema.json")
            public_key = root / "replicator-public.pem"
            public_key.write_bytes(public_pem(signer))
            unsigned: dict[str, Any] = {
                "schema_version": "1.0",
                "receipt_id": "R-KEY-SUBSTITUTION",
                "replicator": {
                    "identity": "replicator-a",
                    "organization": None,
                    "relationship_disclosure": "No relationship to the producer.",
                    "public_key_fingerprint": public_key_fingerprint(public_pem(claimed)),
                },
                "artifact": {
                    "source_sha256": "a" * 64,
                    "payload_manifest_sha256": "b" * 64,
                    "bundle_manifest_sha256": "c" * 64,
                },
                "environment": {
                    "os": "test-os",
                    "architecture": "test-arch",
                    "python": "3.12",
                    "fingerprint": "d" * 64,
                },
                "result": "PASS",
                "commands": [{"argv": ["pytest"], "exit_code": 0}],
                "deviations": [],
            }
            receipt = dict(unsigned)
            receipt["signature"] = {
                "algorithm": "Ed25519",
                "value_base64": base64.b64encode(signer.sign(canonical_json(unsigned))).decode(),
            }
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            valid, reason = verify_replication(receipt_path, schema, public_key)
            self.assertFalse(valid)
            self.assertEqual("replicator public key fingerprint mismatch", reason)

            unsigned["replicator"]["public_key_fingerprint"] = public_key_fingerprint(
                public_pem(signer)
            )
            receipt = dict(unsigned)
            receipt["signature"] = {
                "algorithm": "Ed25519",
                "value_base64": base64.b64encode(signer.sign(canonical_json(unsigned))).decode(),
            }
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            valid, reason = verify_replication(receipt_path, schema, public_key)
            self.assertTrue(valid)
            self.assertEqual("valid receipt", reason)


if __name__ == "__main__":
    unittest.main()
