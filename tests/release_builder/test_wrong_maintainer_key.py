from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from release.verify_manifest_signature import verify


class WrongMaintainerKeyTests(unittest.TestCase):
    def test_wrong_public_key_does_not_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            producer = Ed25519PrivateKey.generate()
            attacker = Ed25519PrivateKey.generate()
            manifest = root / "manifest"
            signature = root / "signature"
            public_key = root / "public.pem"
            manifest.write_bytes(b"identified payload\n")
            signature.write_text(
                base64.b64encode(producer.sign(manifest.read_bytes())).decode() + "\n",
                encoding="ascii",
            )
            public_key.write_bytes(
                attacker.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            with self.assertRaises(InvalidSignature):
                verify(manifest, public_key, signature)


if __name__ == "__main__":
    unittest.main()
