from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from release.generate_manifest import ManifestError, generate_manifest
from release.verify_release import verify_manifest


class FilesystemToctouTests(unittest.TestCase):
    def test_manifest_generation_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real.txt").write_text("safe", encoding="utf-8")
            (root / "link.txt").symlink_to(root / "real.txt")
            with self.assertRaises(ManifestError):
                generate_manifest(root, root / "MANIFEST.sha256")

    def test_replacement_after_manifest_is_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload.txt"
            manifest = root / "outside" / "PAYLOAD_MANIFEST.sha256"
            payload.write_text("safe", encoding="utf-8")
            generate_manifest(root, manifest)
            payload.unlink()
            payload.symlink_to(root / "other.txt")
            (root / "other.txt").write_text("attacker", encoding="utf-8")
            result = verify_manifest(root, manifest)
            self.assertFalse(result.valid)
            self.assertEqual("INDETERMINATE", result.status)


if __name__ == "__main__":
    unittest.main()
