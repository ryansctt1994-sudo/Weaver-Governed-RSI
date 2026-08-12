from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from release.generate_manifest import generate_manifest
from release.verify_release import verify_manifest


class PayloadMutationTests(unittest.TestCase):
    def test_payload_mutation_is_not_an_ordinary_test_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root.parent / f"{root.name}.manifest"
            try:
                payload = root / "payload.py"
                payload.write_text("safe = True\n", encoding="utf-8")
                generate_manifest(root, manifest)
                payload.write_text("safe = False\n", encoding="utf-8")
                result = verify_manifest(root, manifest)
                self.assertEqual("INDETERMINATE", result.status)
                self.assertEqual("artifact mutation", result.reason)
            finally:
                manifest.unlink(missing_ok=True)

    def test_unmanifested_file_is_indeterminate_when_completeness_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root.parent / f"{root.name}.manifest"
            try:
                (root / "payload.py").write_text("safe = True\n", encoding="utf-8")
                generate_manifest(root, manifest)
                (root / "injected.py").write_text("unexpected = True\n", encoding="utf-8")
                result = verify_manifest(root, manifest, require_complete=True)
                self.assertEqual("INDETERMINATE", result.status)
                self.assertEqual("manifest coverage mismatch", result.reason)
                self.assertEqual("injected.py", result.path)
            finally:
                manifest.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
