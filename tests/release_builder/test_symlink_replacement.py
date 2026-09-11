from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from release.verify_release import verify_manifest


class SymlinkReplacementTests(unittest.TestCase):
    def test_manifested_symlink_is_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("target", encoding="utf-8")
            link = root / "payload.txt"
            link.symlink_to(target)
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{'0' * 64}  payload.txt\n", encoding="utf-8")
            result = verify_manifest(root, manifest)
            self.assertEqual("INDETERMINATE", result.status)
            self.assertEqual("unsafe file type", result.reason)


if __name__ == "__main__":
    unittest.main()
