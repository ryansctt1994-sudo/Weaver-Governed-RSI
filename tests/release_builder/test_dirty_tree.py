from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.release_builder._git_fixture import initialize_release_fixture, run_builder


class DirtyTreeTests(unittest.TestCase):
    def test_dirty_tracked_tree_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, output = base / "repo", base / "out"
            root.mkdir()
            initialize_release_fixture(root)
            (root / "payload.txt").write_text("mutated\n", encoding="utf-8")
            result = run_builder(root, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("dirty tracked tree", result.stderr)


if __name__ == "__main__":
    unittest.main()
