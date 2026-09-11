from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from release.generate_manifest import generate_manifest
from tests.release_builder._git_fixture import initialize_release_fixture, run_builder


class ReproducibleBuildTests(unittest.TestCase):
    def test_manifest_is_independent_of_file_creation_order(self) -> None:
        with tempfile.TemporaryDirectory() as left_dir, tempfile.TemporaryDirectory() as right_dir:
            left, right = Path(left_dir), Path(right_dir)
            (left / "b.txt").write_text("b", encoding="utf-8")
            (left / "a.txt").write_text("a", encoding="utf-8")
            (right / "a.txt").write_text("a", encoding="utf-8")
            (right / "b.txt").write_text("b", encoding="utf-8")
            left_manifest = left.parent / f"{left.name}.manifest"
            right_manifest = right.parent / f"{right.name}.manifest"
            try:
                self.assertEqual(
                    generate_manifest(left, left_manifest),
                    generate_manifest(right, right_manifest),
                )
            finally:
                left_manifest.unlink(missing_ok=True)
                right_manifest.unlink(missing_ok=True)

    def test_release_builder_reproduces_unsigned_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repo"
            root.mkdir()
            initialize_release_fixture(root)
            first, second = base / "first", base / "second"
            first_result = run_builder(root, first)
            second_result = run_builder(root, second)
            self.assertEqual(0, first_result.returncode, first_result.stderr)
            self.assertEqual(0, second_result.returncode, second_result.stderr)
            for artifact in (
                "source.tar.gz",
                "replication-kit.tar.gz",
                "PAYLOAD_MANIFEST.sha256",
                "README_replication.md",
            ):
                with self.subTest(artifact=artifact):
                    self.assertEqual(
                        (first / artifact).read_bytes(), (second / artifact).read_bytes()
                    )


if __name__ == "__main__":
    unittest.main()
