from __future__ import annotations

import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests.release_builder._git_fixture import git, initialize_release_fixture, run_builder


class UntrackedExecutableTests(unittest.TestCase):
    def test_untracked_executable_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, output = base / "repo", base / "out"
            root.mkdir()
            initialize_release_fixture(root)
            executable = root / "untracked.sh"
            executable.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            os.chmod(executable, 0o755)
            result = run_builder(root, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("untracked files present", result.stderr)

    def test_ignored_private_material_is_absent_from_payload_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, output = base / "repo", base / "out"
            root.mkdir()
            initialize_release_fixture(root)
            private_material = root / "maintainer_private.pem"
            private_material.write_text("fixture secret material\n", encoding="utf-8")
            result = run_builder(root, output)
            self.assertEqual(0, result.returncode, result.stderr)
            manifest = (output / "PAYLOAD_MANIFEST.sha256").read_text(encoding="utf-8")
            self.assertNotIn("maintainer_private.pem", manifest)
            with tarfile.open(output / "source.tar.gz", "r:gz") as archive:
                self.assertNotIn("weaver-governed-rsi/maintainer_private.pem", archive.getnames())

    def test_tracked_private_key_material_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, output = base / "repo", base / "out"
            root.mkdir()
            initialize_release_fixture(root)
            disguised = root / "public-looking.pem"
            disguised.write_text(
                "-----BEGIN " + "PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            for command in (("add", "-f", disguised.name), ("commit", "-m", "unsafe fixture")):
                committed = git(*command, cwd=root)
                self.assertEqual(0, committed.returncode, committed.stderr)
            result = run_builder(root, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("private key material", result.stdout)


if __name__ == "__main__":
    unittest.main()
