from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def initialize_release_fixture(root: Path) -> None:
    (root / "release").mkdir()
    (root / "replication").mkdir()
    shutil.copy2(REPOSITORY_ROOT / "release/build_release.sh", root / "release/build_release.sh")
    shutil.copy2(
        REPOSITORY_ROOT / "release/generate_manifest.py",
        root / "release/generate_manifest.py",
    )
    shutil.copy2(
        REPOSITORY_ROOT / "release/verify_release.py",
        root / "release/verify_release.py",
    )
    shutil.copy2(
        REPOSITORY_ROOT / "replication/README_replication.md",
        root / "replication/README_replication.md",
    )
    shutil.copy2(REPOSITORY_ROOT / ".gitignore", root / ".gitignore")
    (root / "payload.txt").write_text("identified payload\n", encoding="utf-8")
    commands = (
        ("init", "-b", "main"),
        ("config", "user.name", "Release Test"),
        ("config", "user.email", "release-test@example.invalid"),
        ("add", "."),
        ("commit", "-m", "fixture"),
    )
    for command in commands:
        result = git(*command, cwd=root)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)


def run_builder(root: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("bash", str(root / "release/build_release.sh"), str(root), str(output)),
        check=False,
        capture_output=True,
        text=True,
    )
