from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PayloadEntry:
    relative_path: str
    object_type: str
    content_sha256: str | None
    symlink_target: str | None
    mode: int | None
    size_bytes: int | None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tracked_files(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return sorted(p.decode("utf-8") for p in proc.stdout.split(b"\x00") if p)


def _entry(root: Path, rel: str) -> PayloadEntry:
    path = root / rel
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return PayloadEntry(rel, "missing", None, None, None, None)

    if stat.S_ISLNK(st.st_mode):
        return PayloadEntry(rel, "symlink", None, os.readlink(path), st.st_mode, st.st_size)
    if stat.S_ISDIR(st.st_mode):
        return PayloadEntry(rel, "directory", None, None, st.st_mode, st.st_size)
    if stat.S_ISREG(st.st_mode):
        return PayloadEntry(
            rel,
            "regular",
            _sha256_bytes(path.read_bytes()),
            None,
            st.st_mode,
            st.st_size,
        )
    return PayloadEntry(rel, "other", None, None, st.st_mode, st.st_size)


def capture_payload_snapshot(root: Path) -> dict[str, PayloadEntry]:
    """Canonical tracked-payload snapshot used by mutation integrity checks."""
    return {rel: _entry(root, rel) for rel in _tracked_files(root)}


def payload_manifest_sha256(snapshot: dict[str, PayloadEntry]) -> str:
    payload = [
        {
            "relative_path": entry.relative_path,
            "object_type": entry.object_type,
            "content_sha256": entry.content_sha256,
            "symlink_target": entry.symlink_target,
            "mode": entry.mode,
            "size_bytes": entry.size_bytes,
        }
        for _, entry in sorted(snapshot.items())
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compare_snapshots(
    before: dict[str, PayloadEntry],
    after: dict[str, PayloadEntry],
    *,
    allowed_mutations: Iterable[str] = (),
) -> list[str]:
    allowed = set(allowed_mutations)
    changed: list[str] = []
    for path in sorted(set(before) | set(after)):
        if path in allowed:
            continue
        if before.get(path) != after.get(path):
            changed.append(path)
    return changed


def git_changed_paths(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(line.strip() for line in proc.stdout.splitlines() if line.strip())
