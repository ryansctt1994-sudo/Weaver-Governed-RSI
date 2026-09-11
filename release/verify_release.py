#!/usr/bin/env python3
"""Verify manifest paths, hashes, file types, and forbidden release material."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release.generate_manifest import ManifestError, iter_payload_files  # noqa: E402

_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
FORBIDDEN_NAMES = frozenset({".env", "id_ed25519", "id_rsa", "credentials.json"})
FORBIDDEN_SUFFIXES = frozenset({".key", ".p12", ".sqlite", ".sqlite3", ".db"})
_PEM_BEGIN = b"-----BEGIN "
PRIVATE_KEY_MARKERS = tuple(
    _PEM_BEGIN + key_type + b"-----"
    for key_type in (
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
        b"DSA PRIVATE KEY",
    )
)


@dataclass(frozen=True, slots=True)
class ReleaseVerification:
    valid: bool
    status: str
    reason: str | None = None
    path: str | None = None


def _safe_relative(raw: str) -> PurePosixPath | None:
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path


def verify_manifest(
    root: Path,
    manifest: Path,
    *,
    require_complete: bool = False,
    excluded_paths: tuple[Path, ...] = (),
) -> ReleaseVerification:
    root = root.resolve()
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return ReleaseVerification(False, "INDETERMINATE", type(exc).__name__)
    seen: set[str] = set()
    for line in lines:
        match = _LINE.fullmatch(line)
        if match is None:
            return ReleaseVerification(False, "INDETERMINATE", "malformed manifest line")
        expected, raw_path = match.groups()
        relative = _safe_relative(raw_path)
        if relative is None or raw_path in seen:
            return ReleaseVerification(False, "INDETERMINATE", "unsafe or duplicate path", raw_path)
        seen.add(raw_path)
        normalized_name = relative.name.lower()
        if (
            normalized_name in FORBIDDEN_NAMES
            or normalized_name.startswith(".env.")
            or relative.suffix.lower() in FORBIDDEN_SUFFIXES
            or ("private" in normalized_name and relative.suffix.lower() == ".pem")
        ):
            return ReleaseVerification(False, "FAIL", "forbidden release material", raw_path)
        candidate = root.joinpath(*relative.parts)
        try:
            mode = candidate.lstat().st_mode
        except OSError:
            return ReleaseVerification(False, "INDETERMINATE", "listed file missing", raw_path)
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return ReleaseVerification(False, "INDETERMINATE", "unsafe file type", raw_path)
        try:
            content = candidate.read_bytes()
        except OSError:
            return ReleaseVerification(False, "INDETERMINATE", "listed file unreadable", raw_path)
        if any(marker in content for marker in PRIVATE_KEY_MARKERS):
            return ReleaseVerification(False, "FAIL", "private key material", raw_path)
        observed = hashlib.sha256(content).hexdigest()
        if observed != expected:
            return ReleaseVerification(False, "INDETERMINATE", "artifact mutation", raw_path)
    if require_complete:
        excluded = (manifest.resolve(), *excluded_paths)
        try:
            payload_paths = {
                path.resolve().relative_to(root).as_posix()
                for path in iter_payload_files(root, excluded_paths=excluded)
            }
        except (OSError, ManifestError) as exc:
            return ReleaseVerification(False, "INDETERMINATE", str(exc))
        if payload_paths != seen:
            difference = sorted(payload_paths ^ seen)
            return ReleaseVerification(
                False,
                "INDETERMINATE",
                "manifest coverage mismatch",
                difference[0] if difference else None,
            )
    return ReleaseVerification(True, "PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="path to exclude from completeness checks; relative paths resolve beneath --root",
    )
    args = parser.parse_args()
    excluded = tuple(
        path if path.is_absolute() else args.root / path for path in map(Path, args.exclude)
    )
    result = verify_manifest(
        args.root,
        args.manifest,
        require_complete=args.require_complete,
        excluded_paths=excluded,
    )
    print(result)
    if result.valid:
        return 0
    return 1 if result.status == "FAIL" else 3


if __name__ == "__main__":
    sys.exit(main())
