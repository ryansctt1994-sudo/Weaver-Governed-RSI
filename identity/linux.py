from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Optional

from .model import ObjectIdentity


def _hash_fd(fd: int) -> str:
    """Hash bytes through the retained descriptor without pathname re-resolution."""
    h = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        h.update(chunk)
        offset += len(chunk)
    return h.hexdigest()


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _mount_identity_from_stat(st: os.stat_result) -> str:
    return f"dev:{st.st_dev}"


def _relative(path: Path, relative_to: Path) -> str:
    try:
        return str(path.absolute().relative_to(relative_to.absolute()))
    except ValueError:
        return str(path)


class LinuxIdentityCapture:
    platform_identity_kind = "linux_inode"

    def capture(self, path: Path, *, relative_to: Path) -> ObjectIdentity:
        """Path-view capture for revalidation; lstat never follows symlinks."""
        rel = _relative(path, relative_to)
        try:
            lst = os.lstat(path)
        except OSError as exc:
            return ObjectIdentity(
                relative_path=rel,
                object_type="other",
                content_sha256=None,
                symlink_target=None,
                mode=None,
                size_bytes=None,
                device_id=None,
                file_id=None,
                mount_identity=None,
                owner=None,
                group=None,
                platform_identity_kind=self.platform_identity_kind,
                identity_complete=False,
                uncertainty_reason=f"capture_failed:{type(exc).__name__}",
            )

        object_type = _kind(lst.st_mode)
        symlink_target: Optional[str] = None
        content_sha: Optional[str] = None

        if object_type == "symlink":
            try:
                symlink_target = os.readlink(path)
            except OSError:
                return ObjectIdentity(
                    relative_path=rel,
                    object_type=object_type,
                    content_sha256=None,
                    symlink_target=None,
                    mode=lst.st_mode,
                    size_bytes=lst.st_size,
                    device_id=str(lst.st_dev),
                    file_id=str(lst.st_ino),
                    mount_identity=_mount_identity_from_stat(lst),
                    owner=str(lst.st_uid),
                    group=str(lst.st_gid),
                    platform_identity_kind=self.platform_identity_kind,
                    identity_complete=False,
                    uncertainty_reason="symlink_text_unavailable",
                )
        elif object_type == "regular":
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(path, flags)
                try:
                    fst = os.fstat(fd)
                    if (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino):
                        return ObjectIdentity(
                            relative_path=rel,
                            object_type=object_type,
                            content_sha256=None,
                            symlink_target=None,
                            mode=lst.st_mode,
                            size_bytes=lst.st_size,
                            device_id=str(lst.st_dev),
                            file_id=str(lst.st_ino),
                            mount_identity=_mount_identity_from_stat(lst),
                            owner=str(lst.st_uid),
                            group=str(lst.st_gid),
                            platform_identity_kind=self.platform_identity_kind,
                            identity_complete=False,
                            uncertainty_reason="identity_changed_during_capture",
                        )
                    content_sha = _hash_fd(fd)
                finally:
                    os.close(fd)
            except OSError as exc:
                return ObjectIdentity(
                    relative_path=rel,
                    object_type=object_type,
                    content_sha256=None,
                    symlink_target=None,
                    mode=lst.st_mode,
                    size_bytes=lst.st_size,
                    device_id=str(lst.st_dev),
                    file_id=str(lst.st_ino),
                    mount_identity=_mount_identity_from_stat(lst),
                    owner=str(lst.st_uid),
                    group=str(lst.st_gid),
                    platform_identity_kind=self.platform_identity_kind,
                    identity_complete=False,
                    uncertainty_reason=f"open_failed:{type(exc).__name__}",
                )

        resolved_device_id = None
        resolved_file_id = None
        resolved_mount = None
        resolved_canon = None
        try:
            if object_type == "symlink":
                resolved = os.stat(path)
                resolved_device_id = str(resolved.st_dev)
                resolved_file_id = str(resolved.st_ino)
                resolved_mount = _mount_identity_from_stat(resolved)
                resolved_canon = str(path.resolve(strict=True))
        except OSError:
            return ObjectIdentity(
                relative_path=rel,
                object_type=object_type,
                content_sha256=None,
                symlink_target=symlink_target,
                mode=lst.st_mode,
                size_bytes=lst.st_size,
                device_id=str(lst.st_dev),
                file_id=str(lst.st_ino),
                mount_identity=_mount_identity_from_stat(lst),
                owner=str(lst.st_uid),
                group=str(lst.st_gid),
                platform_identity_kind=self.platform_identity_kind,
                identity_complete=False,
                uncertainty_reason="resolved_target_unavailable",
            )

        return ObjectIdentity(
            relative_path=rel,
            object_type=object_type,
            content_sha256=content_sha,
            symlink_target=symlink_target,
            mode=lst.st_mode,
            size_bytes=lst.st_size,
            device_id=str(lst.st_dev),
            file_id=str(lst.st_ino),
            mount_identity=_mount_identity_from_stat(lst),
            owner=str(lst.st_uid),
            group=str(lst.st_gid),
            platform_identity_kind=self.platform_identity_kind,
            identity_complete=True,
            uncertainty_reason=None,
            resolved_device_id=resolved_device_id,
            resolved_file_id=resolved_file_id,
            resolved_mount_identity=resolved_mount,
            resolved_canonical_path=resolved_canon,
        )

    def capture_from_fd(
        self,
        fd: int,
        *,
        relative_path: str,
    ) -> ObjectIdentity:
        """Authorization-view capture from a retained open descriptor."""
        try:
            st = os.fstat(fd)
        except OSError as exc:
            return ObjectIdentity(
                relative_path=relative_path,
                object_type="other",
                content_sha256=None,
                symlink_target=None,
                mode=None,
                size_bytes=None,
                device_id=None,
                file_id=None,
                mount_identity=None,
                owner=None,
                group=None,
                platform_identity_kind=self.platform_identity_kind,
                identity_complete=False,
                uncertainty_reason=f"fstat_failed:{type(exc).__name__}",
            )

        object_type = _kind(st.st_mode)
        content_sha = _hash_fd(fd) if object_type == "regular" else None
        return ObjectIdentity(
            relative_path=relative_path,
            object_type=object_type,
            content_sha256=content_sha,
            symlink_target=None,
            mode=st.st_mode,
            size_bytes=st.st_size,
            device_id=str(st.st_dev),
            file_id=str(st.st_ino),
            mount_identity=_mount_identity_from_stat(st),
            owner=str(st.st_uid),
            group=str(st.st_gid),
            platform_identity_kind=self.platform_identity_kind,
            identity_complete=True,
            uncertainty_reason=None,
        )
