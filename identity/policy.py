from __future__ import annotations

from .model import IdentityPolicy, IdentityVerdict, ObjectIdentity


class LinuxIdentityPolicy:
    """I7 policy: identity continuity is stronger than content equality."""

    protects_mode = True

    def equivalent(
        self,
        before: ObjectIdentity,
        after: ObjectIdentity,
    ) -> IdentityVerdict:
        if not before.identity_complete or not after.identity_complete:
            return IdentityVerdict.INDETERMINATE
        if before.platform_identity_kind != after.platform_identity_kind:
            return IdentityVerdict.INDETERMINATE
        if before.object_type != after.object_type:
            return IdentityVerdict.CHANGED

        for a, b in (
            (before.device_id, after.device_id),
            (before.file_id, after.file_id),
            (before.mount_identity, after.mount_identity),
        ):
            if a is None or b is None:
                return IdentityVerdict.INDETERMINATE
            if a != b:
                return IdentityVerdict.CHANGED

        if before.symlink_target != after.symlink_target:
            return IdentityVerdict.CHANGED

        resolved_before = (
            before.resolved_device_id,
            before.resolved_file_id,
            before.resolved_mount_identity,
        )
        resolved_after = (
            after.resolved_device_id,
            after.resolved_file_id,
            after.resolved_mount_identity,
        )
        if any(v is not None for v in resolved_before + resolved_after):
            if any(v is None for v in resolved_before + resolved_after):
                return IdentityVerdict.INDETERMINATE
            if resolved_before != resolved_after:
                return IdentityVerdict.CHANGED

        if self.protects_mode and before.mode != after.mode:
            return IdentityVerdict.CHANGED

        return IdentityVerdict.EQUIVALENT


class WindowsIdentityPolicy:
    """Conservative Windows policy over volume/file-ID/reparse semantics."""

    protects_mode = True

    def equivalent(
        self,
        before: ObjectIdentity,
        after: ObjectIdentity,
    ) -> IdentityVerdict:
        if not before.identity_complete or not after.identity_complete:
            return IdentityVerdict.INDETERMINATE
        if before.platform_identity_kind != after.platform_identity_kind:
            return IdentityVerdict.INDETERMINATE
        if before.object_type != after.object_type:
            return IdentityVerdict.CHANGED

        for a, b in (
            (before.device_id, after.device_id),
            (before.file_id, after.file_id),
            (before.mount_identity, after.mount_identity),
        ):
            if a is None or b is None:
                return IdentityVerdict.INDETERMINATE
            if a != b:
                return IdentityVerdict.CHANGED

        if before.symlink_target != after.symlink_target:
            return IdentityVerdict.CHANGED
        if self.protects_mode and before.mode != after.mode:
            return IdentityVerdict.CHANGED
        return IdentityVerdict.EQUIVALENT


def get_identity_policy(kind: str) -> IdentityPolicy:
    if kind == "linux_inode":
        return LinuxIdentityPolicy()
    if kind == "windows_file_id":
        return WindowsIdentityPolicy()
    raise ValueError(f"unknown identity policy kind: {kind}")
