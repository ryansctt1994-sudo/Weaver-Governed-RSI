from __future__ import annotations

from pathlib import Path

from .model import ObjectIdentity


class WindowsIdentityCapture:
    """Stable Windows adapter surface; fail closed until Win32 handle capture is implemented."""

    platform_identity_kind = "windows_file_id"

    def capture(self, path: Path, *, relative_to: Path) -> ObjectIdentity:
        try:
            rel = str(path.absolute().relative_to(relative_to.absolute()))
        except ValueError:
            rel = str(path)
        reason = "windows_handle_adapter_not_implemented"
        if not path.exists() and not path.is_symlink():
            reason = "object_missing"
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
            uncertainty_reason=reason,
        )
