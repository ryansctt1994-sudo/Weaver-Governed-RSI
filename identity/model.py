from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol


class IdentityVerdict(str, Enum):
    EQUIVALENT = "EQUIVALENT"
    CHANGED = "CHANGED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ObjectIdentity:
    relative_path: str
    object_type: str
    content_sha256: Optional[str]
    symlink_target: Optional[str]
    mode: Optional[int]
    size_bytes: Optional[int]
    device_id: Optional[str]
    file_id: Optional[str]
    mount_identity: Optional[str]
    owner: Optional[str]
    group: Optional[str]
    platform_identity_kind: str
    identity_complete: bool
    uncertainty_reason: Optional[str]
    resolved_device_id: Optional[str] = None
    resolved_file_id: Optional[str] = None
    resolved_mount_identity: Optional[str] = None
    resolved_canonical_path: Optional[str] = None


class IdentityCapture(Protocol):
    def capture(self, path: Path, *, relative_to: Path) -> ObjectIdentity:
        ...


class IdentityPolicy(Protocol):
    protects_mode: bool

    def equivalent(
        self,
        before: ObjectIdentity,
        after: ObjectIdentity,
    ) -> IdentityVerdict:
        ...
