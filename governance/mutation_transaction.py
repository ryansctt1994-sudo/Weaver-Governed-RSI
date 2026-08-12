from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

from identity.linux import LinuxIdentityCapture
from identity.model import IdentityVerdict, ObjectIdentity
from identity.policy import LinuxIdentityPolicy


DENIAL_STATES = {
    IdentityVerdict.CHANGED: "REJECTED_OBJECT_IDENTITY_CHANGED",
    IdentityVerdict.INDETERMINATE: "INDETERMINATE_OBJECT_IDENTITY",
}


class MutationTransaction:
    """Reference transaction for I7/I7a adversarial validation."""

    def __init__(
        self,
        target: Path,
        *,
        protected_names: Optional[Iterable[str]] = None,
        mutation_bytes: bytes = b"MUTATED",
    ) -> None:
        if os.name == "nt":
            raise RuntimeError("reference MutationTransaction currently targets POSIX/Linux")
        self._target = target
        self._root = target.parent
        self._capture = LinuxIdentityCapture()
        self._policy = LinuxIdentityPolicy()
        self._protected_names = set(
            protected_names
            or {
                "constitution.py",
                "trust_root.py",
                "verifier.py",
                "authority_registry.py",
                "recursion_firewall.py",
            }
        )
        self._mutation_bytes = mutation_bytes
        self._fd: Optional[int] = None
        self._authorized_identity: Optional[ObjectIdentity] = None
        self._terminal_state = "PROPOSED"
        self._authority_delta = 0
        self._staged = False

    @property
    def authority_delta(self) -> int:
        return self._authority_delta

    @property
    def terminal_state(self) -> str:
        return self._terminal_state

    def _protected_object_ids(self) -> set[tuple[int, int]]:
        ids: set[tuple[int, int]] = set()
        for name in self._protected_names:
            candidate = self._root / name
            try:
                st = os.stat(candidate, follow_symlinks=False)
            except OSError:
                continue
            ids.add((st.st_dev, st.st_ino))
        return ids

    def _path_object_id(self, path: Path) -> tuple[int, int] | None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    def _reject_protected_alias(self, path: Path) -> bool:
        if path.name in self._protected_names:
            return True
        object_id = self._path_object_id(path)
        return object_id is not None and object_id in self._protected_object_ids()

    def authorize(self, target: Path) -> ObjectIdentity:
        if target != self._target:
            self._terminal_state = "REJECTED_TARGET_MISMATCH"
            raise ValueError("transaction target mismatch")
        if self._reject_protected_alias(target):
            self._terminal_state = "REJECTED_PROTECTED_OBJECT_ALIAS"
            raise PermissionError("protected object or alias")

        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags)
        except OSError as exc:
            self._terminal_state = "INDETERMINATE_OBJECT_IDENTITY"
            raise RuntimeError("unable to bind target descriptor") from exc

        try:
            identity = self._capture.capture_from_fd(fd, relative_path=str(target.name))
            if not identity.identity_complete:
                self._terminal_state = "INDETERMINATE_OBJECT_IDENTITY"
                raise RuntimeError(identity.uncertainty_reason or "identity incomplete")
            current = self._capture.capture(target, relative_to=self._root)
            verdict = self._policy.equivalent(identity, current)
            if verdict is not IdentityVerdict.EQUIVALENT:
                self._terminal_state = DENIAL_STATES[verdict]
                raise RuntimeError(self._terminal_state)
            self._fd = fd
            self._authorized_identity = identity
            self._terminal_state = "AUTHORIZED"
            fd = -1
            return identity
        finally:
            if fd >= 0:
                os.close(fd)

    def stage(self) -> None:
        if self._fd is None or self._authorized_identity is None:
            if self._terminal_state.startswith("REJECTED") or self._terminal_state.startswith("INDETERMINATE"):
                return
            raise RuntimeError("transaction is not authorized")
        self._staged = True
        self._terminal_state = "STAGED"

    def _validate_current_identity(self) -> IdentityVerdict:
        if self._authorized_identity is None:
            return IdentityVerdict.INDETERMINATE
        if self._reject_protected_alias(self._target):
            return IdentityVerdict.CHANGED
        current = self._capture.capture(self._target, relative_to=self._root)
        return self._policy.equivalent(self._authorized_identity, current)

    def commit(self) -> str:
        if self._fd is None or self._authorized_identity is None:
            return self._terminal_state
        if not self._staged:
            self.stage()

        verdict = self._validate_current_identity()
        if verdict is not IdentityVerdict.EQUIVALENT:
            self._terminal_state = DENIAL_STATES[verdict]
            self._authority_delta = 0
            self.close()
            return self._terminal_state

        try:
            os.ftruncate(self._fd, 0)
            os.pwrite(self._fd, self._mutation_bytes, 0)
            os.fsync(self._fd)
        except OSError:
            self._terminal_state = "INDETERMINATE_OBJECT_IDENTITY"
            self._authority_delta = 0
            self.close()
            return self._terminal_state

        self._terminal_state = "EXECUTED"
        self._authority_delta = 0
        self.close()
        return self._terminal_state

    def authorize_and_attempt(self) -> str:
        try:
            self.authorize(self._target)
        except (PermissionError, RuntimeError, ValueError):
            return self._terminal_state
        self.stage()
        return self.commit()

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __del__(self) -> None:
        self.close()
