"""Explicit authority registry with self-amendment and revocation guards."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock


class Permission(StrEnum):
    """Finite permissions understood by the governance kernel."""

    PROPOSE = "propose"
    VALIDATE = "validate"
    RATIFY = "ratify"
    APPLY = "apply"
    REVOKE = "revoke"
    GOVERN_AUTHORITY = "govern_authority"
    EVALUATE_EVIDENCE = "evaluate_evidence"


@dataclass(frozen=True, slots=True)
class Principal:
    """An identity and its explicitly assigned permissions."""

    principal_id: str
    permissions: frozenset[Permission]

    @classmethod
    def build(cls, principal_id: str, permissions: Iterable[Permission]) -> Principal:
        if not principal_id.strip():
            raise ValueError("principal_id must be non-empty")
        return cls(principal_id=principal_id, permissions=frozenset(permissions))


class AuthorityDenied(PermissionError):
    """Raised when an actor lacks authority or attempts self-authorization."""


class AuthorityRegistry:
    """Thread-safe, deny-by-default registry.

    Permission changes require an actor with ``GOVERN_AUTHORITY`` and cannot target that
    actor. This is a minimal software guard, not proof of organizational independence.
    """

    def __init__(self, principals: Iterable[Principal] = ()) -> None:
        self._lock = RLock()
        self._principals = {principal.principal_id: principal for principal in principals}
        self._revoked: set[str] = set()

    def principal(self, principal_id: str) -> Principal:
        with self._lock:
            principal = self._principals.get(principal_id)
            if principal is None:
                raise AuthorityDenied(f"unknown principal: {principal_id}")
            return principal

    def has(self, principal_id: str, permission: Permission) -> bool:
        with self._lock:
            if principal_id in self._revoked:
                return False
            principal = self._principals.get(principal_id)
            return principal is not None and permission in principal.permissions

    def require(self, principal_id: str, permission: Permission) -> None:
        if not self.has(principal_id, permission):
            raise AuthorityDenied(f"{principal_id!r} lacks {permission.value!r}")

    def assert_distinct(self, *principal_ids: str) -> None:
        if len(principal_ids) != len(set(principal_ids)):
            raise AuthorityDenied("separation of duty requires distinct principals")

    def replace_permissions(
        self,
        requester_id: str,
        target_id: str,
        permissions: Iterable[Permission],
    ) -> Principal:
        """Replace another principal's permissions after explicit authority checking."""

        self.require(requester_id, Permission.GOVERN_AUTHORITY)
        if requester_id == target_id:
            raise AuthorityDenied("a principal cannot modify its own authority")
        with self._lock:
            updated = Principal.build(target_id, permissions)
            self._principals[target_id] = updated
            return updated

    def revoke(self, requester_id: str, target_id: str) -> None:
        self.require(requester_id, Permission.REVOKE)
        if requester_id == target_id:
            raise AuthorityDenied("a principal cannot be its own revocation authority")
        with self._lock:
            if target_id not in self._principals:
                raise AuthorityDenied(f"unknown principal: {target_id}")
            self._revoked.add(target_id)

    def is_revoked(self, principal_id: str) -> bool:
        with self._lock:
            return principal_id in self._revoked
