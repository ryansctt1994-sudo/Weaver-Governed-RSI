"""Immutable public trust-root representation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from kernel.verifier import public_key_fingerprint


class TrustRootError(RuntimeError):
    """Raised for unauthorized or malformed trust-root operations."""


@dataclass(frozen=True, slots=True)
class TrustedKey:
    key_id: str
    public_key_pem: bytes
    purpose: str

    @property
    def fingerprint(self) -> str:
        return public_key_fingerprint(self.public_key_pem)


class TrustRoot:
    """Public keys only; rotation creates a new object after external authorization."""

    def __init__(self, keys: Mapping[str, TrustedKey]) -> None:
        if set(keys) != {key.key_id for key in keys.values()}:
            raise TrustRootError("key mapping does not match key IDs")
        self._keys = MappingProxyType(dict(keys))

    @property
    def keys(self) -> Mapping[str, TrustedKey]:
        return self._keys

    def get(self, key_id: str) -> TrustedKey:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise TrustRootError(f"untrusted key: {key_id}") from exc

    def with_rotated_key(
        self,
        *,
        old_key_id: str,
        replacement: TrustedKey,
        externally_ratified: bool,
    ) -> TrustRoot:
        if not externally_ratified:
            raise TrustRootError("trust-root rotation requires external ratification")
        if old_key_id not in self._keys:
            raise TrustRootError(f"cannot rotate missing key: {old_key_id}")
        updated = dict(self._keys)
        del updated[old_key_id]
        if replacement.key_id in updated:
            raise TrustRootError(f"replacement key ID already exists: {replacement.key_id}")
        updated[replacement.key_id] = replacement
        return TrustRoot(updated)
