from __future__ import annotations

import unittest

from kernel.authority_registry import (
    AuthorityDenied,
    AuthorityRegistry,
    Permission,
    Principal,
)


class AuthorityRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AuthorityRegistry(
            [
                Principal.build("governor", [Permission.GOVERN_AUTHORITY, Permission.REVOKE]),
                Principal.build("proposer", [Permission.PROPOSE]),
                Principal.build("validator", [Permission.VALIDATE]),
            ]
        )

    def test_unknown_identity_is_denied(self) -> None:
        with self.assertRaisesRegex(AuthorityDenied, "^'unknown' lacks 'propose'$"):
            self.registry.require("unknown", Permission.PROPOSE)

    def test_authority_governor_can_change_another_principal(self) -> None:
        updated = self.registry.replace_permissions(
            "governor", "proposer", [Permission.PROPOSE, Permission.APPLY]
        )
        self.assertIn(Permission.APPLY, updated.permissions)
        self.assertEqual(updated, self.registry.principal("proposer"))

    def test_actor_cannot_change_own_authority(self) -> None:
        with self.assertRaisesRegex(
            AuthorityDenied, "^a principal cannot modify its own authority$"
        ):
            self.registry.replace_permissions(
                "governor", "governor", [Permission.GOVERN_AUTHORITY, Permission.APPLY]
            )

    def test_revocation_removes_effective_permissions(self) -> None:
        self.registry.revoke("governor", "proposer")
        self.assertFalse(self.registry.has("proposer", Permission.PROPOSE))

    def test_distinct_error_is_stable_and_explicit(self) -> None:
        with self.assertRaisesRegex(
            AuthorityDenied, "^separation of duty requires distinct principals$"
        ):
            self.registry.assert_distinct("same", "same")


if __name__ == "__main__":
    unittest.main()
