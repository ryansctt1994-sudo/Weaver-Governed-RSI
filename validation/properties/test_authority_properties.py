from __future__ import annotations

import unittest

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kernel.authority_registry import AuthorityDenied, AuthorityRegistry, Permission, Principal


class AuthorityPropertyTests(unittest.TestCase):
    @settings(derandomize=True, suppress_health_check=[HealthCheck.differing_executors])
    @given(st.sampled_from(list(Permission)))
    def test_revoked_principal_has_no_effective_permission(self, permission: Permission) -> None:
        registry = AuthorityRegistry(
            [
                Principal.build("governor", [Permission.REVOKE]),
                Principal.build("target", list(Permission)),
            ]
        )
        registry.revoke("governor", "target")
        self.assertFalse(registry.has("target", permission))

    @settings(derandomize=True, suppress_health_check=[HealthCheck.differing_executors])
    @given(st.sampled_from(list(Permission)))
    def test_unknown_principal_is_always_denied(self, permission: Permission) -> None:
        registry = AuthorityRegistry()
        with self.assertRaises(AuthorityDenied):
            registry.require("unknown", permission)


if __name__ == "__main__":
    unittest.main()
