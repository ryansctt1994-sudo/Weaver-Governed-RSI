from __future__ import annotations

import unittest

from kernel.recursion_firewall import RecursionFirewall


class RecursionFirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.firewall = RecursionFirewall()

    def test_empty_absolute_and_traversal_paths_are_blocked(self) -> None:
        for path in ("", "/absolute.py", "safe/../escape.py"):
            with self.subTest(path=path):
                decision = self.firewall.inspect(proposer_id="p", changed_paths=[path])
                self.assertFalse(decision.allowed)
                self.assertEqual("FW-PATH-001", decision.findings[0].code)
                self.assertEqual(
                    f"unsafe repository paths: {(path,)!r}", decision.findings[0].message
                )

    def test_ordinary_relative_path_is_allowed(self) -> None:
        decision = self.firewall.inspect(proposer_id="p", changed_paths=["examples/ordinary.txt"])
        self.assertTrue(decision.allowed)
        self.assertEqual((), decision.findings)

    def test_authority_request_for_another_identity_is_not_self_authorization(self) -> None:
        decision = self.firewall.inspect(
            proposer_id="p",
            changed_paths=["examples/ordinary.txt"],
            authority_target="other",
            requested_permissions=["validate"],
        )
        self.assertTrue(decision.allowed)

    def test_empty_permission_request_does_not_trigger_self_authorization(self) -> None:
        decision = self.firewall.inspect(
            proposer_id="p",
            changed_paths=["examples/ordinary.txt"],
            authority_target="p",
            requested_permissions=[],
        )
        self.assertTrue(decision.allowed)

    def test_self_authorization_finding_is_stable_and_blocking(self) -> None:
        decision = self.firewall.inspect(
            proposer_id="p",
            changed_paths=["examples/ordinary.txt"],
            authority_target="p",
            requested_permissions=["ratify"],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(1, len(decision.findings))
        finding = decision.findings[0]
        self.assertEqual("FW-AUTH-001", finding.code)
        self.assertEqual(
            "a proposer cannot request an authority expansion for itself", finding.message
        )
        self.assertTrue(finding.blocking)

    def test_protected_change_defaults_to_blocked(self) -> None:
        decision = self.firewall.inspect(
            proposer_id="p", changed_paths=["constitution/invariants.yaml"]
        )
        self.assertFalse(decision.allowed)
        finding = decision.findings[0]
        self.assertEqual("FW-PROTECTED-001", finding.code)
        self.assertEqual(
            "protected targets require an explicit governance-change declaration",
            finding.message,
        )

    def test_declared_protected_change_can_enter_review(self) -> None:
        decision = self.firewall.inspect(
            proposer_id="p",
            changed_paths=["constitution/invariants.yaml"],
            protected_change_declared=True,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(("constitution/invariants.yaml",), decision.protected_paths)


if __name__ == "__main__":
    unittest.main()
