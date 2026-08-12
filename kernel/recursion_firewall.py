"""Static firewall for self-authorization and protected-target proposals."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

DEFAULT_PROTECTED_PATTERNS = (
    "constitution/**",
    "kernel/recursion_firewall.py",
    "kernel/verifier.py",
    "kernel/authority_registry.py",
    "kernel/trust_root.py",
    "release/**",
    "validation/evidence_registry.py",
    ".github/CODEOWNERS",
    ".github/workflows/**",
)


@dataclass(frozen=True, slots=True)
class FirewallFinding:
    code: str
    message: str
    blocking: bool = True


@dataclass(frozen=True, slots=True)
class FirewallDecision:
    allowed: bool
    findings: tuple[FirewallFinding, ...]
    protected_paths: tuple[str, ...]


class RecursionFirewall:
    """Deny malformed paths, self-authorization, and undeclared protected changes."""

    def __init__(self, protected_patterns: Iterable[str] = DEFAULT_PROTECTED_PATTERNS) -> None:
        self._patterns = tuple(protected_patterns)

    def is_protected(self, path: str) -> bool:
        normalized = PurePosixPath(path)
        return any(normalized.match(pattern) for pattern in self._patterns)

    @staticmethod
    def _path_is_safe(path: str) -> bool:
        parsed = PurePosixPath(path)
        return bool(path) and not parsed.is_absolute() and ".." not in parsed.parts

    def inspect(
        self,
        *,
        proposer_id: str,
        changed_paths: Iterable[str],
        authority_target: str | None = None,
        requested_permissions: Iterable[str] = (),
        protected_change_declared: bool = False,
    ) -> FirewallDecision:
        paths = tuple(changed_paths)
        findings: list[FirewallFinding] = []

        unsafe_paths = tuple(path for path in paths if not self._path_is_safe(path))
        if unsafe_paths:
            findings.append(
                FirewallFinding("FW-PATH-001", f"unsafe repository paths: {unsafe_paths!r}")
            )

        requested = tuple(requested_permissions)
        if authority_target == proposer_id and requested:
            findings.append(
                FirewallFinding(
                    "FW-AUTH-001",
                    "a proposer cannot request an authority expansion for itself",
                )
            )

        protected = tuple(sorted(path for path in paths if self.is_protected(path)))
        if protected and not protected_change_declared:
            findings.append(
                FirewallFinding(
                    "FW-PROTECTED-001",
                    "protected targets require an explicit governance-change declaration",
                )
            )

        return FirewallDecision(
            allowed=not any(finding.blocking for finding in findings),
            findings=tuple(findings),
            protected_paths=protected,
        )
