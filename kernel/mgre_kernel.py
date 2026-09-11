"""Minimal governed recursive-enhancement proposal kernel."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from kernel.authority_registry import AuthorityRegistry, Permission
from kernel.ledger import AppendOnlyLedger, LedgerRecord, canonical_json
from kernel.recursion_firewall import FirewallDecision, RecursionFirewall
from kernel.state_machine import ProposalState, Transition, transition

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ValidationResult(StrEnum):
    # Result label, not a credential.
    PASS = "PASS"  # nosec B105
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("change sha256 must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    proposer_id: str
    summary: str
    changes: tuple[Change, ...]
    authority_target: str | None = None
    requested_permissions: tuple[str, ...] = ()
    protected_change_declared: bool = False

    def __post_init__(self) -> None:
        if not self.proposal_id.strip() or not self.summary.strip() or not self.changes:
            raise ValueError("proposal ID, summary, and at least one change are required")
        paths = [change.path for change in self.changes]
        if len(paths) != len(set(paths)):
            raise ValueError("proposal paths must be unique")

    @property
    def digest(self) -> str:
        payload = {
            "proposal_id": self.proposal_id,
            "proposer_id": self.proposer_id,
            "summary": self.summary,
            "changes": [
                {"path": change.path, "sha256": change.sha256}
                for change in sorted(self.changes, key=lambda item: item.path)
            ],
            "authority_target": self.authority_target,
            "requested_permissions": sorted(self.requested_permissions),
            "protected_change_declared": self.protected_change_declared,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class KernelReceipt:
    proposal_id: str
    state: ProposalState
    record: LedgerRecord
    firewall: FirewallDecision | None = None


class GovernedKernel:
    """Coordinate proposals while keeping authorization outside capability output."""

    def __init__(
        self,
        authority_registry: AuthorityRegistry,
        *,
        firewall: RecursionFirewall | None = None,
        ledger: AppendOnlyLedger | None = None,
    ) -> None:
        self.authority_registry = authority_registry
        self.firewall = firewall or RecursionFirewall()
        self.ledger = ledger or AppendOnlyLedger()
        self._proposals: dict[str, Proposal] = {}
        self._states: dict[str, ProposalState] = {}
        self._validators: dict[str, str] = {}
        self._ratifiers: dict[str, str] = {}
        self._revoked_proposals: set[str] = set()

    def state(self, proposal_id: str) -> ProposalState:
        try:
            return self._states[proposal_id]
        except KeyError as exc:
            raise KeyError(f"unknown proposal: {proposal_id}") from exc

    def _record(
        self,
        proposal: Proposal,
        event: Transition,
        actor_id: str,
        recorded_at: str,
        **details: object,
    ) -> LedgerRecord:
        return self.ledger.append(
            {
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "transition": event.value,
                "actor_id": actor_id,
                "details": details,
            },
            recorded_at=recorded_at,
        )

    def submit(self, proposal: Proposal, *, recorded_at: str) -> KernelReceipt:
        self.authority_registry.require(proposal.proposer_id, Permission.PROPOSE)
        if proposal.proposal_id in self._proposals:
            raise ValueError(f"duplicate proposal ID: {proposal.proposal_id}")

        decision = self.firewall.inspect(
            proposer_id=proposal.proposer_id,
            changed_paths=(change.path for change in proposal.changes),
            authority_target=proposal.authority_target,
            requested_permissions=proposal.requested_permissions,
            protected_change_declared=proposal.protected_change_declared,
        )
        event = Transition.SUBMIT if decision.allowed else Transition.BLOCK
        state = transition(ProposalState.DRAFT, event)
        self._proposals[proposal.proposal_id] = proposal
        self._states[proposal.proposal_id] = state
        record = self._record(
            proposal,
            event,
            proposal.proposer_id,
            recorded_at,
            finding_codes=[finding.code for finding in decision.findings],
            protected_paths=list(decision.protected_paths),
        )
        return KernelReceipt(proposal.proposal_id, state, record, decision)

    def validate(
        self,
        proposal_id: str,
        *,
        validator_id: str,
        result: ValidationResult,
        recorded_at: str,
    ) -> KernelReceipt:
        proposal = self._proposals[proposal_id]
        self.authority_registry.require(validator_id, Permission.VALIDATE)
        self.authority_registry.assert_distinct(proposal.proposer_id, validator_id)
        event = {
            ValidationResult.PASS: Transition.VALIDATION_PASS,
            ValidationResult.FAIL: Transition.VALIDATION_FAIL,
            ValidationResult.INDETERMINATE: Transition.VALIDATION_INDETERMINATE,
        }[result]
        state = transition(self.state(proposal_id), event)
        self._states[proposal_id] = state
        self._validators[proposal_id] = validator_id
        record = self._record(
            proposal, event, validator_id, recorded_at, validation_result=result.value
        )
        return KernelReceipt(proposal_id, state, record)

    def ratify(
        self,
        proposal_id: str,
        *,
        ratifier_id: str,
        approve: bool,
        recorded_at: str,
    ) -> KernelReceipt:
        proposal = self._proposals[proposal_id]
        self.authority_registry.require(ratifier_id, Permission.RATIFY)
        self.authority_registry.assert_distinct(
            proposal.proposer_id,
            self._validators[proposal_id],
            ratifier_id,
        )
        event = Transition.RATIFY if approve else Transition.REJECT
        state = transition(self.state(proposal_id), event)
        self._states[proposal_id] = state
        if approve:
            self._ratifiers[proposal_id] = ratifier_id
        record = self._record(proposal, event, ratifier_id, recorded_at, approved=approve)
        return KernelReceipt(proposal_id, state, record)

    def apply(
        self,
        proposal_id: str,
        *,
        applicator_id: str,
        observed_proposal_digest: str,
        recorded_at: str,
    ) -> KernelReceipt:
        proposal = self._proposals[proposal_id]
        self.authority_registry.require(applicator_id, Permission.APPLY)
        self.authority_registry.assert_distinct(
            proposal.proposer_id,
            self._validators[proposal_id],
            self._ratifiers[proposal_id],
            applicator_id,
        )
        if proposal_id in self._revoked_proposals:
            raise PermissionError("proposal authority was revoked")
        event = (
            Transition.APPLY
            if observed_proposal_digest == proposal.digest
            else Transition.ARTIFACT_MISMATCH
        )
        state = transition(self.state(proposal_id), event)
        self._states[proposal_id] = state
        record = self._record(
            proposal,
            event,
            applicator_id,
            recorded_at,
            observed_proposal_digest=observed_proposal_digest,
        )
        return KernelReceipt(proposal_id, state, record)

    def revoke(
        self,
        proposal_id: str,
        *,
        revoker_id: str,
        recorded_at: str,
    ) -> KernelReceipt:
        proposal = self._proposals[proposal_id]
        self.authority_registry.require(revoker_id, Permission.REVOKE)
        self.authority_registry.assert_distinct(proposal.proposer_id, revoker_id)
        state = transition(self.state(proposal_id), Transition.REVOKE)
        self._revoked_proposals.add(proposal_id)
        self._states[proposal_id] = state
        record = self._record(proposal, Transition.REVOKE, revoker_id, recorded_at)
        return KernelReceipt(proposal_id, state, record)

    @property
    def proposal_ids(self) -> tuple[str, ...]:
        return tuple(self._proposals)


def sha256_changes(items: Iterable[tuple[str, bytes]]) -> tuple[Change, ...]:
    """Convenience helper for constructing content-bound change objects."""

    return tuple(Change(path, hashlib.sha256(content).hexdigest()) for path, content in items)
