"""Deterministic reconstruction of proposal state from a verified ledger."""

from __future__ import annotations

from dataclasses import dataclass

from kernel.ledger import AppendOnlyLedger
from kernel.state_machine import ProposalState, Transition, transition


class ReplayError(RuntimeError):
    """Raised when a ledger is invalid or semantically unreplayable."""


@dataclass(frozen=True, slots=True)
class ReplayResult:
    states: dict[str, ProposalState]
    record_count: int


def replay(ledger: AppendOnlyLedger) -> ReplayResult:
    verification = ledger.verify()
    if not verification.valid:
        raise ReplayError(
            f"ledger verification failed at {verification.failure_index}: {verification.reason}"
        )

    states: dict[str, ProposalState] = {}
    for record in ledger.records:
        event = record.event
        proposal_id = event.get("proposal_id")
        transition_name = event.get("transition")
        if not isinstance(proposal_id, str) or not isinstance(transition_name, str):
            raise ReplayError(f"record {record.sequence} lacks replay fields")
        current = states.get(proposal_id, ProposalState.DRAFT)
        try:
            states[proposal_id] = transition(current, Transition(transition_name))
        except (ValueError, RuntimeError) as exc:
            raise ReplayError(f"record {record.sequence} is semantically invalid") from exc
    return ReplayResult(states=states, record_count=len(ledger.records))
