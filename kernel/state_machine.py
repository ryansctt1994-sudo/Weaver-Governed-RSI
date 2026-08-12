"""Deny-by-default proposal state machine."""

from __future__ import annotations

from enum import StrEnum


class ProposalState(StrEnum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    VALIDATED = "VALIDATED"
    RATIFIED = "RATIFIED"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


class Transition(StrEnum):
    SUBMIT = "submit"
    BLOCK = "block"
    # Event label, not a credential.
    VALIDATION_PASS = "validation_pass"  # nosec B105
    VALIDATION_FAIL = "validation_fail"
    VALIDATION_INDETERMINATE = "validation_indeterminate"
    RATIFY = "ratify"
    REJECT = "reject"
    APPLY = "apply"
    ARTIFACT_MISMATCH = "artifact_mismatch"
    REVOKE = "revoke"


_ALLOWED: dict[tuple[ProposalState, Transition], ProposalState] = {
    (ProposalState.DRAFT, Transition.SUBMIT): ProposalState.SUBMITTED,
    (ProposalState.DRAFT, Transition.BLOCK): ProposalState.REJECTED,
    (ProposalState.SUBMITTED, Transition.VALIDATION_PASS): ProposalState.VALIDATED,
    (ProposalState.SUBMITTED, Transition.VALIDATION_FAIL): ProposalState.REJECTED,
    (
        ProposalState.SUBMITTED,
        Transition.VALIDATION_INDETERMINATE,
    ): ProposalState.INDETERMINATE,
    (ProposalState.VALIDATED, Transition.RATIFY): ProposalState.RATIFIED,
    (ProposalState.VALIDATED, Transition.REJECT): ProposalState.REJECTED,
    (ProposalState.VALIDATED, Transition.REVOKE): ProposalState.REJECTED,
    (ProposalState.RATIFIED, Transition.APPLY): ProposalState.APPLIED,
    (ProposalState.RATIFIED, Transition.ARTIFACT_MISMATCH): ProposalState.INDETERMINATE,
    (ProposalState.RATIFIED, Transition.REVOKE): ProposalState.REJECTED,
}


class InvalidTransition(RuntimeError):
    """Raised when a transition is not explicitly permitted."""


def transition(current: ProposalState, event: Transition) -> ProposalState:
    try:
        return _ALLOWED[(current, event)]
    except KeyError as exc:
        raise InvalidTransition(f"cannot {event.value} from {current.value}") from exc


def allowed_transitions(current: ProposalState) -> frozenset[Transition]:
    return frozenset(event for state, event in _ALLOWED if state is current)
