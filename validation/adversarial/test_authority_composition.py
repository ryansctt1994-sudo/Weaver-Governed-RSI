from __future__ import annotations

from governance.composition import CompositionEvaluator, GovernanceState, Proposal


DENIAL_STATES = {
    "REJECTED_STALE_AUTHORIZATION",
    "REJECTED_RECEIPT_PROPOSAL_MISMATCH",
    "REJECTED_AUTHORITY_NONTRANSFERABLE",
    "REJECTED_COMPOSITION_UNSAFE",
    "REJECTED_REVOKED_AUTHORITY",
    "REJECTED_RATIFICATION_PROPOSAL_MISMATCH",
    "REJECTED_STALE_POLICY_CONTEXT",
    "REJECTED_STALE_TRUST_CONTEXT",
    "REJECTED_AUTHORIZATION_ALREADY_CONSUMED",
    "INDETERMINATE_COMPOSITION_STATE",
}


def test_c0_single_authorized_proposal_executes(evaluator, initial_state, benign_proposal) -> None:
    auth = evaluator.authorize(benign_proposal, initial_state)
    assert evaluator.apply(benign_proposal, auth, initial_state).terminal_state == "EXECUTED"


def test_c0b_second_proposal_may_execute_after_revalidation(
    evaluator, initial_state, benign_p1, benign_p2
) -> None:
    auth1 = evaluator.authorize(benign_p1, initial_state)
    state1 = evaluator.apply(benign_p1, auth1, initial_state).state
    auth2 = evaluator.authorize(benign_p2, state1)
    assert evaluator.apply(benign_p2, auth2, state1).terminal_state == "EXECUTED"


def test_crt_l1_receipt_for_p1_cannot_authorize_p2(
    evaluator, initial_state, benign_p1, malicious_p2
) -> None:
    auth1 = evaluator.authorize(benign_p1, initial_state)
    result = evaluator.apply(malicious_p2, auth1, initial_state)
    assert result.terminal_state == "REJECTED_RECEIPT_PROPOSAL_MISMATCH"
    assert result.authority_delta <= 0


def test_crt_l2_authority_is_not_inherited(
    evaluator, initial_state, benign_p1, p2_claiming_p1_authority
) -> None:
    auth1 = evaluator.authorize(benign_p1, initial_state)
    result = evaluator.apply(p2_claiming_p1_authority, auth1, initial_state)
    assert result.terminal_state == "REJECTED_AUTHORITY_NONTRANSFERABLE"
    assert result.authority_delta <= 0


def test_crt_l3_revoking_p1_never_increases_p2_authority(
    evaluator, initial_state, p1, p2
) -> None:
    auth1 = evaluator.authorize(p1, initial_state)
    before = evaluator.authority_of(p2)
    evaluator.revoke(auth1)
    after = evaluator.authority_of(p2)
    assert after <= before
    result = evaluator.apply(p2, auth1, initial_state)
    assert result.terminal_state in {
        "REJECTED_REVOKED_AUTHORITY",
        "REJECTED_RECEIPT_PROPOSAL_MISMATCH",
    }


def test_crt_l4_p2_authorization_becomes_stale_after_p1_changes_state(
    evaluator, initial_state, p1, p2
) -> None:
    auth1 = evaluator.authorize(p1, initial_state)
    auth2 = evaluator.authorize(p2, initial_state)
    state1 = evaluator.apply(p1, auth1, initial_state).state
    result = evaluator.apply(p2, auth2, state1)
    assert result.terminal_state == "REJECTED_STALE_AUTHORIZATION"
    assert result.authority_delta <= 0


def test_crt_l5_p2_can_execute_after_revalidation_on_new_state(
    evaluator, initial_state, p1, compatible_p2
) -> None:
    auth1 = evaluator.authorize(p1, initial_state)
    state1 = evaluator.apply(p1, auth1, initial_state).state
    auth2 = evaluator.authorize(compatible_p2, state1)
    assert evaluator.apply(compatible_p2, auth2, state1).terminal_state == "EXECUTED"


def test_crt_l6_two_individually_permitted_changes_cannot_compose_into_violation(
    evaluator: CompositionEvaluator,
    initial_state: GovernanceState,
) -> None:
    p1 = Proposal("log-redirect", "set_logging_destination", "alternate.log", "ratify:log")
    p2 = Proposal("verify-redirect", "set_verifier_input", "alternate.log", "ratify:verify")
    assert evaluator.preview(p1, initial_state).permitted
    assert evaluator.preview(p2, initial_state).permitted

    auth1 = evaluator.authorize(p1, initial_state)
    state1 = evaluator.apply(p1, auth1, initial_state).state
    evaluation = evaluator.evaluate(p2, state1)
    assert evaluation.would_violate_protected_invariant
    assert evaluation.terminal_state == "REJECTED_COMPOSITION_UNSAFE"


def test_crt_l9_ratification_reuse_is_denied(
    evaluator, initial_state, p1_with_ratification, p2
) -> None:
    auth1 = evaluator.authorize(p1_with_ratification, initial_state)
    result = evaluator.apply(p2, auth1, initial_state)
    assert result.terminal_state in {
        "REJECTED_RATIFICATION_PROPOSAL_MISMATCH",
        "REJECTED_RECEIPT_PROPOSAL_MISMATCH",
    }


def test_crt_l10_policy_version_drift_invalidates_old_authorization(
    evaluator, initial_state, p2, policy_bump_proposal
) -> None:
    auth2 = evaluator.authorize(p2, initial_state)
    auth1 = evaluator.authorize(policy_bump_proposal, initial_state)
    state1 = evaluator.apply(policy_bump_proposal, auth1, initial_state).state
    result = evaluator.apply(p2, auth2, state1)
    assert result.terminal_state in {
        "REJECTED_STALE_AUTHORIZATION",
        "REJECTED_STALE_POLICY_CONTEXT",
    }


def test_crt_l11_trust_root_drift_invalidates_old_authorization(
    evaluator, initial_state, p2, trust_root_mutation_proposal
) -> None:
    auth2 = evaluator.authorize(p2, initial_state)
    auth1 = evaluator.authorize(trust_root_mutation_proposal, initial_state)
    state1 = evaluator.apply(trust_root_mutation_proposal, auth1, initial_state).state
    result = evaluator.apply(p2, auth2, state1)
    assert result.terminal_state in {
        "REJECTED_STALE_AUTHORIZATION",
        "REJECTED_STALE_TRUST_CONTEXT",
    }


def test_crt_l12_safe_independent_sequential_changes_are_allowed(
    evaluator, initial_state, independent_p1, independent_p2
) -> None:
    auth1 = evaluator.authorize(independent_p1, initial_state)
    state1 = evaluator.apply(independent_p1, auth1, initial_state).state
    auth2 = evaluator.authorize(independent_p2, state1)
    assert evaluator.apply(independent_p2, auth2, state1).terminal_state == "EXECUTED"


def test_crt_l13_consumed_single_use_authorization_cannot_execute_twice(
    evaluator, initial_state, benign_proposal
) -> None:
    auth = evaluator.authorize(benign_proposal, initial_state)
    first = evaluator.apply(benign_proposal, auth, initial_state)
    assert first.terminal_state == "EXECUTED"
    second = evaluator.apply(benign_proposal, auth, initial_state)
    assert second.terminal_state == "REJECTED_AUTHORIZATION_ALREADY_CONSUMED"
    assert second.authority_delta <= 0
