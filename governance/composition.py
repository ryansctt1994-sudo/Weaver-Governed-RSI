from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _cjson(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    action: str
    value: str
    ratification_id: str
    claims_parent_authority: bool = False

    def sha256(self) -> str:
        return _sha256(
            _cjson(
                {
                    "proposal_id": self.proposal_id,
                    "action": self.action,
                    "value": self.value,
                    "ratification_id": self.ratification_id,
                    "claims_parent_authority": self.claims_parent_authority,
                }
            )
        )


@dataclass(frozen=True)
class GovernanceState:
    logging_destination: str = "audit.log"
    verifier_input: str = "audit.log"
    policy_version: int = 1
    trust_root_version: int = 1
    proposer_controlled_outputs: tuple[str, ...] = ()
    history: tuple[str, ...] = ()

    def sha256(self) -> str:
        return _sha256(
            _cjson(
                {
                    "logging_destination": self.logging_destination,
                    "verifier_input": self.verifier_input,
                    "policy_version": self.policy_version,
                    "trust_root_version": self.trust_root_version,
                    "proposer_controlled_outputs": list(self.proposer_controlled_outputs),
                    "history": list(self.history),
                }
            )
        )

    @property
    def policy_sha256(self) -> str:
        return _sha256(f"policy:{self.policy_version}".encode())

    @property
    def authority_context_sha256(self) -> str:
        return _sha256(
            _cjson(
                {
                    "policy_version": self.policy_version,
                    "trust_root_version": self.trust_root_version,
                }
            )
        )


@dataclass(frozen=True)
class AuthorizationReceipt:
    authorization_id: str
    proposal_id: str
    proposal_sha256: str
    pre_state_sha256: str
    policy_sha256: str
    trust_root_version: int
    authority_context_sha256: str
    ratification_id: str
    issued_utc: str
    issuer_key_id: str
    signature: bytes

    def unsigned_payload(self) -> bytes:
        return _cjson(
            {
                "authorization_id": self.authorization_id,
                "proposal_id": self.proposal_id,
                "proposal_sha256": self.proposal_sha256,
                "pre_state_sha256": self.pre_state_sha256,
                "policy_sha256": self.policy_sha256,
                "trust_root_version": self.trust_root_version,
                "authority_context_sha256": self.authority_context_sha256,
                "ratification_id": self.ratification_id,
                "issued_utc": self.issued_utc,
                "issuer_key_id": self.issuer_key_id,
            }
        )


@dataclass(frozen=True)
class PreviewResult:
    permitted: bool
    terminal_state: str
    would_violate_protected_invariant: bool = False
    authority_delta: int = 0


@dataclass(frozen=True)
class ApplyResult:
    terminal_state: str
    state: GovernanceState
    authority_delta: int = 0
    protected_invariant_breached: bool = False
    unauthorized_execution_observed: bool = False
    would_violate_protected_invariant: bool = False


class CompositionEvaluator:
    """Reference evaluator for I8/I8a/I8b/I9 adversarial validation."""

    DOMAIN = b"WEAVER-AUTHORIZATION-V1\x00"

    def __init__(self) -> None:
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._issuer_key_id = "composition-evaluator-v1"
        self._revoked: set[str] = set()
        self._consumed: set[str] = set()
        self._proposal_authority: dict[str, int] = {}

    @staticmethod
    def clone_state(state: GovernanceState) -> GovernanceState:
        return copy.deepcopy(state)

    def _protected_invariants_hold(self, state: GovernanceState) -> bool:
        return state.verifier_input not in set(state.proposer_controlled_outputs)

    def _transition(self, proposal: Proposal, state: GovernanceState) -> GovernanceState:
        history = state.history + (proposal.proposal_id,)
        if proposal.action == "set_logging_destination":
            return replace(
                state,
                logging_destination=proposal.value,
                proposer_controlled_outputs=tuple(sorted(set(state.proposer_controlled_outputs) | {proposal.value})),
                history=history,
            )
        if proposal.action == "set_verifier_input":
            return replace(state, verifier_input=proposal.value, history=history)
        if proposal.action == "bump_policy":
            return replace(state, policy_version=state.policy_version + 1, history=history)
        if proposal.action == "bump_trust_root":
            return replace(state, trust_root_version=state.trust_root_version + 1, history=history)
        if proposal.action == "noop":
            return replace(state, history=history)
        raise ValueError(f"unknown proposal action: {proposal.action}")

    def preview(self, proposal: Proposal, state: GovernanceState) -> PreviewResult:
        if proposal.claims_parent_authority:
            return PreviewResult(False, "REJECTED_AUTHORITY_NONTRANSFERABLE")
        try:
            candidate = self._transition(proposal, state)
        except ValueError:
            return PreviewResult(False, "REJECTED_UNKNOWN_PROPOSAL")
        if not self._protected_invariants_hold(candidate):
            return PreviewResult(
                False,
                "REJECTED_COMPOSITION_UNSAFE",
                would_violate_protected_invariant=True,
            )
        return PreviewResult(True, "PERMITTED")

    def evaluate(self, proposal: Proposal, state: GovernanceState) -> PreviewResult:
        return self.preview(proposal, state)

    def authorize(self, proposal: Proposal, state: GovernanceState) -> AuthorizationReceipt:
        preview = self.preview(proposal, state)
        if not preview.permitted:
            raise PermissionError(preview.terminal_state)
        receipt = AuthorizationReceipt(
            authorization_id=str(uuid.uuid4()),
            proposal_id=proposal.proposal_id,
            proposal_sha256=proposal.sha256(),
            pre_state_sha256=state.sha256(),
            policy_sha256=state.policy_sha256,
            trust_root_version=state.trust_root_version,
            authority_context_sha256=state.authority_context_sha256,
            ratification_id=proposal.ratification_id,
            issued_utc=datetime.now(timezone.utc).isoformat(),
            issuer_key_id=self._issuer_key_id,
            signature=b"",
        )
        signature = self._private_key.sign(self.DOMAIN + receipt.unsigned_payload())
        receipt = replace(receipt, signature=signature)
        self._proposal_authority.setdefault(proposal.proposal_id, 0)
        return receipt

    def _verify_receipt_signature(self, receipt: AuthorizationReceipt) -> bool:
        try:
            self._public_key.verify(receipt.signature, self.DOMAIN + receipt.unsigned_payload())
        except Exception:
            return False
        return True

    def revalidate(
        self,
        proposal: Proposal,
        authorization: AuthorizationReceipt,
        current_state: GovernanceState,
    ) -> PreviewResult:
        if authorization.proposal_id != proposal.proposal_id:
            return PreviewResult(False, "REJECTED_RECEIPT_PROPOSAL_MISMATCH")
        if authorization.proposal_sha256 != proposal.sha256():
            return PreviewResult(False, "REJECTED_RECEIPT_PROPOSAL_MISMATCH")
        if authorization.ratification_id != proposal.ratification_id:
            return PreviewResult(False, "REJECTED_RATIFICATION_PROPOSAL_MISMATCH")
        if authorization.pre_state_sha256 != current_state.sha256():
            return PreviewResult(False, "REJECTED_STALE_AUTHORIZATION")
        if authorization.policy_sha256 != current_state.policy_sha256:
            return PreviewResult(False, "REJECTED_STALE_POLICY_CONTEXT")
        if authorization.trust_root_version != current_state.trust_root_version:
            return PreviewResult(False, "REJECTED_STALE_TRUST_CONTEXT")
        if authorization.authority_context_sha256 != current_state.authority_context_sha256:
            return PreviewResult(False, "REJECTED_STALE_AUTHORIZATION")
        return self.preview(proposal, current_state)

    def apply(
        self,
        proposal: Proposal,
        authorization: AuthorizationReceipt,
        state: GovernanceState,
    ) -> ApplyResult:
        if not self._verify_receipt_signature(authorization):
            return ApplyResult("REJECTED_INVALID_SIGNATURE", state)
        if authorization.authorization_id in self._revoked:
            return ApplyResult("REJECTED_REVOKED_AUTHORITY", state)
        if authorization.authorization_id in self._consumed:
            return ApplyResult("REJECTED_AUTHORIZATION_ALREADY_CONSUMED", state)
        if proposal.claims_parent_authority:
            return ApplyResult("REJECTED_AUTHORITY_NONTRANSFERABLE", state)
        if authorization.proposal_id != proposal.proposal_id:
            return ApplyResult("REJECTED_RECEIPT_PROPOSAL_MISMATCH", state)
        if authorization.proposal_sha256 != proposal.sha256():
            return ApplyResult("REJECTED_RECEIPT_PROPOSAL_MISMATCH", state)
        if authorization.ratification_id != proposal.ratification_id:
            return ApplyResult("REJECTED_RATIFICATION_PROPOSAL_MISMATCH", state)
        if authorization.pre_state_sha256 != state.sha256():
            return ApplyResult("REJECTED_STALE_AUTHORIZATION", state)
        if authorization.policy_sha256 != state.policy_sha256:
            return ApplyResult("REJECTED_STALE_POLICY_CONTEXT", state)
        if authorization.trust_root_version != state.trust_root_version:
            return ApplyResult("REJECTED_STALE_TRUST_CONTEXT", state)
        if authorization.authority_context_sha256 != state.authority_context_sha256:
            return ApplyResult("REJECTED_STALE_AUTHORIZATION", state)

        preview = self.preview(proposal, state)
        if not preview.permitted:
            return ApplyResult(
                preview.terminal_state,
                state,
                authority_delta=0,
                would_violate_protected_invariant=preview.would_violate_protected_invariant,
            )

        candidate = self._transition(proposal, state)
        if not self._protected_invariants_hold(candidate):
            return ApplyResult(
                "REJECTED_COMPOSITION_UNSAFE",
                state,
                authority_delta=0,
                would_violate_protected_invariant=True,
            )

        self._consumed.add(authorization.authorization_id)
        return ApplyResult("EXECUTED", candidate, authority_delta=0)

    def authority_of(self, proposal: Proposal) -> int:
        return self._proposal_authority.get(proposal.proposal_id, 0)

    def revoke(self, authorization: AuthorizationReceipt) -> None:
        self._revoked.add(authorization.authorization_id)
