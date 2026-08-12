from __future__ import annotations

from pathlib import Path

import pytest

from governance.composition import CompositionEvaluator, GovernanceState, Proposal
from governance.mutation_transaction import MutationTransaction
from identity.linux import LinuxIdentityCapture
from identity.policy import LinuxIdentityPolicy


@pytest.fixture
def transaction_factory():
    def factory(target: Path) -> MutationTransaction:
        return MutationTransaction(target)

    return factory


@pytest.fixture
def descriptor_transaction_factory(transaction_factory):
    return transaction_factory


@pytest.fixture
def identity_capture():
    return LinuxIdentityCapture()


@pytest.fixture
def identity_policy():
    return LinuxIdentityPolicy()


@pytest.fixture
def safe_file(tmp_path: Path) -> Path:
    path = tmp_path / "safe.py"
    path.write_text("benign", encoding="utf-8")
    return path


@pytest.fixture
def evaluator():
    return CompositionEvaluator()


@pytest.fixture
def initial_state():
    return GovernanceState()


def proposal(pid: str, action: str = "noop", value: str = "") -> Proposal:
    return Proposal(
        proposal_id=pid,
        action=action,
        value=value,
        ratification_id=f"ratify:{pid}",
    )


@pytest.fixture
def benign_proposal():
    return proposal("benign")


@pytest.fixture
def benign_p1():
    return proposal("p1", "set_logging_destination", "internal.log")


@pytest.fixture
def benign_p2():
    return proposal("p2", "noop")


@pytest.fixture
def p1(benign_p1):
    return benign_p1


@pytest.fixture
def p2(benign_p2):
    return benign_p2


@pytest.fixture
def malicious_p2():
    return proposal("malicious-p2", "noop")


@pytest.fixture
def compatible_p2(benign_p2):
    return benign_p2


@pytest.fixture
def p2_claiming_p1_authority():
    return Proposal(
        proposal_id="p2-parent-claim",
        action="noop",
        value="",
        ratification_id="ratify:p2-parent-claim",
        claims_parent_authority=True,
    )


@pytest.fixture
def p1_with_ratification():
    return proposal("ratified-p1")


@pytest.fixture
def policy_bump_proposal():
    return proposal("policy-bump", "bump_policy")


@pytest.fixture
def trust_root_mutation_proposal():
    return proposal("trust-bump", "bump_trust_root")


@pytest.fixture
def independent_p1():
    return proposal("independent-1", "set_logging_destination", "internal.log")


@pytest.fixture
def independent_p2():
    return proposal("independent-2", "noop")
