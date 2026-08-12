# Governance

## Prime rule

> No source file, test suite, release artifact, maintainer, AI agent, or CI job may assign its
> own evidence tier.

Artifacts emit evidence. The Evidence Registry evaluates promotion.

## Authority separation

- A proposer may create a change proposal but cannot make it effective.
- A validator may evaluate an identified artifact but cannot ratify its own result.
- A ratifier may authorize a bounded transition but cannot rewrite the constitutional
  invariants inside the same transition.
- A release builder may package approved bytes but cannot determine their evidence tier.
- An evidence evaluator must be distinct from the evidence producer for promotion above E1.
- Missing, ambiguous, or mutated evidence resolves to **INDETERMINATE**, never authority.

## Protected targets

The following paths are governance-sensitive:

```text
constitution/
kernel/recursion_firewall.py
kernel/verifier.py
kernel/authority_registry.py
kernel/trust_root.py
release/
validation/evidence_registry.py
.github/CODEOWNERS
.github/workflows/
```

Changes require:

1. an explicit threat-boundary statement;
2. adversarial tests for the affected invariant;
3. review by a CODEOWNER;
4. a reviewer independent of the change author when one is available;
5. dismissal of stale approvals after new commits;
6. a new receipt tied to the final commit, without automatic evidence promotion.

Until an independent reviewer is configured, protected-target changes remain
**maintainer-reviewed but not independently governed**.

## Branch and release policy

- no direct pushes to `main`;
- pull requests and required CI for all changes;
- force pushes and branch deletion disabled on `main`;
- signed maintainer commits where practical;
- immutable release tags and external attestation refs;
- no release from a dirty tree or a payload containing unsafe symlinks;
- the bytes tested must be bound to the bytes shipped by payload and bundle manifests.

Repository settings enforce these rules where the hosting plan supports them; this document
remains normative when a setting is unavailable.

## Evidence ladder

| Tier | Meaning in this project |
|---|---|
| E0 | Proposed, scaffolded, or unverified claim |
| E1 | Internally inspected artifact with identity recorded |
| E2 | Repeatable same-environment validation |
| E3 | Fresh-environment verification tied to exact bytes |
| E4 | Independent heterogeneous replication accepted by the registry |
| E5 | Independent external review with published scope and limitations |

The exact acceptance rules live in `constitution/ratification_policy.yaml` and ADR-0001.

## Amendment

Constitutional changes are versioned proposals. They cannot be bundled with the capability
change that depends on them, and they require a separate ratification record.
