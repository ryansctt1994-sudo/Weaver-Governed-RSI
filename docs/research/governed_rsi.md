# Governed recursive self-improvement

## Hypothesis

Bounded self-improvement can be represented as proposal generation under an external
authorization process. Improvement quality and governance authority are orthogonal variables.

## Minimal experiment

1. A proposer emits a change with content digests and declared targets.
2. The recursion firewall checks protected surfaces and requested permissions.
3. A distinct validator evaluates the identified bytes.
4. A distinct ratifier authorizes or rejects the transition.
5. Application is limited to the ratified bytes and scope.
6. The ledger permits deterministic replay and independent inspection.

## Falsification conditions

The research hypothesis is weakened if an actor can gain authority through capability output,
if proposal bytes can change after validation, if revocation loses a race with application,
or if evidence promotion can be self-assigned.

## Current limit

This repository tests a control abstraction. It does not run autonomous model training or
demonstrate that a future generally capable system cannot exploit unmodeled channels.
