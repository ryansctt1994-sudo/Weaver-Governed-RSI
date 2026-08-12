# Weaver Constitution

## Purpose

This constitution limits how proposed capability improvements become authorized state
changes. It does not prove that the limits are universally sufficient.

## Invariants

1. **Capability is not authority.** Increased ability does not grant permissions.
2. **A proposal is not an action.** A submitted change cannot execute before validation and
   ratification.
3. **Self-improvement is not self-authorization.** A system cannot approve changes to its
   own permissions, trust roots, verification logic, recursion firewall, or constitution.
4. **Evidence generation is not evidence evaluation.** Producers cannot promote their own
   evidence claims.
5. **Uncertainty is not authority.** Missing identity, failed instruments, ambiguous state,
   and artifact mutation produce an indeterminate result that cannot authorize action.
6. **Revocation dominates pending authorization.** Once observed, a valid revocation blocks
   subsequent application under the revoked authority.
7. **Exact bytes define the evaluated artifact.** Names, branches, and mutable URLs are not
   sufficient artifact identity.

## Protected constitutional surface

The machine-readable list in `protected_targets.yaml` is normative for automated checks.
Changes to that list are themselves protected.

## Amendment procedure

An amendment must be proposed, validated, and ratified separately from any capability change
that relies on it. The amendment record must identify the old and new constitutional hashes,
the ratifiers, dissent or uncertainty, and the effective commit.

## Authority limit

This document governs this repository's process. It does not claim legal authority, moral
infallibility, AGI containment, or production certification.
