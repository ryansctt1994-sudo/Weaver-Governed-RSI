# ADR-0004: No self-assigned evidence tier

- Status: Accepted
- Date: 2026-08-12

## Context

A component that benefits from a stronger evidence label has a structural conflict of
interest. Automated promotion also risks converting instrument failure into authority.

## Decision

No code, CI job, artifact producer, maintainer, or AI agent may assign its own evidence tier.
The Evidence Registry evaluates a submitted claim, and its evaluator must be distinct from the
producer for promotion above E1.

## Consequences

CI is intentionally unable to update `evidence/registry.json`. Promotion is slower but its
authority and provenance are inspectable.
