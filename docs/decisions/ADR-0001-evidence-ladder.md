# ADR-0001: Evidence ladder

- Status: Accepted
- Date: 2026-08-12

## Context

Test results, same-author reproduction, heterogeneous replication, and external review provide
different strengths of support. A single green status would erase those differences.

## Decision

Use E0–E5 as defined in `GOVERNANCE.md`. Promotion is performed only by the Evidence Registry
after tier prerequisites are evaluated. CI and artifacts may report results but never a tier.

## Consequences

Status is conservative and may remain below a portfolio narrative until source evidence is
imported. Evidence claims become auditable and gaps remain visible.
