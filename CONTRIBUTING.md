# Contributing

We welcome falsification attempts, reproducibility reports, narrow fixes, and clearly scoped
research proposals.

## Before opening a pull request

1. Open or reference an issue that states the claim or invariant affected.
2. Keep governance, validation, evidence evaluation, and release logic in their assigned
   trust domains.
3. Add a test that would fail without the change.
4. Run the unit and release-builder suites.
5. Identify any effect on protected targets, schemas, compatibility, evidence claims, or
   trust roots.
6. Do not include secrets, generated private keys, mutable local databases, or unverifiable
   receipts.

## Pull-request declarations

Every pull request must state:

- what changed and why;
- which invariant or research question it affects;
- validation performed;
- known gaps and untested assumptions;
- whether a protected target changed;
- whether the author generated any evidence being evaluated.

Passing CI is necessary but not sufficient for evidence promotion or release authorization.

## Commit style

Use small, reviewable commits with imperative subjects. Do not rewrite signed release tags or
external attestations.
