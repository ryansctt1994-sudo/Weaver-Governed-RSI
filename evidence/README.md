# Evidence store

This directory records evidence state; it is not a badge generator.

## Rules

- Receipts and manifests are content-addressed and immutable after publication.
- Supersession creates a linked replacement; it does not overwrite history.
- Accepted claims identify artifact bytes, test definitions, environment, producer, evaluator,
  result, limitations, and receipt digest.
- Unverifiable or mutated material is quarantined and grants no authority.
- Private keys, secrets, credentials, and mutable local trust databases are forbidden.
- CI may upload candidate results but may not edit `registry.json` or assign a tier.

## Current state

The repository starts at E0 because the referenced historical E3 bytes and receipts have not
been imported. This is not a judgment that the prior claim is false; it is a statement that
the repository cannot yet evaluate it.

The project record names F-07, F-10, F-11, and F-12. Their descriptions are absent, so the
registry preserves only their identifiers and import gap. Meanings must come from canonical
source records, not reconstruction by a maintainer or AI agent.
