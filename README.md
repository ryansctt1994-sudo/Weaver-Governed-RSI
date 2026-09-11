# WEAVER

## Governed Recursive Self-Improvement Research

Weaver Governed RSI is a research prototype for testing governance boundaries around
bounded recursive self-improvement.

The project investigates whether an AI system can propose improvements without acquiring
authority to approve changes to its own governance, verification, trust, or authorization
mechanisms.

It does **not** claim AGI, ASI, universal alignment, formal containment, or production safety.

> **Research question:** Can increasingly capable systems improve their behavior without
> inheriting authority over the mechanisms that govern, verify, and authorize those
> improvements?

## Constitutional invariants

- Capability ≠ Authority
- Proposal ≠ Action
- Self-Improvement ≠ Self-Authorization
- Evidence Generation ≠ Evidence Evaluation
- Uncertainty ≠ Authority

The machine-readable source is [`constitution/invariants.yaml`](constitution/invariants.yaml).

## Evidence status

| Scope | Ceiling | State |
|---|---:|---|
| This repository | **E0** | Initial scaffold; no historical receipts imported or accepted |
| Prior portfolio claim | **E3** | Declared outside this repository; pending byte-level import and registry review |
| Independent replication target | **E4** | Pending heterogeneous reproduction |
| Independent external review target | **E5** | Pending |

No source file, test suite, release artifact, maintainer, AI agent, or CI job may assign its
own evidence tier. CI emits results; the Evidence Registry evaluates promotion under
[`GOVERNANCE.md`](GOVERNANCE.md).

This distinction is deliberate. The repository will not convert a narrative status claim into
accepted evidence without the underlying bytes, manifests, receipts, identities, and review
record.

## Trust boundaries

| Area | Responsibility | Must not do |
|---|---|---|
| [`kernel/`](kernel/) | Governed runtime | Promote its own evidence or rewrite its trust root |
| [`validation/`](validation/) | Attempt to falsify the runtime | Authorize deployment or silently repair results |
| [`evidence/`](evidence/) | Record evaluated claims and receipts | Treat missing evidence as success |
| [`release/`](release/) | Bind tested payload bytes to shipped bundle bytes | Include private keys or mutable trust state |
| [`replication/`](replication/) | Independent reproduction interface | Reuse producer identity as replicator identity |

## Validation snapshot

Local candidate run (2026-08-12; not registry-accepted): **70 tests passed with 9
subtests**, and **379 of 382 mutants were killed (99.21%)**. The three survivors are
reviewed equivalent JSON-encoder substitutions documented in
[`validation/mutation/critical_mutants.md`](validation/mutation/critical_mutants.md). No
signed receipt has been accepted for this tree, so these counts do not promote the repository
above E0.

The initial baseline includes executable tests for:

- proposal/action separation and legal state transitions;
- self-authorization denial and protected-target review;
- producer/verifier Ed25519 separation;
- append-only, hash-chained ledger verification;
- deterministic replay;
- evidence producer/evaluator independence;
- release-manifest mutation and symlink rejection.

Run the repository-controlled checks:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
pytest
python release/generate_manifest.py --root . --output /tmp/PAYLOAD_MANIFEST.sha256
python release/verify_release.py \
  --root . \
  --manifest /tmp/PAYLOAD_MANIFEST.sha256 \
  --require-complete
```

Passing tests establish only what their assertions and environment support. They do not, by
themselves, promote the repository above E0.

## Repository map

```text
constitution/  human- and machine-readable invariants and ratification policy
kernel/        minimal governed runtime and trust primitives
schemas/       interoperable JSON contracts
validation/    unit, integration, adversarial, property, concurrency, and mutation surfaces
redteam/       attack catalog and constitutional red-team matrix
evidence/      registry, receipts, manifests, attestations, and quarantine
release/       deterministic manifests, signing, and release-integrity tooling
replication/   independent reproduction kit and receipt verifier
anchors/       optional external timestamp/anchor interface
tools/         inspection and comparison utilities
docs/          architecture, research notes, and decisions
```

## Known gaps

The supplied project record references findings **F-07**, **F-10**, **F-11**, and **F-12**,
but their canonical descriptions and source artifacts have not been imported. They remain
visible as unresolved records in [`evidence/registry.json`](evidence/registry.json); this
repository does not invent their meanings.

Other current gaps:

- no accepted historical MGRE receipt bundle in this repository;
- no external witness identity or independent replication receipt;
- no formal proof of containment or general alignment;
- no production deployment approval;
- no branch ruleset or independent CODEOWNER configured through repository settings yet.

## Release posture

The first supportable public milestone is:

> **Weaver Governed RSI — Initial Governance Kernel Candidate**

`v0.1.0-e3-baseline` is reserved until the historical E3 evidence bundle is imported and
accepted. A future E4 candidate may use a normal semantic version such as
`v0.3.0-e4-candidate`; an external attestation should use a separate immutable ref such as
`attestation/e4-a-arm64-YYYY-MM-DD`.

Release bundles may contain public keys, signed manifests, and replication material. They
must never contain producer, maintainer, anchor, or replicator private keys; credentials;
development `.env` files; or local trust-state databases.

## Security and participation

Read [`SECURITY.md`](SECURITY.md) before reporting a vulnerability and
[`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing changes. Governance-sensitive paths
receive stricter review under [`GOVERNANCE.md`](GOVERNANCE.md).

## License

MIT. See [`LICENSE`](LICENSE).
