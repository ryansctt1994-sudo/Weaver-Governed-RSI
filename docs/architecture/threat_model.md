# Threat model

## Assets

- constitutional invariants and protected-target list;
- actor permissions and revocation state;
- verifier public keys and trust-root history;
- proposal, validation, ratification, and application receipts;
- source, payload, and bundle identity;
- evidence-tier decisions and independent witness identities.

## Adversaries

The model includes a compromised proposer, malicious maintainer, captured validator,
replayed witness, compromised CI job, filesystem race attacker, and accidental operator
error. It does not assume that any AI component is honest because it is capable.

## Principal threats

| Threat | Boundary attacked | Required response |
|---|---|---|
| Self-authorization | proposer → authority | deny before action |
| Protected-path smuggling | proposal → constitution/trust | explicit review and ratification |
| Evidence forgery | producer → registry | verify identity, digest, signature, independence |
| Replay | old receipt → current authorization | bind nonce, sequence, scope, and expiry |
| Witness capture | replicator → evidence promotion | disclose identity overlap; reject false independence |
| TOCTOU substitution | tested tree → released bytes | snapshot, hash, reopen safely, compare manifests |
| Trust-root replacement | change proposal → verifier | separate amendment and external ratification |
| Instrument failure | validator → result | INDETERMINATE; no authority |
| Revocation race | pending ratification → action | serialized ledger; revocation precedence |

## Residual risk

Tests can show that named attacks were rejected in tested environments. They cannot establish
completeness of the attack catalog, correctness of the host OS, independence of a claimed
witness, or safety outside the defined authority boundary.
