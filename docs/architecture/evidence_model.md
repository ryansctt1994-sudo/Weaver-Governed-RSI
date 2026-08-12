# Evidence model

## Executable claim tuple

The current registry evaluator binds:

```text
(claim_id, artifact_digest, receipt_digest, environment_fingerprint,
 producer_identity, evaluator_identity, target_tier, result,
 independence_assertion, heterogeneity_assertion)
```

If an artifact, receipt, or environment identity is absent, evaluation is indeterminate.
The signed receipt should additionally bind the test-definition digest, limitations, and
observation time. The registry does not yet enforce those three receipt fields; that is a
published limitation rather than an implied guarantee.

## Results

- `PASS`: the stated test completed against the identified artifact.
- `FAIL`: the stated assertion is known false for the identified artifact.
- `INDETERMINATE`: the test cannot establish pass or fail.

Pass is local to a claim. It is not proof of global safety. Fail takes precedence over
indeterminacy when both a known invariant failure and an instrument problem are present.

## Promotion

Promotion is a registry decision, not a test output. The registry verifies tier prerequisites,
producer/evaluator separation, artifact identity, receipt signatures, and unresolved blocking
findings. E4 additionally requires an independent heterogeneous reproducer.

## Storage

Receipts are append-only artifacts. Superseding a receipt creates a new receipt that links to
the prior digest; it does not overwrite history. Unverifiable material belongs in
`evidence/quarantined/` and cannot authorize promotion.
