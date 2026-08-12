# Independent replication

This kit is for an independent operator attempting to reproduce a named release claim. A
successful local run does not become E4 until the Evidence Registry verifies artifact identity,
receipt signature, relationship disclosure, meaningful environmental heterogeneity, and raw
results.

## Clean-room procedure

1. Obtain the release bundle through an authenticated channel.
2. Verify `BUNDLE_MANIFEST.sig` with `maintainer_public.pem`.
3. Verify every file in `BUNDLE_MANIFEST.sha256`.
4. Extract `source.tar.gz` into a new directory or disposable VM.
5. Copy the verified `PAYLOAD_MANIFEST.sha256` beside the extracted source root. The manifest
   intentionally does not list itself.
6. Record OS, CPU architecture, Python runtime, dependencies, and source digest.
7. Generate a new Ed25519 replicator key locally. Never accept a private key from the producer.
8. Run `replication/run_all.sh` from the extracted source without modifying the payload.
9. Record exact argv, exit states, and hashes of stdout and stderr.
10. Fill and sign a replication receipt conforming to the JSON schema.
11. Submit the receipt, public key, raw logs, relationship disclosure, and deviations for
    Evidence Registry review.

## Result semantics

- A known failed assertion yields `FAIL`.
- Missing manifests or unverified artifact identity yield `FAIL` because package identity is
  required by the replication contract.
- Instrument/environment failure yields `INDETERMINATE`.
- Artifact mutation during validation yields `INDETERMINATE_ARTIFACT_MUTATION`.
- A known failure takes precedence over simultaneous indeterminacy in the aggregate result.

## Independence disclosure

State employment, contracting, funding, family, organizational, infrastructure, and key-
custody relationships with the producer. The registry—not the replicator—decides whether the
receipt supports an independent tier.
