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
6. Record OS, CPU architecture, Python runtime, dependencies, and source digest. Use
   `python tools/environment_fingerprint.py --output /path/outside/artifact/environment.json`
   for the machine-captured environment fingerprint.
7. Generate a new Ed25519 replicator key locally. Never accept a private key from the producer.
8. Run `python replication/capture_run.py --evidence-dir /path/outside/artifact/evidence` from
   the extracted source without modifying the payload. The evidence directory is required to be
   outside the artifact root. The helper invokes `replication/run_all.sh` and writes
   `replication-run.json`, `replication.stdout.log`, and `replication.stderr.log`.
9. Preserve all three generated files. The JSON records the exact argv, exit code, and SHA-256
   hashes of stdout and stderr; the hashes identify the raw logs but do not replace them.
10. Fill and sign a replication receipt conforming to the JSON schema, copying only
    machine-captured fields from the generated evidence where applicable.
11. Submit the receipt, public key, environment capture, raw logs, relationship disclosure, and
    deviations for Evidence Registry review.

## Result semantics

- A known failed assertion yields `FAIL` and exit code `1`.
- Missing manifests or unverified artifact identity yield `FAIL` because package identity is
  required by the replication contract.
- Instrument/environment failure yields `INDETERMINATE` and exit code `3`.
- Artifact mutation during validation yields `INDETERMINATE_ARTIFACT_MUTATION` and exit code `4`.
- A known failure takes precedence over simultaneous indeterminacy in the aggregate result.
- Unknown nonzero runner exits are treated as `FAIL`; they must not be silently promoted to an
  indeterminate or passing result.

## Independence disclosure

State employment, contracting, funding, family, organizational, infrastructure, and key-
custody relationships with the producer. The registry—not the replicator—decides whether the
receipt supports an independent tier.

The producer must not supply the replicator private key, pre-filled relationship disclosure,
replicator identity, or a replacement raw log set. Shared infrastructure, shared credentials,
producer-operated execution, or undisclosed material relationships must be reported as
deviations and evaluated before any independent evidence tier is considered.
