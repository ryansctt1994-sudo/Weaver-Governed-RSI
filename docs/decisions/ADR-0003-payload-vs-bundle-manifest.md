# ADR-0003: Payload and bundle manifests

- Status: Accepted
- Date: 2026-08-12

## Context

A manifest included inside the object it describes creates a self-reference problem. One
manifest also fails to distinguish tested source bytes from release metadata added later.

## Decision

Generate `PAYLOAD_MANIFEST.sha256` over the approved payload. Build the release bundle, then
generate `BUNDLE_MANIFEST.sha256` over all distributable files except the bundle manifest and
its signature. Sign the bundle manifest with the maintainer key.

The bundle-manifest sequence is:

```bash
python release/generate_manifest.py \
  --root release-out \
  --output release-out/BUNDLE_MANIFEST.sha256 \
  --exclude BUNDLE_MANIFEST.sig
python release/sign_manifest.py \
  --manifest release-out/BUNDLE_MANIFEST.sha256 \
  --private-key /controlled/path/maintainer-private.pem \
  --output release-out/BUNDLE_MANIFEST.sig
python release/verify_release.py \
  --root release-out \
  --manifest release-out/BUNDLE_MANIFEST.sha256 \
  --require-complete \
  --exclude BUNDLE_MANIFEST.sig
```

## Consequences

The two identities are explicit and independently checkable. Build order and exclusion rules
must remain deterministic and tested.
