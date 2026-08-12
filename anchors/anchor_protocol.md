# Anchor protocol

Anchors prove that a digest was presented to an external service no later than a recorded
time. They do not prove that the underlying claim is true, independently produced, or safe.

An anchor record binds provider, artifact digest, provider proof, timestamp, and optional
verification URI. Verification remains offline-capable where the provider format allows it.

Private anchor credentials and keys must remain outside the repository and release bundle.
