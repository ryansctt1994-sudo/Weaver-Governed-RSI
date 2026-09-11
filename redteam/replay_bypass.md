# Replay-bypass attacks

Attempt duplicate proposal IDs, reordered ledger records, reused signatures under new scope,
stale ratification after content change, and duplicated replication receipts.

The baseline binds proposal content to a digest and ledger position to a previous hash. Future
networked implementations also need nonces, expiry, clock policy, and globally serialized
revocation semantics.
