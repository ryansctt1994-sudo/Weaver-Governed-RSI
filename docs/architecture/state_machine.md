# Proposal state machine

```mermaid
stateDiagram-v2
    [*] --> DRAFT
    DRAFT --> SUBMITTED: submit
    SUBMITTED --> VALIDATED: validation_pass
    SUBMITTED --> REJECTED: validation_fail
    SUBMITTED --> INDETERMINATE: instrument_or_identity_error
    VALIDATED --> RATIFIED: ratify
    VALIDATED --> REJECTED: reject
    RATIFIED --> APPLIED: apply
    RATIFIED --> REJECTED: revoke
    REJECTED --> [*]
    INDETERMINATE --> [*]
    APPLIED --> [*]
```

Terminal states cannot transition. A new proposal is required after rejection,
indeterminacy, application, or any material change to the proposed bytes.

The implementation denies all transitions not explicitly listed. Actor permission,
separation-of-duty, protected-target, and revocation checks are additional guards around this
graph.
