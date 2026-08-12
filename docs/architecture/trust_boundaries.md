# Trust boundaries

## Boundary rules

1. **Proposal boundary:** untrusted capability output becomes inert structured data.
2. **Governance boundary:** only registered actors may request state transitions.
3. **Validation boundary:** validation may emit a verdict but cannot apply a change.
4. **Ratification boundary:** a ratifier must be distinct from the proposer and validator.
5. **Evidence boundary:** evaluation is separated from production and CI.
6. **Release boundary:** exact tested payload bytes are bound to shipped bundle bytes.
7. **Replication boundary:** replicator identity and environment are external inputs, not
   producer-controlled assertions.

## Trusted computing base

The intentionally small trusted core consists of:

- `constitution/invariants.yaml`;
- `kernel/authority_registry.py`;
- `kernel/recursion_firewall.py`;
- `kernel/state_machine.py`;
- `kernel/verifier.py` and `kernel/trust_root.py`;
- `validation/evidence_registry.py`;
- release manifest and signature verification.

Everything else is treated as an input, test instrument, packaging helper, or research
surface. A small trusted core reduces review surface but does not make it formally verified.
