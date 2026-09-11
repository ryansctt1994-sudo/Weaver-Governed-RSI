# Validation boundary

Validation attempts to falsify the governed runtime. It may emit test results and receipts;
it may not authorize application, change a trust root, or assign an evidence tier.

Suites are separated by purpose:

- `unit/`: isolated behavior;
- `integration/`: multi-component flows;
- `adversarial/`: constitutional, cryptographic, replay, and filesystem attacks;
- `properties/`: state-space and invariant properties;
- `concurrency/`: serialization and revocation races;
- `mutation/`: mutation policy and survivor tracking;
- `fixtures/`: inert, documented test inputs.

## Exit semantics

- `0`: checks completed and passed for the identified artifact;
- `1`: a known check or invariant failed;
- `3`: instrument, environment, or artifact identity was indeterminate.

These exits are test outcomes, not evidence tiers.
