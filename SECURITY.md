# Security policy

## Supported versions

Only the current default branch and the latest signed research release are supported.

## Reporting

Do not open a public issue for a vulnerability that could enable authority escalation,
signature bypass, evidence forgery, trust-root replacement, release substitution, or secret
disclosure. Use GitHub's private vulnerability-reporting channel when it is enabled.

If private reporting is unavailable, contact the repository owner through the verified
contact method on the owner's GitHub profile. Do not include private keys, credentials,
personal data, or live exploit material in an unencrypted message.

Include:

- affected commit and file paths;
- preconditions and trust boundary crossed;
- minimal reproduction steps;
- expected and observed result;
- whether a private key, witness identity, or release artifact may be compromised;
- suggested containment, if known.

## Response semantics

Security results use three distinct states:

- **FAIL**: a known assertion or invariant is false;
- **INDETERMINATE**: the instrument, environment, or artifact identity prevents evaluation;
- **PASS**: the specified check completed against identified bytes.

Instrument failure and artifact mutation are never normalized into an ordinary passing or
failing test.

## Research-only warning

This repository is not approved for safety-critical or autonomous production use.
