# Critical mutation review

## Local candidate snapshot

- Run date: 2026-08-12
- Tool: Mutmut 3.7.0
- Result: 379 killed, 3 survived, 99.21% mutation score
- Policy gate: PASS (75% minimum; no blocking execution statuses)

This is a local candidate validation result. It is not an Evidence Registry promotion and
does not raise the repository evidence ceiling above E0.

All mutants that removed or altered authority checks, separation-of-duty checks, revocation
precedence, replay validation, artifact identity checks, deny-by-default transitions, or
evidence-promotion semantics were killed.

## Reviewed equivalent survivors

The three surviving mutants are non-semantic substitutions in `canonical_json`:

- `ensure_ascii=False` to `ensure_ascii=None`: both are falsey and emit the same UTF-8 JSON.
- `allow_nan=False` to `allow_nan=None`: both reject non-finite numeric values.
- `encode("utf-8")` to `encode("UTF-8")`: Python resolves both names to the same codec.

These substitutions do not change serialized bytes or acceptance behavior for the supported
inputs. They are retained in the report rather than hidden or marked as killed.

## Instrumentation limitation

`kernel/verifier.py` is excluded from Mutmut 3.7.0 because its trampoline fails the baseline
on `cryptography.exceptions.InvalidSignature`. The verifier remains covered by direct
mutation-equivalent adversarial cases for wrong keys, payload substitution, and malformed
base64. This exclusion is a known gap, not a waiver of cryptographic validation.

Any future surviving mutant that removes or reverses a permission check, self-authorization
guard, signature check, artifact digest comparison, revocation precedence rule, or
indeterminate result must be recorded here and treated as release-blocking until killed or
explicitly accepted with reasoning.
