# Critical mutation review

## Historical local candidate snapshot

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

## Review of the six survivors at eb82be9

Baseline source: `eb82be986bd30891a855e8d9726c7b9b04d4bed5`.
The fresh local Mutmut 3.7.0 baseline evaluated 548 mutants: 542 killed and six survived
(98.91%). The earlier 379/382 result above is historical, not the current denominator.

| Mutant | Actual change | Assessment and action |
|---|---|---|
| `kernel.ledger.x_canonical_json__mutmut_5` | `ensure_ascii=False` becomes `None` | Equivalent for the supported JSON inputs: both select the false branch. Retain as a visible survivor. |
| `kernel.ledger.x_canonical_json__mutmut_6` | `allow_nan=False` becomes `None` | Equivalent: both reject non-finite numbers. Retain as a visible survivor. |
| `kernel.ledger.x_canonical_json__mutmut_18` | `utf-8` becomes `UTF-8` | Same Python codec. Retain as a visible survivor. |
| `kernel.mgre_kernel.xǁGovernedKernelǁapply__mutmut_16` | Revocation error gains `XX` prefixes and suffixes | Diagnostic coverage gap. The prior regex matched a substring; anchor it and verify denied application leaves state and ledger unchanged. The mutation does not bypass the revocation guard. |
| `validation.evidence_registry.x_load_registry__mutmut_3` | Explicit UTF-8 decoding becomes locale-default decoding | Portability coverage gap. Exercise a registry with non-ASCII text under the C locale with Python UTF-8 mode disabled. |
| `validation.evidence_registry.x_load_registry__mutmut_5` | `utf-8` becomes `UTF-8` | Same Python codec. Retain as a visible survivor. |

The equivalence assessment uses Python's encoder branch behavior and codec resolution,
plus representative nested JSON, Unicode, scalar, and non-finite-number probes on the
pinned Python 3.12 environment. It is a scoped review, not a formal proof for arbitrary
encoders, custom objects, monkey-patched runtimes, or future Python implementations.

The registry regression uses a separate interpreter so it also works when the parent is in
UTF-8 mode. A negative control first confirms that default decoding rejects the fixture's
UTF-8 bytes in that process; the real registry loader must then recover the original text.
The mutation selection environment is inherited, so the subprocess exercises the selected
registry mutant during mutation testing. No mocked read or exact-call assertion is used.

No production code change was needed for these two gaps. The existing implementation
already specifies UTF-8 and emits the correct revocation diagnostic. The mutation target
set, verifier exclusion, score threshold, and evidence/authority posture are unchanged.

### Follow-up validation

- Full suite: 79 tests and 9 subtests passed on Python 3.12.
- Fresh full mutation campaign: 544 killed, four survived, 548 evaluated (99.27%).
- Both identified coverage-gap mutants returned exit code 1 (killed).
- The four remaining IDs are ledger `_5`, `_6`, `_18` and registry-loader `_5` above.
- The unchanged 75% mutation gate passed with no blocking execution statuses.
- Ruff lint/format, strict mypy (56 source files), compilation, and Bandit passed.

Reproduce with the hash-locked dependencies, then run:

```sh
python -m pytest validation tests -q
mutmut run
mutmut results
python validation/mutation/check_mutation_score.py --mutants-root mutants --minimum-score 75
```

Use a fresh mutation workspace when reproducing the full campaign. These results establish
the listed local checks only; they do not establish independent reproduction or security
of the complete system.
