# WGRSI-RC1: Governed Recursive Gain Experiment

## Purpose

WGRSI-RC1 is a bounded falsification experiment for recursive improvement under
external governance. It does not run autonomous model training and does not grant
a candidate any runtime authority.

The experiment distinguishes ordinary improvement from recursive gain:

- capability gain: the successor performs the bounded task better;
- recursive gain: the successor is measurably better at producing the next useful
  improvement;
- governance admissibility: the evaluator and retention gate remain outside the
  recursive proposer.

A candidate is admissible only when capability and recursive-gain deltas are both
positive beyond frozen thresholds, regression remains bounded, no security
violation is observed, and evaluator sufficiency passes.

## Core invariant

```text
improvement != evidence
evidence != authority
parent evidence != successor evidence
parent authority != successor authority
```

Every candidate successor is constructed at `E0` with `authority=NONE`.
Promotion is a separate evidence process.

## Sufficiency Lock

The evaluator publishes five bounded factors:

- coverage
- independence
- detection power
- latency margin
- uncertainty

The RC1 sufficiency score is deliberately conservative:

```text
S = min(coverage, independence, detection_power, latency_margin, 1 - uncertainty)
```

If the candidate otherwise qualifies but `S` is below the frozen threshold,
the verdict is `WITHHOLD`, not `ACCEPT`.

## Retention rule

A successor is accepted only when all of the following hold:

1. the candidate is a direct child of the active artifact;
2. generation increments exactly by one;
3. capability delta meets the frozen minimum;
4. recursive-gain delta meets the frozen minimum;
5. regression stays within the frozen limit;
6. no security violation is present;
7. the Sufficiency Lock passes.

Rejected and withheld candidates cannot mutate the active state.

## Receipts and rollback

Each accepted transition emits a hash-chained cycle receipt binding:

- parent artifact digest;
- candidate artifact digest;
- evaluator digest;
- hidden-evaluation digest;
- verdict and reasons;
- capability delta;
- recursive-gain delta;
- sufficiency score;
- previous receipt digest.

The best-state ledger admits only an `ACCEPT` decision and supports explicit
rollback to the prior accepted state.

## Required adversarial cases

RC1 should eventually exercise at least:

- evaluator tampering;
- hidden-evaluation substitution;
- parent substitution;
- successor evidence inheritance;
- successor authority inheritance;
- capability gain without recursive gain;
- insufficient evaluator independence;
- regression beyond threshold;
- receipt tamper;
- rollback after an accepted successor.

## Claim boundary

Passing RC1 would show that this bounded implementation can enforce its declared
recursive-gain and governance predicates under tested conditions.

It would **not** establish autonomous RSI, AGI/ASI safety, universal evaluator
independence, production readiness, or authority for a model to deploy changes.
External reproduction remains a separate evidence milestone.
