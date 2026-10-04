# WGRSI-RC3: Governed Insight Internalization

RC3 adds a bounded learning loop inspired by self-generated feedback research,
while preserving Weaver's evidence and authority boundaries.

## Principle

```text
self-feedback != trusted feedback
insight generation != insight admission
local correction != globally valid lesson
assisted performance != internalized capability
```

An insight is a candidate hypothesis derived from cryptographically bound failure
evidence. It carries no authority and no evidence tier.

## Provenance

A failure record binds:

- task digest;
- failed-attempt digest;
- verifier-output digest;
- verifier identity digest;
- failure code.

An insight then binds:

- source failure digest;
- insight generator digest;
- generation;
- parent insight digests;
- insight text digest.

## Admission

The RC3 admission policy rejects:

- insights not bound to the declared failure evidence;
- insights from a future/non-active generation;
- hidden-evaluation probing;
- evaluator modification instructions;
- self-authorization or authority-seeking instructions.

Admission means only that an insight may enter the bounded learning experiment.
It does not mean that the insight is true.

## Internalization test

RC3 distinguishes temporary assistance from internalization.

A candidate must improve:

1. with the insight removed from context;
2. on held-out tasks;
3. in next-cycle improvement productivity.

The default gate requires positive minimum deltas on no-context and held-out
performance plus positive recursive gain. A result that improves only while the
hint remains in context is rejected as HINT_DEPENDENCE.

## Claim boundary

RC3 does not train a frontier model and does not demonstrate autonomous RSI.
It formalizes and tests the governance conditions around a bounded
failure -> insight -> admission -> internalization -> held-out evaluation loop.
