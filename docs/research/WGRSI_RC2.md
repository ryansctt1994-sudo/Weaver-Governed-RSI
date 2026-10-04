# WGRSI-RC2: Evaluator Isolation

RC2 upgrades evaluator independence from a logical role distinction to a tested
Linux trust-domain boundary.

## Trust domains

- **Candidate domain**: may submit only candidate JSON.
- **Evaluator domain**: owns the hidden suite and Ed25519 signing key.
- **Retention domain**: verifies the signed evaluator receipt before using it.

The CI isolation harness creates distinct Unix users and places the hidden suite
and evaluator key in an evaluator-owned directory. The candidate identity must
fail to read both files before evaluation is allowed to proceed.

## Data flow

```text
candidate process
    |
    | candidate JSON on stdin
    v
evaluator process (different uid)
    |
    | reads hidden suite + signing key
    v
signed evaluation receipt
    |
    v
retention verifier
```

No hidden-suite path or evaluator private key is included in the candidate
payload.

## Receipt

The evaluator signs the canonical result body using Ed25519. The result binds:

- candidate payload digest;
- hidden-evaluation digest;
- observed score;
- frozen baseline score;
- PASS/FAIL verdict;
- explicit failure reasons.

Receipt verification detects both body and signature tampering.

## Adversarial cases exercised

- candidate read access to hidden suite -> must fail;
- candidate read access to signing key -> must fail;
- hidden-evaluation probe signal -> FAIL;
- evaluator-tampering signal -> FAIL;
- receipt body tamper -> verification failure;
- receipt signature tamper -> verification failure.

## Boundary

RC2 establishes process/user separation on the tested Linux host. It does not
claim kernel/hypervisor independence, remote-machine independence, resistance to
a compromised root account, or independent external reproduction.

The candidate still does not receive evidence or authority from an accepted
result. Evaluation is evidence input, not authority.
