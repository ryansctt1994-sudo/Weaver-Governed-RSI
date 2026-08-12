# Constitutional Red-Team Matrix

The matrix maps named attacks to invariants and executable tests. A passing row means the
specific test rejected the specific fixture; it is not a completeness claim.

| ID | Attack | Invariant | Expected result | Test surface |
|---|---|---|---|---|
| CRT-01 | proposer requests its own permissions | I-03 | blocked before validation | `test_mgre_a1_a8.py` |
| CRT-02 | undeclared constitution change | I-03 | blocked | `test_mgre_adversarial.py` |
| CRT-03 | proposer acts as validator | I-04 | authority denied | `test_mgre_a1_a8.py` |
| CRT-04 | validator acts as ratifier | I-04 | authority denied | `test_mgre_a1_a8.py` |
| CRT-05 | post-validation payload substitution | I-07 | indeterminate, no apply | `test_mgre_adversarial.py` |
| CRT-06 | malformed or wrong-key signature | I-07 | invalid | `test_crypto_adversarial.py` |
| CRT-07 | ledger event replay/reordering | I-07 | verification or replay failure | `test_mgre_adversarial.py` |
| CRT-08 | revocation before application | I-06 | application denied | `test_revocation_races.py` |
| CRT-09 | producer evaluates E3 claim | I-04 | promotion rejected | `test_crt_matrix.py` |
| CRT-10 | E4 without heterogeneous witness | I-05 | indeterminate | `test_crt_matrix.py` |
| CRT-11 | symlink substitution during release | I-07 | build rejected | `test_filesystem_toctou.py` |
| CRT-12 | validation mutates artifact | I-05/I-07 | indeterminate mutation | `test_payload_mutation.py` |
