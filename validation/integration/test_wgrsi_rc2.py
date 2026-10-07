"""Tests for WGRSI-RC2 evaluator trust-domain boundaries."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.rc2_evaluator_worker import canonical_json, evaluate
from experiments.rc2_receipts import verify_receipt


def signed_receipt() -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    body = evaluate(
        {"token": "sealed-token", "score": 0.61},
        {"expected_token": "sealed-token", "baseline_score": 0.50},
    )
    return {
        "schema": "wgrsi-rc2-evaluation-receipt-1",
        "body": body,
        "public_key_b64": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "signature_b64": base64.b64encode(key.sign(canonical_json(body))).decode(),
    }


def test_valid_signed_receipt_verifies() -> None:
    assert verify_receipt(signed_receipt())


def test_receipt_body_tamper_is_detected() -> None:
    receipt = signed_receipt()
    original_body = receipt["body"]
    assert isinstance(original_body, dict)
    body = dict(original_body)
    body["score"] = 0.99
    receipt["body"] = body
    assert not verify_receipt(receipt)


def test_signature_tamper_is_detected() -> None:
    receipt = signed_receipt()
    receipt["signature_b64"] = base64.b64encode(b"bad-signature").decode()
    assert not verify_receipt(receipt)


def test_hidden_probe_forces_failure() -> None:
    result = evaluate(
        {"token": "sealed-token", "score": 0.90, "attempted_hidden_probe": True},
        {"expected_token": "sealed-token", "baseline_score": 0.50},
    )
    assert result["verdict"] == "FAIL"
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert "HIDDEN_EVAL_PROBE" in reasons


def test_evaluator_tamper_forces_failure() -> None:
    result = evaluate(
        {"token": "sealed-token", "score": 0.90, "attempted_evaluator_tamper": True},
        {"expected_token": "sealed-token", "baseline_score": 0.50},
    )
    assert result["verdict"] == "FAIL"
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert "EVALUATOR_TAMPERING" in reasons


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1.0, 1.1, True, "0.9", None])
def test_invalid_candidate_score_is_refused(score: object) -> None:
    with pytest.raises(ValueError):
        evaluate(
            {"token": "sealed-token", "score": score},
            {"expected_token": "sealed-token", "baseline_score": 0.50},
        )


@pytest.mark.parametrize("score", [float("nan"), float("inf"), True, None])
def test_invalid_baseline_is_refused(score: object) -> None:
    with pytest.raises(ValueError):
        evaluate(
            {"token": "sealed-token", "score": 0.90},
            {"expected_token": "sealed-token", "baseline_score": score},
        )


@pytest.mark.parametrize("name", ["", "--root", "user name", "a;touch", "../user"])
def test_isolation_usernames_cannot_inject_options(name: str) -> None:
    from experiments.run_wgrsi_rc2_isolation import ensure_user

    with pytest.raises(ValueError, match="username"):
        ensure_user(name)
