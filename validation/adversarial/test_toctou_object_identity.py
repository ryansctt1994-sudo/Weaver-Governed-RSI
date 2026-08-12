from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable

import pytest

from governance.mutation_transaction import MutationTransaction
from identity.model import IdentityVerdict


DENIAL_STATES = {
    "REJECTED_OBJECT_IDENTITY_CHANGED",
    "INDETERMINATE_OBJECT_IDENTITY",
    "REJECTED_PROTECTED_OBJECT_ALIAS",
}


def test_crt_k12_unchanged_object_is_allowed(
    transaction_factory: Callable[[Path], MutationTransaction],
    safe_file: Path,
) -> None:
    tx = transaction_factory(safe_file)
    tx.authorize(safe_file)
    tx.stage()
    assert tx.commit() == "EXECUTED"


def test_crt_k2_delete_recreate_same_bytes_is_changed(
    identity_capture,
    identity_policy,
    tmp_path: Path,
) -> None:
    target = tmp_path / "safe.py"
    target.write_bytes(b"same bytes")
    hold_fd = os.open(target, os.O_RDONLY)
    try:
        before = identity_capture.capture(target, relative_to=tmp_path)
        target.unlink()
        target.write_bytes(b"same bytes")
        after = identity_capture.capture(target, relative_to=tmp_path)
        assert before.content_sha256 == after.content_sha256
        assert identity_policy.equivalent(before, after) is IdentityVerdict.CHANGED
        assert before.file_id != after.file_id
    finally:
        os.close(hold_fd)


def test_crt_k10_delete_recreate_at_transaction_level(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    target = tmp_path / "safe.py"
    target.write_bytes(b"payload")
    tx = transaction_factory(target)
    tx.authorize(target)
    target.unlink()
    target.write_bytes(b"payload")
    tx.stage()
    assert tx.commit() in DENIAL_STATES


def test_crt_k1_symlink_swap_after_authorization_is_denied(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    safe = tmp_path / "harmless.py"
    protected = tmp_path / "constitution.py"
    safe.write_text("benign", encoding="utf-8")
    protected.write_text("IMMUTABLE", encoding="utf-8")
    original = protected.read_bytes()

    tx = transaction_factory(safe)
    tx.authorize(safe)
    safe.unlink()
    safe.symlink_to(protected)
    tx.stage()
    terminal = tx.commit()

    assert terminal in DENIAL_STATES
    assert protected.read_bytes() == original
    assert tx.authority_delta <= 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link semantics")
def test_crt_k3_hardlink_alias_does_not_launder_protected_identity(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    protected = tmp_path / "constitution.py"
    alias = tmp_path / "harmless.py"
    protected.write_text("IMMUTABLE", encoding="utf-8")
    os.link(protected, alias)
    original = protected.read_bytes()

    tx = transaction_factory(alias)
    terminal = tx.authorize_and_attempt()
    assert terminal == "REJECTED_PROTECTED_OBJECT_ALIAS"
    assert protected.read_bytes() == original
    assert tx.authority_delta <= 0


def test_crt_k4_parent_directory_swap_is_denied(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    safe_dir = root / "safe"
    replacement = root / "replacement"
    safe_dir.mkdir(parents=True)
    replacement.mkdir()
    target = safe_dir / "policy.py"
    target.write_text("safe", encoding="utf-8")
    replacement_target = replacement / "policy.py"
    replacement_target.write_text("protected", encoding="utf-8")

    tx = transaction_factory(target)
    tx.authorize(target)
    old_dir = root / "old-safe"
    safe_dir.rename(old_dir)
    replacement.rename(safe_dir)
    tx.stage()
    terminal = tx.commit()

    assert terminal in DENIAL_STATES
    assert (safe_dir / "policy.py").read_text(encoding="utf-8") == "protected"


@pytest.mark.skip(reason="Requires isolated mount namespace/capability; report as UNAVAILABLE")
def test_crt_k5_bind_mount_substitution_is_denied() -> None:
    pass


def test_crt_k6_atomic_rename_exchange_is_denied(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    safe = tmp_path / "safe.py"
    attacker = tmp_path / "attacker.py"
    safe.write_text("benign", encoding="utf-8")
    attacker.write_text("evil", encoding="utf-8")

    tx = transaction_factory(safe)
    tx.authorize(safe)
    os.replace(attacker, safe)
    tx.stage()
    assert tx.commit() in DENIAL_STATES
    assert safe.read_text(encoding="utf-8") == "evil"


def test_crt_k9_permission_change_is_denied_when_mode_protected(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    target = tmp_path / "safe.py"
    target.write_text("benign", encoding="utf-8")
    target.chmod(0o644)
    tx = transaction_factory(target)
    tx.authorize(target)
    target.chmod(0o600)
    tx.stage()
    assert tx.commit() in DENIAL_STATES


@pytest.mark.slow
@pytest.mark.parametrize("delay_point", ["after_authorize", "after_stage", "before_commit"])
def test_crt_k11_concurrent_swap_race_never_mutates_protected_object(
    transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
    delay_point: str,
) -> None:
    safe = tmp_path / "safe.py"
    protected = tmp_path / "constitution.py"
    alternate = tmp_path / "alternate.py"
    safe.write_text("benign", encoding="utf-8")
    protected.write_text("IMMUTABLE", encoding="utf-8")
    alternate.write_text("attacker", encoding="utf-8")
    original = protected.read_bytes()
    stop = threading.Event()

    def attacker() -> None:
        while not stop.is_set():
            try:
                safe.unlink(missing_ok=True)
                safe.symlink_to(protected)
                safe.unlink(missing_ok=True)
                safe.write_text("benign", encoding="utf-8")
                safe.unlink(missing_ok=True)
                safe.symlink_to(alternate)
                safe.unlink(missing_ok=True)
                safe.write_text("benign", encoding="utf-8")
            except OSError:
                pass

    thread = threading.Thread(target=attacker, daemon=True)
    thread.start()
    iterations = int(os.environ.get("WEAVER_RACE_ITERATIONS", "1000"))

    try:
        for _ in range(iterations):
            tx = transaction_factory(safe)
            terminal = "INDETERMINATE_OBJECT_IDENTITY"
            try:
                tx.authorize(safe)
                if delay_point == "after_authorize":
                    time.sleep(0.0001)
                tx.stage()
                if delay_point == "after_stage":
                    time.sleep(0.0001)
                if delay_point == "before_commit":
                    time.sleep(0.0001)
                terminal = tx.commit()
            except (PermissionError, RuntimeError, ValueError, OSError):
                terminal = tx.terminal_state
            finally:
                tx.close()

            assert protected.read_bytes() == original
            if terminal != "EXECUTED":
                assert tx.authority_delta <= 0
    finally:
        stop.set()
        thread.join(timeout=2)


def test_descriptor_binding_does_not_redirect_after_path_replacement(
    descriptor_transaction_factory: Callable[[Path], MutationTransaction],
    tmp_path: Path,
) -> None:
    target = tmp_path / "safe.py"
    replacement = tmp_path / "replacement.py"
    target.write_text("original", encoding="utf-8")
    replacement.write_text("attacker", encoding="utf-8")

    tx = descriptor_transaction_factory(target)
    tx.authorize(target)
    target.unlink()
    replacement.rename(target)
    tx.stage()
    terminal = tx.commit()

    assert terminal in DENIAL_STATES
    assert target.read_text(encoding="utf-8") == "attacker"
