"""Linux trust-domain harness for WGRSI-RC2 evaluator isolation.

Creates distinct candidate/evaluator users when run with sufficient privilege,
proves the candidate user cannot read the hidden suite or signing key, then runs
the evaluator under the evaluator identity with candidate payload on stdin.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    # Commands are fixed harness argv; candidate JSON is sent only through stdin.
    return subprocess.run(  # noqa: S603  # nosec B603
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def require_linux_tools() -> None:
    if os.name != "posix" or shutil.which("runuser") is None:
        raise RuntimeError("RC2 isolation harness requires Linux runuser support")
    if os.geteuid() != 0:
        raise RuntimeError("RC2 isolation harness requires root privileges")


def ensure_user(name: str) -> None:
    if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name) is None:
        raise ValueError("invalid harness username")
    try:
        pwd.getpwnam(name)
        return
    except KeyError:
        pass
    result = run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"failed to create {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-user", default="wgrsi_candidate")
    parser.add_argument("--evaluator-user", default="wgrsi_evaluator")
    args = parser.parse_args()

    require_linux_tools()
    ensure_user(args.candidate_user)
    ensure_user(args.evaluator_user)
    candidate_user = pwd.getpwnam(args.candidate_user)
    evaluator = pwd.getpwnam(args.evaluator_user)
    if candidate_user.pw_uid == evaluator.pw_uid or 0 in (candidate_user.pw_uid, evaluator.pw_uid):
        raise RuntimeError("candidate and evaluator require distinct non-root UIDs")

    with tempfile.TemporaryDirectory(prefix="wgrsi-rc2-") as tmp:
        root = Path(tmp)
        # Both users must traverse the root; only the evaluator owns hidden/.
        root.chmod(0o711)
        hidden_dir = root / "hidden"
        hidden_dir.mkdir(mode=0o700)
        os.chown(hidden_dir, evaluator.pw_uid, evaluator.pw_gid)

        hidden = hidden_dir / "suite.json"
        key_path = hidden_dir / "evaluator.key"
        expected_token = secrets.token_hex(16)
        hidden.write_text(
            json.dumps({"expected_token": expected_token, "baseline_score": 0.50}),
            encoding="utf-8",
        )
        private_key = Ed25519PrivateKey.generate()
        key_path.write_text(private_key.private_bytes_raw().hex(), encoding="utf-8")
        for path in (hidden, key_path):
            os.chmod(path, 0o600)
            os.chown(path, evaluator.pw_uid, evaluator.pw_gid)

        candidate_probe = run(["runuser", "-u", args.candidate_user, "--", "cat", str(hidden)])
        if candidate_probe.returncode == 0:
            print(json.dumps({"status": "FAIL", "reason": "candidate-read-hidden-suite"}))
            return 1

        key_probe = run(["runuser", "-u", args.candidate_user, "--", "cat", str(key_path)])
        if key_probe.returncode == 0:
            print(json.dumps({"status": "FAIL", "reason": "candidate-read-signing-key"}))
            return 1

        candidate = json.dumps({"token": expected_token, "score": 0.61})
        # Hosted runner workspaces need not be traversable by the evaluator UID.
        # Copy only the public worker into the accessible harness directory.
        worker_path = root / "rc2_evaluator_worker.py"
        shutil.copyfile(Path(__file__).with_name("rc2_evaluator_worker.py"), worker_path)
        worker_path.chmod(0o444)
        result = run(
            [
                "runuser",
                "-u",
                args.evaluator_user,
                "--",
                sys.executable,
                str(worker_path),
                "--hidden-suite",
                str(hidden),
                "--signing-key",
                str(key_path),
            ],
            input_text=candidate,
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return 1

        receipt = json.loads(result.stdout)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "candidate_hidden_read_denied": True,
                    "candidate_key_read_denied": True,
                    "evaluator_uid": evaluator.pw_uid,
                    "receipt": receipt,
                },
                sort_keys=True,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
