from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import yaml

from evidence.payload import capture_payload_snapshot, compare_snapshots, git_changed_paths, payload_manifest_sha256


class MutationStatus(str, Enum):
    KILLED = "KILLED"
    SURVIVED = "SURVIVED"
    INDETERMINATE = "INDETERMINATE"
    CONTROL_PASS = "CONTROL_PASS"


class CampaignState(str, Enum):
    MUTATION_HARNESS_VALIDATED = "MUTATION_HARNESS_VALIDATED"
    INDETERMINATE_MUTATION_HARNESS = "INDETERMINATE_MUTATION_HARNESS"
    CAMPAIGN_COMPLETE = "CAMPAIGN_COMPLETE"
    CAMPAIGN_BLOCKED = "CAMPAIGN_BLOCKED"


@dataclass
class MutationResult:
    mutant_id: str
    severity: str
    affected_invariants: list[str]
    baseline_commit: str
    baseline_payload_manifest_sha256: str
    mutant_payload_manifest_sha256: str
    patch_sha256: str | None
    baseline_suite_exit_code: int | None
    targeted_tests: list[str]
    targeted_exit_code: int | None
    detecting_tests: list[str]
    detection_count: int
    independent_detection_families: list[str]
    status: MutationStatus
    killed: bool
    survived: bool
    integrity_ok: bool
    changed_paths: list[str]
    unexpected_changed_paths: list[str]
    survival_reason: str | None
    indeterminate_reason: str | None
    gap_registered: bool = False
    gap_id: str | None = None
    promotion_blocking: bool = False
    started_utc: str = ""
    completed_utc: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _family(nodeid: str) -> str:
    s = nodeid.lower()
    for needle, family in (
        ("symlink", "symlink_swap"),
        ("rename", "rename_replacement"),
        ("concurrent", "concurrent_race"),
        ("delete_recreate", "delete_recreate"),
        ("stale", "stale_authorization"),
        ("policy", "policy_context"),
        ("trust", "trust_context"),
    ):
        if needle in s:
            return family
    return "other"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class MutationRunner:
    def __init__(self, repo_root: Path, catalog_path: Path, reports_dir: Path) -> None:
        self.repo = repo_root.resolve()
        self.catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
        self.reports = reports_dir.resolve()
        self.reports.mkdir(parents=True, exist_ok=True)

    def _entry(self, mutant_id: str) -> dict:
        entry = self.catalog.get("controls", {}).get(mutant_id) or self.catalog.get("mutants", {}).get(mutant_id)
        if entry is None:
            raise KeyError(mutant_id)
        return entry

    def _commit(self) -> str:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

    def _clean(self) -> None:
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=self.repo, text=True).strip():
            raise RuntimeError("canonical repository must be clean")

    def _worktree(self) -> tuple[Path, Path]:
        parent = Path(tempfile.mkdtemp(prefix="weaver-mutation-"))
        wt = parent / "worktree"
        subprocess.check_call(["git", "worktree", "add", "--detach", str(wt), "HEAD"], cwd=self.repo, stdout=subprocess.DEVNULL)
        return parent, wt

    def _drop_worktree(self, parent: Path, wt: Path) -> None:
        subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=self.repo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(parent, ignore_errors=True)

    def _pytest(self, wt: Path, suites: list[str], out: Path) -> tuple[int, dict[str, str]]:
        if not suites:
            raise RuntimeError("no targeted suites configured")
        out.parent.mkdir(parents=True, exist_ok=True)
        p = subprocess.run([sys.executable, "-m", "pytest", *suites, f"--junitxml={out}", "-q"], cwd=wt, capture_output=True, text=True)
        if not out.exists():
            return p.returncode, {}
        root = ET.parse(out).getroot()
        results: dict[str, str] = {}
        for case in root.iter("testcase"):
            nodeid = f"{case.attrib.get('classname', '')}::{case.attrib.get('name', '')}"
            status = "PASSED"
            if case.find("failure") is not None:
                status = "FAILED"
            elif case.find("error") is not None:
                status = "ERROR"
            elif case.find("skipped") is not None:
                status = "SKIPPED"
            results[nodeid] = status
        return p.returncode, results

    @staticmethod
    def _detectors(expected: list[str], results: dict[str, str]) -> list[str]:
        tokens = [_norm(x) for x in expected]
        return sorted({node for node, status in results.items() if status == "FAILED" and any(t in _norm(node) for t in tokens)})

    @staticmethod
    def _expected_executed(expected: list[str], results: dict[str, str]) -> bool:
        if not expected:
            return bool(results)
        nodes = [_norm(n) for n in results]
        return all(any(_norm(e) in n for n in nodes) for e in expected)

    def _patch(self, wt: Path, rel: str | None) -> str | None:
        if rel is None:
            return None
        patch = self.repo / "mutation" / rel
        if not patch.exists():
            raise FileNotFoundError(patch)
        subprocess.check_call(["git", "apply", "--check", str(patch)], cwd=wt)
        subprocess.check_call(["git", "apply", str(patch)], cwd=wt)
        return _sha256_file(patch)

    def _emit_result(self, result: MutationResult) -> None:
        payload = asdict(result)
        payload["status"] = result.status.value
        (self.reports / f"{result.mutant_id}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def run_one(self, mutant_id: str) -> MutationResult:
        self._clean()
        entry = self._entry(mutant_id)
        started = _now()
        parent, wt = self._worktree()
        baseline_hash = mutant_hash = ""
        patch_hash = None
        baseline_exit = targeted_exit = None
        detecting: list[str] = []
        changed: list[str] = []
        unexpected: list[str] = []
        integrity_ok = execution_possible = True
        reason = survival = None

        try:
            baseline = capture_payload_snapshot(wt)
            baseline_hash = payload_manifest_sha256(baseline)
            suites = entry.get("expected_suites") or []
            baseline_exit, _ = self._pytest(wt, suites, wt / ".mutation_tmp" / "baseline.xml")
            if baseline_exit != 0 or compare_snapshots(baseline, capture_payload_snapshot(wt)):
                execution_possible = False
                reason = "baseline_failed_or_mutated"

            if mutant_id == "M00":
                status = MutationStatus.CONTROL_PASS if execution_possible else MutationStatus.INDETERMINATE
                mutant_hash = baseline_hash
            elif execution_possible:
                try:
                    patch_hash = self._patch(wt, entry.get("patch"))
                except Exception as exc:
                    execution_possible = integrity_ok = False
                    reason = f"patch_apply_failed:{type(exc).__name__}"

                if execution_possible:
                    changed = git_changed_paths(wt)
                    expected_changed = sorted(entry.get("expected_changed_paths") or [])
                    if expected_changed and changed != expected_changed:
                        unexpected = sorted(set(changed) ^ set(expected_changed))
                        execution_possible = integrity_ok = False
                        reason = "patch_changed_unexpected_paths"

                if execution_possible:
                    pre = capture_payload_snapshot(wt)
                    mutant_hash = payload_manifest_sha256(pre)
                    targeted_exit, results = self._pytest(wt, suites, wt / ".mutation_tmp" / "targeted.xml")
                    post = capture_payload_snapshot(wt)
                    unexpected.extend(compare_snapshots(pre, post))
                    if unexpected:
                        execution_possible = integrity_ok = False
                        reason = "artifact_mutation_during_mutation_test"

                    expected = entry.get("expected_tests") or []
                    if not self._expected_executed(expected, results):
                        execution_possible = False
                        reason = "expected_detector_not_executed"
                    detecting = self._detectors(expected, results)
                    if targeted_exit not in (0, 1):
                        execution_possible = False
                        reason = f"pytest_execution_error:{targeted_exit}"
                    elif targeted_exit == 1 and not detecting:
                        execution_possible = False
                        reason = "nonsemantic_test_failure"

                if not execution_possible or not integrity_ok:
                    status = MutationStatus.INDETERMINATE
                elif detecting:
                    status = MutationStatus.KILLED
                else:
                    status = MutationStatus.SURVIVED
                    survival = "relevant_tests_did_not_detect_mutant"
            else:
                status = MutationStatus.INDETERMINATE
        except Exception as exc:
            status = MutationStatus.INDETERMINATE
            integrity_ok = False
            reason = f"runner_exception:{type(exc).__name__}:{exc}"
        finally:
            self._drop_worktree(parent, wt)

        blocking = entry.get("severity") in {"critical", "high", "control"} and status in {MutationStatus.SURVIVED, MutationStatus.INDETERMINATE}
        result = MutationResult(
            mutant_id=mutant_id,
            severity=entry.get("severity", "unknown"),
            affected_invariants=entry.get("invariants", []),
            baseline_commit=self._commit(),
            baseline_payload_manifest_sha256=baseline_hash,
            mutant_payload_manifest_sha256=mutant_hash,
            patch_sha256=patch_hash,
            baseline_suite_exit_code=baseline_exit,
            targeted_tests=entry.get("expected_tests", []),
            targeted_exit_code=targeted_exit,
            detecting_tests=detecting,
            detection_count=len(detecting),
            independent_detection_families=sorted({_family(x) for x in detecting}),
            status=status,
            killed=status == MutationStatus.KILLED,
            survived=status == MutationStatus.SURVIVED,
            integrity_ok=integrity_ok,
            changed_paths=changed,
            unexpected_changed_paths=sorted(set(unexpected)),
            survival_reason=survival,
            indeterminate_reason=reason,
            promotion_blocking=blocking,
            started_utc=started,
            completed_utc=_now(),
        )
        self._emit_result(result)
        return result

    def _state(self, state: CampaignState, reason: str | None = None) -> None:
        record = {"schema_version": "weaver.mutation.campaign.v1", "state": state.value, "reason": reason, "utc": _now(), "baseline_commit": self._commit()}
        (self.reports / "campaign_state.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    def run_campaign_gate(self) -> bool:
        m00 = self.run_one("M00")
        if m00.status != MutationStatus.CONTROL_PASS:
            self._state(CampaignState.INDETERMINATE_MUTATION_HARNESS, f"M00:{m00.status.value}")
            return False
        mctl = self.run_one("MCTL-1")
        if mctl.status != MutationStatus.KILLED:
            self._state(CampaignState.INDETERMINATE_MUTATION_HARNESS, f"MCTL-1:{mctl.status.value}")
            return False
        self._state(CampaignState.MUTATION_HARNESS_VALIDATED)
        return True

    def run_vertical_slice(self) -> list[MutationResult]:
        if not self.run_campaign_gate():
            raise RuntimeError("mutation harness controls failed")
        results = [self.run_one("M01"), self.run_one("M06")]
        blockers = [r.mutant_id for r in results if r.status != MutationStatus.KILLED]
        summary = {
            "schema_version": "weaver.mutation.vertical-slice.v1",
            "baseline_commit": self._commit(),
            "controls": {"M00": "CONTROL_PASS", "MCTL-1": "KILLED"},
            "mutants": {r.mutant_id: r.status.value for r in results},
            "instrument_integrity": "VALID" if all(r.integrity_ok for r in results) else "VIOLATED",
            "promotion_blockers": blockers,
            "result": "VERTICAL_SLICE_PASS" if not blockers else "VERTICAL_SLICE_BLOCKED",
            "completed_utc": _now(),
        }
        (self.reports / "vertical_slice_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return results

    def run_campaign(self) -> list[MutationResult]:
        if not self.run_campaign_gate():
            raise RuntimeError("mutation campaign controls failed")
        results = [self.run_one(mid) for mid in self.catalog["mutants"]]
        blockers = [r.mutant_id for r in results if r.promotion_blocking]
        state = CampaignState.CAMPAIGN_BLOCKED if blockers else CampaignState.CAMPAIGN_COMPLETE
        summary = {
            "schema_version": "weaver.mutation.campaign.v1",
            "state": state.value,
            "baseline_commit": self._commit(),
            "total_mutants": len(results),
            "killed": sum(r.status == MutationStatus.KILLED for r in results),
            "survived": sum(r.status == MutationStatus.SURVIVED for r in results),
            "indeterminate": sum(r.status == MutationStatus.INDETERMINATE for r in results),
            "promotion_blockers": blockers,
            "completed_utc": _now(),
        }
        (self.reports / "campaign_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return results


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--catalog", type=Path, default=Path("mutation/catalog.yaml"))
    p.add_argument("--reports", type=Path, default=Path("mutation/reports"))
    p.add_argument("--vertical-slice", action="store_true")
    p.add_argument("--mutant")
    args = p.parse_args()
    repo = args.repo.resolve()
    runner = MutationRunner(repo, repo / args.catalog, repo / args.reports)
    if args.vertical_slice:
        runner.run_vertical_slice()
        return 0
    if args.mutant:
        result = runner.run_one(args.mutant)
        print(result.status.value)
        return 0 if result.status in {MutationStatus.KILLED, MutationStatus.CONTROL_PASS} else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
