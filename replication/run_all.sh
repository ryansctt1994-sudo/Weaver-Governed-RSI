#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
failed=0
indeterminate=0
artifact_mutation=0

if [[ ! -f "$repo_root/PAYLOAD_MANIFEST.sha256" ]]; then
  echo "FAIL: PAYLOAD_MANIFEST.sha256 missing" >&2
  failed=1
else
  python "$repo_root/release/verify_release.py" \
    --root "$repo_root" \
    --manifest "$repo_root/PAYLOAD_MANIFEST.sha256" \
    --require-complete \
    --exclude PAYLOAD_MANIFEST.sha256
  verify_exit=$?
  if [[ $verify_exit -eq 1 ]]; then
    failed=1
  elif [[ $verify_exit -eq 3 ]]; then
    indeterminate=1
  elif [[ $verify_exit -ne 0 ]]; then
    failed=1
  fi
fi

python "$repo_root/validation/integrity_wrapper.py" \
  --root "$repo_root" \
  -- python -m pytest validation tests
test_exit=$?
if [[ $test_exit -eq 1 ]]; then
  failed=1
elif [[ $test_exit -eq 3 ]]; then
  indeterminate=1
elif [[ $test_exit -eq 4 ]]; then
  artifact_mutation=1
elif [[ $test_exit -ne 0 ]]; then
  failed=1
fi

if [[ $failed -eq 1 ]]; then
  echo "REPLICATION RESULT: FAIL"
  exit 1
fi
if [[ $artifact_mutation -eq 1 ]]; then
  echo "REPLICATION RESULT: INDETERMINATE_ARTIFACT_MUTATION"
  exit 4
fi
if [[ $indeterminate -eq 1 ]]; then
  echo "REPLICATION RESULT: INDETERMINATE"
  exit 3
fi
echo "REPLICATION RESULT: PASS"
