#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <repository-root> <output-directory>" >&2
  exit 2
fi

repo_root="$(cd "$1" && pwd -P)"
output_dir="$2"

if [[ -e "$output_dir" ]]; then
  echo "refusing to overwrite existing output: $output_dir" >&2
  exit 1
fi

git -C "$repo_root" diff --quiet --ignore-submodules -- || {
  echo "dirty tracked tree" >&2
  exit 1
}

if [[ -n "$(git -C "$repo_root" ls-files --others --exclude-standard)" ]]; then
  echo "untracked files present" >&2
  exit 1
fi

mkdir -p "$output_dir"
source_date_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH="$source_date_epoch"

git -C "$repo_root" archive \
  --format=tar.gz \
  --prefix=weaver-governed-rsi/ \
  --output="$output_dir/source.tar.gz" \
  HEAD

git -C "$repo_root" archive \
  --format=tar.gz \
  --prefix=weaver-replication-kit/ \
  --output="$output_dir/replication-kit.tar.gz" \
  HEAD

extraction_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$extraction_root"
}
trap cleanup EXIT
tar -xzf "$output_dir/source.tar.gz" -C "$extraction_root"
python "$repo_root/release/generate_manifest.py" \
  --root "$extraction_root/weaver-governed-rsi" \
  --output "$output_dir/PAYLOAD_MANIFEST.sha256"
python "$repo_root/release/verify_release.py" \
  --root "$extraction_root/weaver-governed-rsi" \
  --manifest "$output_dir/PAYLOAD_MANIFEST.sha256" \
  --require-complete

cp "$repo_root/replication/README_replication.md" "$output_dir/README_replication.md"
echo "unsigned release candidate written to $output_dir"
echo "generate BUNDLE_MANIFEST.sha256 and sign it only in the controlled signing environment"
