#!/usr/bin/env bash
set -euo pipefail

umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

case "${1:-}" in
  "")
    full=0
    ;;
  --full)
    full=1
    ;;
  *)
    echo "usage: $0 [--full]" >&2
    exit 2
    ;;
esac

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-ps-artifact.XXXXXX")"
cleanup() {
  if [[ "$work_dir" == "${TMPDIR:-/tmp}/chio-ps-artifact."* ]]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT

# The Lean archive is rebuilt from the committed tarball first so that a stale
# manifest still leaves an independently checked proof archive behind.
python3 - "$work_dir" <<'PY'
from pathlib import Path
import sys
import tarfile

destination = Path(sys.argv[1]).resolve()
archive_path = Path(
    "docs/papers/programmable-sovereignty/supplementary/lean-source.tar.gz"
)
with tarfile.open(archive_path, "r:gz") as archive:
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if destination not in target.parents and target != destination:
            raise SystemExit(f"unsafe archive member: {member.name}")
        if member.issym() or member.islnk():
            raise SystemExit(f"archive links are not permitted: {member.name}")
    archive.extractall(destination, filter="data")
PY

(
  cd "$work_dir/chio-lean"
  lake build
)

python3 scripts/generate-programmable-sovereignty-artifact.py --check

if [[ "$full" -eq 1 ]]; then
  result_dir="$work_dir/results"
  target_dir="$work_dir/cargo-target"
  private_tmp="$work_dir/tmp"
  mkdir -m 700 "$private_tmp"
  export TMPDIR="$private_tmp"

  ./scripts/check-formal-proofs.sh
  # PS-T01 through PS-T09 from the artifact manifest's behavioral tests.
  cargo test -p chio-formal-diff-tests
  cargo test -p chio-runtime-core --test runtime_treaty
  cargo test -p chio-runtime-core --test runtime_admission
  cargo test -p chio-runtime-core --test runtime_buyer_review
  cargo test -p chio-runtime-harness
  cargo test -p chio-federation
  bash scripts/check-chio-live-treaty-buyer-closure.sh
  cargo test -p chio-kernel -- federation_cosign chio_runtime durable_admission
  cargo test -p chio-conformance \
    --test c2_bilateral_invocation_partial_verifier \
    --test b4_bilateral_dsse_signature_slice \
    --test b4_bilateral_dsse_pae_conformance
  CHIO_PAPER_RESULT_DIR="$result_dir/bilateral" \
    CHIO_TARGET_DIR="$target_dir" \
    bash docs/papers/programmable-sovereignty/bench/run-bilateral-admission.sh
  CHIO_PAPER_RESULT_DIR="$result_dir/replay" \
    CHIO_TARGET_DIR="$target_dir" \
    bash docs/papers/programmable-sovereignty/bench/run-replay-corpus.sh
  paper_build_dir="$work_dir/paper"
  cp -a docs/papers/programmable-sovereignty "$paper_build_dir"
  make -C "$paper_build_dir" submit-check
  python3 scripts/generate-programmable-sovereignty-artifact.py --check
fi

echo "programmable sovereignty artifact check passed"
