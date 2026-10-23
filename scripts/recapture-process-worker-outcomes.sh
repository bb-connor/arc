#!/usr/bin/env bash
# Recapture the retained native process-worker outcome fixtures in
# crates/products/chio-cli/tests/fixtures/process-worker-outcomes from a real
# native campaign run.
#
# Host: a Linux x86_64 qualification host with a native cage (chio-cage-init
# must initialise for real) and Docker. Every input is a required flag; the
# script reads no defaults from the environment.
#
# Usage:
#   scripts/recapture-process-worker-outcomes.sh \
#     --bin-dir DIR            directory holding chio, chio-cage-init and
#                              enforcement-probe built from this checkout
#     --worker-image ID        image id built from
#                              examples/reference-swarm/ProcessWorker.Dockerfile
#     --work-dir DIR           empty directory for campaign output
#     --anchor-root DIR        empty tmpfs directory for receipt rollback anchors
#
# The outcome artifacts are kernel receipts signed under chio.receipt.v1; the
# swarm, launch-policy and native launch artifacts they carry are signed under
# their own registered wrapper ids. Afterwards run
#   cargo test -p chio-cli --lib process_host::call_evidence::outcomes_native
set -euo pipefail

usage() {
  sed -n '9,18p' "$0" >&2
  exit 2
}

bin_dir=""
worker_image=""
work_dir=""
anchor_root=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) bin_dir="${2:?}"; shift 2 ;;
    --worker-image) worker_image="${2:?}"; shift 2 ;;
    --work-dir) work_dir="${2:?}"; shift 2 ;;
    --anchor-root) anchor_root="${2:?}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$bin_dir" && -n "$worker_image" && -n "$work_dir" && -n "$anchor_root" ]] || usage

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(git -C "$root" rev-parse --show-toplevel)" == "$root" ]]
fixtures="$root/crates/products/chio-cli/tests/fixtures/process-worker-outcomes"
chio="$bin_dir/chio"
for tool in "$chio" "$bin_dir/chio-cage-init" "$bin_dir/enforcement-probe"; do
  [[ -x "$tool" ]] || { echo "missing executable: $tool" >&2; exit 1; }
done
[[ -d "$work_dir" && -z "$(ls -A "$work_dir")" ]] || { echo "--work-dir must be an empty directory" >&2; exit 1; }
[[ -d "$anchor_root" && -z "$(ls -A "$anchor_root")" ]] || { echo "--anchor-root must be an empty directory" >&2; exit 1; }

# capture NAME CAMPAIGN SERVER...
capture() {
  local name="$1" campaign="$2"
  shift 2
  local out="$work_dir/$name"
  python3 "$root/examples/reference-swarm/$campaign" \
    --chio "$chio" \
    --cage-init "$bin_dir/chio-cage-init" \
    --probe "$bin_dir/enforcement-probe" \
    --worker-image "$worker_image" \
    --output "$out/campaign" \
    --receipt-rollback-anchor-root "$anchor_root/$name"
  "$chio" process attest-outcomes \
    --state "$out/campaign/state" \
    --plan "$out/campaign/run-plan.json" \
    --out "$out/outcomes.json"
  python3 - "$out/campaign" "$out/pins.json" "$@" <<'PY'
import json
import sys
from pathlib import Path

campaign, out_path, *servers = sys.argv[1:]
campaign = Path(campaign)
runtime_id = json.loads((campaign / "state" / "swarm-calls.json").read_text())["runtime_id"]
signers = {
    server: json.loads((campaign / f"{server}-launch" / "provision-report.json").read_text())[
        "cagePolicyPublicKey"
    ]
    for server in servers
}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump({"launch_policy_signers": signers, "runtime_id": runtime_id}, handle, indent=2)
    handle.write("\n")
PY
  local runtime_id
  runtime_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime_id"])' \
    "$out/pins.json")"
  local trust_args=()
  local server key
  for server in "$@"; do
    key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["launch_policy_signers"][sys.argv[2]])' \
      "$out/pins.json" "$server")"
    trust_args+=(--trusted-launch-policy-signer "$server=$key")
  done
  "$chio" process verify-outcomes \
    --artifact "$out/outcomes.json" \
    --trusted-kernel-pubkey "$out/campaign/state/authority.db.kernel.pub" \
    --runtime-id "$runtime_id" \
    "${trust_args[@]}"
  install -m 0644 "$out/outcomes.json" "$fixtures/current-native-$name.json"
  install -m 0644 "$out/campaign/state/authority.db.kernel.pub" "$fixtures/current-native-$name-kernel.pub"
  install -m 0644 "$out/pins.json" "$fixtures/current-native-$name-pins.json"
}

mkdir -p "$anchor_root/budget" "$anchor_root/clean"
capture budget qualify-process-budget.py alice-probe bob-probe carol-probe dave-probe
capture clean qualify-process-clean-exit.py erin-probe frank-probe

echo "recaptured into $fixtures; update provenance.json with this run's source revision, binary and image digests, then run:"
echo "  cargo test -p chio-cli --lib process_host::call_evidence::outcomes_native"
