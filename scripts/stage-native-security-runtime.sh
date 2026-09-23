#!/usr/bin/env bash
# Stage the complete supported Linux runtime into an existing release directory.
set -euo pipefail
umask 022

if [[ $# != 2 ]]; then
  echo "usage: $0 <cargo-target-directory> <release-stage-directory>" >&2
  exit 64
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! git -C "$root" diff --quiet HEAD --; then
  echo "native runtime staging requires committed source" >&2
  exit 1
fi
target_dir="$(realpath -e -- "$1")"
stage_dir="$(realpath -e -- "$2")"
native_target=x86_64-unknown-linux-gnu
static_target=x86_64-unknown-linux-musl
names=(chio chio-secret-brokerd chio-active-response-authorityd chio-keylog-witness chio-keylog-audit chio-cage-init chio-broker-mcp)
targets=("$native_target" "$native_target" "$native_target" "$native_target" "$native_target" "$static_target" "$static_target")

# Validate every executable before adding any companion to the release. Cage
# helpers must be static because their signed filesystem grants omit a loader.
for index in "${!names[@]}"; do
  binary="$target_dir/${targets[$index]}/release/${names[$index]}"
  if [[ ! -f "$binary" || -L "$binary" || ! -x "$binary" ]]; then
    echo "missing native runtime executable: ${names[$index]}" >&2
    exit 1
  fi
  header="$(LC_ALL=C readelf -hW "$binary")"
  if ! grep -Eq 'Machine:.*Advanced Micro Devices X86-64' <<<"$header"; then
    echo "native runtime executable has the wrong architecture: ${names[$index]}" >&2
    exit 1
  fi
  if [[ "${targets[$index]}" == "$static_target" ]]; then
    program_headers="$(LC_ALL=C readelf -lW "$binary")"
    dynamic="$(LC_ALL=C readelf -dW "$binary")"
    if grep -q 'INTERP' <<<"$program_headers" || grep -Eq '\((NEEDED|RPATH|RUNPATH)\)' <<<"$dynamic"; then
      echo "confined executable requires a dynamic loader: ${names[$index]}" >&2
      exit 1
    fi
  fi
  if [[ -e "$stage_dir/${names[$index]}" || -L "$stage_dir/${names[$index]}" ]]; then
    # The ordinary release step may already have staged the exact CLI.
    if [[ "${names[$index]}" != chio || -L "$stage_dir/chio" ]] || ! cmp -s "$binary" "$stage_dir/chio"; then
      echo "refusing to replace an existing runtime executable: ${names[$index]}" >&2
      exit 1
    fi
  fi
done
for destination in native-runtime.json reference-runtime provision-mcp-launch.sh; do
  if [[ -e "$stage_dir/$destination" || -L "$stage_dir/$destination" ]]; then
    echo "runtime staging destination already exists: $destination" >&2
    exit 1
  fi
done

records='[]'
for index in "${!names[@]}"; do
  name="${names[$index]}"
  binary="$target_dir/${targets[$index]}/release/$name"
  if [[ "$name" != chio || ! -e "$stage_dir/chio" ]]; then
    install -m 0755 -- "$binary" "$stage_dir/$name"
  fi
  checksum="$(sha256sum "$stage_dir/$name" | cut -d ' ' -f 1)"
  records="$(jq -c --arg name "$name" --arg target "${targets[$index]}" --arg sha256 "$checksum" \
    '. + [{name: $name, target: $target, sha256: $sha256}]' <<<"$records")"
done
cp -R -- "$root/deploy/reference-runtime" "$stage_dir/reference-runtime"
install -m 0644 -- "$root/scripts/lib/provision-mcp-launch.sh" "$stage_dir/provision-mcp-launch.sh"
install -m 0644 -- "$root/docs/security/broker-prepared-connections.md" "$stage_dir/reference-runtime/broker-prepared-connections.md"
install -m 0644 -- "$root/docs/security/active-defense-rollout.md" "$stage_dir/reference-runtime/active-defense-rollout.md"
source_sha="$(git -C "$root" rev-parse HEAD)"
lock_sha256="$(sha256sum "$root/Cargo.lock" | cut -d ' ' -f 1)"
jq -nS --arg source_sha "$source_sha" --arg lock_sha256 "$lock_sha256" --argjson binaries "$records" \
  '{schema: "chio.native-security-runtime.v1", profile: "linux-x86_64-brokered-native-v1", source_sha: $source_sha, cargo_lock_sha256: $lock_sha256, binaries: $binaries}' \
  > "$stage_dir/native-runtime.json"
