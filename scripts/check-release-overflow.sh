#!/usr/bin/env bash
# Assert that a shipping build still traps integer overflow.
#
# `overflow-checks` is a build-profile setting, so no test in the ordinary
# suite can observe it: `cargo test` runs under `[profile.test]`, where the
# check has always been on, and the wrap only happens under a profile no test
# executes. A release build that silently wraps a budget subtraction turns an
# exhausted budget into an unlimited one, so this runs the arithmetic under the
# shipping profile and looks at what the process does.
#
# The probe reaches its print only when the subtraction wrapped. A build that
# checks overflow dies before it, which is the outcome this gate requires.
#
# `--manifest` and `--profile` exist so the self-test can point the gate at a
# manifest that drops the setting, and at a build that drops the check.
set -euo pipefail

cd "$(dirname "$0")/.."

manifest="Cargo.toml"
profile="release"
probe="chio-profile-probe"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) manifest="$2"; shift 2 ;;
    --profile) profile="$2"; shift 2 ;;
    *) echo "release overflow: unknown argument $1" >&2; exit 2 ;;
  esac
done

for shipping_profile in release docker-release; do
  if ! awk -v header="[profile.${shipping_profile}]" '
        $0 == header { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $0 ~ /^overflow-checks[[:space:]]*=[[:space:]]*true$/ { found = 1 }
        END { exit(found ? 0 : 1) }
      ' "${manifest}"; then
    echo "release overflow: [profile.${shipping_profile}] in ${manifest} does not set overflow-checks = true" >&2
    exit 1
  fi
done

cargo build --quiet --profile "${profile}" -p "${probe}"

target_directory="$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
if [[ "${profile}" == "dev" ]]; then
  binary="${target_directory}/debug/${probe}"
else
  binary="${target_directory}/${profile}/${probe}"
fi

status=0
output="$("${binary}" 0 1 2>&1)" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "release overflow: the ${profile} profile wrapped instead of trapping" >&2
  echo "${output}" >&2
  exit 1
fi

if ! grep -qF 'attempt to subtract with overflow' <<<"${output}"; then
  echo "release overflow: the ${profile} probe failed for another reason (status ${status})" >&2
  echo "${output}" >&2
  exit 1
fi

echo "release overflow: the ${profile} profile traps u64 subtraction below zero (status ${status})"
