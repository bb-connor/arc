#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d -t chio-active-defense-conformance-gate-XXXXXX)"
trap 'rm -rf "${work}"' EXIT
fake_bin="${work}/bin"
mkdir -p "${fake_bin}"

cat >"${fake_bin}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${CARGO_INCREMENTAL:-}" != "0" ]] ||
  [[ "${CARGO_BUILD_JOBS:-}" != "1" ]] ||
  [[ "${CARGO_TERM_COLOR:-}" != "never" ]]; then
  echo "active-defense gate did not pin deterministic Cargo execution" >&2
  exit 63
fi

if [[ "$*" != "test -p chio-conformance --test active_defense -- --nocapture" ]]; then
  printf 'unexpected fake cargo invocation: %s\n' "$*" >&2
  exit 64
fi

tests=(
  slow_cumulative_exfiltration
  canary_pre_dispatch_denial
  honey_tool_pre_dispatch_denial
  temporal_within_boundary
  declassification_replay
  session_isolation_epoch
  event_producer_trust
  truncated_lineage_no_containment
  overlapping_ttl_lift
  partial_rollback_truth
)
mode="${FAKE_ACTIVE_DEFENSE_MODE:-success}"
case "${mode}" in
  zero)
    printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s\n'
    exit 0
    ;;
  removed)
    tests=("${tests[@]:0:9}")
    ;;
  ignored)
    for ((index = 0; index < 9; index++)); do
      printf 'test %s ... ok\n' "${tests[$index]}"
    done
    printf 'test %s ... ignored\n' "${tests[10]}"
    printf 'test result: ok. 9 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
    exit 0
    ;;
  extra)
    tests+=(unratcheted_active_defense_case)
    ;;
  duplicate)
    tests=("${tests[@]:0:9}")
    tests+=(slow_cumulative_exfiltration)
    ;;
  success) ;;
  *)
    printf 'unknown fake active-defense mode: %s\n' "${mode}" >&2
    exit 65
    ;;
esac

for test_name in "${tests[@]}"; do
  printf 'test %s ... ok\n' "${test_name}"
done
printf \
  'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n' \
  "${#tests[@]}"
EOF
chmod 700 "${fake_bin}/cargo"

run_gate() {
  local mode="$1"
  local output="${work}/${mode}.out"
  set +e
  (
    cd "${repo_root}"
    PATH="${fake_bin}:${PATH}" \
      FAKE_ACTIVE_DEFENSE_MODE="${mode}" \
      ./scripts/check-active-defense-conformance.sh
  ) >"${output}" 2>&1
  local status=$?
  set -e
  printf '%s\n' "${status}"
}

for mode in zero removed ignored extra duplicate; do
  status="$(run_gate "${mode}")"
  if [[ "${status}" -eq 0 ]]; then
    echo "active-defense gate accepted invalid ${mode} evidence" >&2
    exit 1
  fi
done

status="$(run_gate success)"
if [[ "${status}" -ne 0 ]]; then
  cat "${work}/success.out" >&2
  exit "${status}"
fi
grep -Fqx 'Active-defense conformance gate passed with exactly ten release tests' \
  "${work}/success.out"

printf 'check-active-defense-conformance.test.sh: all assertions passed\n'
