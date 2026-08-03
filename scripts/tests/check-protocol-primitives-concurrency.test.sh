#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-protocol-primitives-concurrency.sh"
production_store="crates/kernel/chio-kernel/src/budget_store/in_memory.rs"
production_store_parts=(
  "${production_store}"
  "crates/kernel/chio-kernel/src/budget_store/in_memory.part1.inc"
  "crates/kernel/chio-kernel/src/budget_store/in_memory.part2.inc"
)
if [[ ! -x "${runner}" ]]; then
  echo "protocol-primitives concurrency runner is missing or not executable: ${runner}" >&2
  exit 1
fi

if ! grep -Fq '#[cfg(all(test, feature = "loom-tests"))]' "${production_store_parts[@]}"; then
  echo "production budget store does not confine Loom synchronization substitution to tests" >&2
  exit 1
fi
if grep -Fq '#[cfg(feature = "loom-tests")]' "${production_store_parts[@]}"; then
  echo "production budget store enables Loom synchronization outside cfg(test)" >&2
  exit 1
fi
if ! grep -Fq 'pub(crate) fn new_loom()' "${production_store_parts[@]}"; then
  echo "production budget store does not isolate Loom behind its dedicated model constructor" >&2
  exit 1
fi
if ! grep -Fq 'InMemoryBudgetStoreMutex::Std' "${production_store_parts[@]}"; then
  echo "ordinary budget-store construction does not retain the production mutex" >&2
  exit 1
fi

for gate in \
  .github/workflows/ci.yml \
  scripts/ci-pr-tier.sh \
  scripts/ci-workspace.sh
do
  if ! grep -Fq "./${runner}" "${gate}"; then
    echo "protocol-primitives concurrency runner is not wired into ${gate}" >&2
    exit 1
  fi
done

work="$(mktemp -d "${TMPDIR:-/tmp}/chio-protocol-primitives-loom.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/bin"

cat > "${work}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${CHIO_LOOM_COMMAND_CAPTURE:?capture path is required}"
: "${CHIO_LOOM_ENV_CAPTURE:?environment capture path is required}"
printf 'CALL\0' >> "${CHIO_LOOM_COMMAND_CAPTURE}"
for argument in "$@"; do
  printf '%s\0' "${argument}" >> "${CHIO_LOOM_COMMAND_CAPTURE}"
done
printf '%s' "${CARGO_INCREMENTAL:-}" > "${CHIO_LOOM_ENV_CAPTURE}.incremental"
printf '%s' "${CARGO_BUILD_JOBS:-}" > "${CHIO_LOOM_ENV_CAPTURE}.build-jobs"
printf '%s' "${RUSTFLAGS:-}" > "${CHIO_LOOM_ENV_CAPTURE}.rustflags"

if [[ " $* " == *" --list "* ]]; then
  case "${CHIO_LOOM_LIST_VARIANT:-valid}" in
    valid)
      cat <<'TESTS'
protocol_primitives_capture_versus_reverse: test
protocol_primitives_idempotent_compensation: test
protocol_primitives_immutable_maximum_race: test
protocol_primitives_last_unit_contention: test
protocol_primitives_three_key_all_or_nothing: test
TESTS
      ;;
    missing)
      cat <<'TESTS'
protocol_primitives_capture_versus_reverse: test
protocol_primitives_immutable_maximum_race: test
protocol_primitives_last_unit_contention: test
protocol_primitives_three_key_all_or_nothing: test
TESTS
      ;;
    renamed)
      cat <<'TESTS'
protocol_primitives_capture_vs_reverse: test
protocol_primitives_idempotent_compensation: test
protocol_primitives_immutable_maximum_race: test
protocol_primitives_last_unit_contention: test
protocol_primitives_three_key_all_or_nothing: test
TESTS
      ;;
    extra)
      cat <<'TESTS'
protocol_primitives_capture_versus_reverse: test
protocol_primitives_idempotent_compensation: test
protocol_primitives_immutable_maximum_race: test
protocol_primitives_last_unit_contention: test
protocol_primitives_three_key_all_or_nothing: test
protocol_primitives_unexpected_extra: test
TESTS
      ;;
    *)
      echo "unknown mocked list variant: ${CHIO_LOOM_LIST_VARIANT}" >&2
      exit 2
      ;;
  esac
  exit 0
fi

case "${CHIO_LOOM_RUN_VARIANT:-valid}" in
  valid)
    cat <<'TESTS'
running 5 tests
test protocol_primitives_capture_versus_reverse ... ok
test protocol_primitives_idempotent_compensation ... ok
test protocol_primitives_immutable_maximum_race ... ok
test protocol_primitives_last_unit_contention ... ok
test protocol_primitives_three_key_all_or_nothing ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
TESTS
    ;;
  zero)
    cat <<'TESTS'
running 5 tests
test protocol_primitives_capture_versus_reverse ... ignored
test protocol_primitives_idempotent_compensation ... ignored
test protocol_primitives_immutable_maximum_race ... ignored
test protocol_primitives_last_unit_contention ... ignored
test protocol_primitives_three_key_all_or_nothing ... ignored

test result: ok. 0 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.01s
TESTS
    ;;
  missing_summary)
    cat <<'TESTS'
running 5 tests
test protocol_primitives_capture_versus_reverse ... ok
test protocol_primitives_idempotent_compensation ... ok
test protocol_primitives_immutable_maximum_race ... ok
test protocol_primitives_last_unit_contention ... ok
test protocol_primitives_three_key_all_or_nothing ... ok
TESTS
    ;;
  mismatched_summary)
    cat <<'TESTS'
running 5 tests
test protocol_primitives_capture_versus_reverse ... ok
test protocol_primitives_idempotent_compensation ... ok
test protocol_primitives_immutable_maximum_race ... ok
test protocol_primitives_last_unit_contention ... ok
test protocol_primitives_three_key_all_or_nothing ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s
TESTS
    ;;
  *)
    echo "unknown mocked run variant: ${CHIO_LOOM_RUN_VARIANT}" >&2
    exit 2
    ;;
esac
EOF
chmod +x "${work}/bin/cargo"

export CHIO_LOOM_COMMAND_CAPTURE="${work}/cargo-arguments"
export CHIO_LOOM_ENV_CAPTURE="${work}/cargo-environment"
rm -f "${CHIO_LOOM_COMMAND_CAPTURE}"
PATH="${work}/bin:${PATH}" "./${runner}"

python3 - "${CHIO_LOOM_COMMAND_CAPTURE}" <<'PY'
import sys
from pathlib import Path

records = []
current = None
for argument in Path(sys.argv[1]).read_bytes().split(b"\0"):
    if argument == b"CALL":
        current = []
        records.append(current)
    elif argument:
        if current is None:
            raise SystemExit("cargo command capture is missing its call marker")
        current.append(argument.decode("utf-8"))

base = [
    "test",
    "-p",
    "chio-kernel",
    "--features",
    "loom-tests",
    "--test",
    "loom_concurrency",
    "protocol_primitives_",
]
expected = [base + ["--", "--list"], base]
if records != expected:
    raise SystemExit(
        "unexpected protocol-primitives Loom commands:\n"
        f"  actual:   {records!r}\n"
        f"  expected: {expected!r}"
    )
PY

if [[ "$(cat "${CHIO_LOOM_ENV_CAPTURE}.incremental")" != "0" ]]; then
  echo "protocol-primitives concurrency runner did not disable incremental compilation" >&2
  exit 1
fi
if [[ "$(cat "${CHIO_LOOM_ENV_CAPTURE}.build-jobs")" != "1" ]]; then
  echo "protocol-primitives concurrency runner did not constrain Cargo build jobs" >&2
  exit 1
fi
if [[ "$(cat "${CHIO_LOOM_ENV_CAPTURE}.rustflags")" != *"--cfg chio_kernel_loom"* ]]; then
  echo "protocol-primitives concurrency runner did not enable chio_kernel_loom" >&2
  exit 1
fi

for variant in missing renamed extra; do
  output="${work}/${variant}.out"
  rm -f "${CHIO_LOOM_COMMAND_CAPTURE}"
  set +e
  CHIO_LOOM_LIST_VARIANT="${variant}" PATH="${work}/bin:${PATH}" \
    "./${runner}" >"${output}" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "protocol-primitives concurrency runner accepted ${variant} test inventory" >&2
    exit 1
  fi
  if ! grep -Fq 'exact test set mismatch' "${output}"; then
    echo "protocol-primitives concurrency runner did not report ${variant} inventory drift" >&2
    cat "${output}" >&2
    exit 1
  fi
done

for variant in zero missing_summary mismatched_summary; do
  output="${work}/${variant}.out"
  rm -f "${CHIO_LOOM_COMMAND_CAPTURE}"
  set +e
  CHIO_LOOM_RUN_VARIANT="${variant}" PATH="${work}/bin:${PATH}" \
    "./${runner}" >"${output}" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "protocol-primitives concurrency runner accepted ${variant} execution summary" >&2
    exit 1
  fi
  if ! grep -Eq 'execution (set mismatch|summary is absent, non-exact, or ambiguous)' "${output}"; then
    echo "protocol-primitives concurrency runner did not reject ${variant} execution evidence" >&2
    cat "${output}" >&2
    exit 1
  fi
done

echo "protocol-primitives concurrency gate contract passed"
