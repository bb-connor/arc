#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-enterprise-cross-mechanism.sh"
test_name="enterprise_invocation_composes_all_controls_and_mutations_fail_closed"
work="$(mktemp -d "${TMPDIR:-/tmp}/chio-enterprise-composition-test.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/bin"

cat > "${work}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${CHIO_ENTERPRISE_COMMAND_CAPTURE:?command capture path is required}"
: "${CHIO_ENTERPRISE_ENV_CAPTURE:?environment capture path is required}"
printf 'CALL\0' >> "${CHIO_ENTERPRISE_COMMAND_CAPTURE}"
for argument in "$@"; do
  printf '%s\0' "${argument}" >> "${CHIO_ENTERPRISE_COMMAND_CAPTURE}"
done
printf 'CALL\0%s\0%s\0' \
  "${CARGO_INCREMENTAL:-}" \
  "${CARGO_BUILD_JOBS:-}" >> "${CHIO_ENTERPRISE_ENV_CAPTURE}"

test_name="enterprise_invocation_composes_all_controls_and_mutations_fail_closed"
if [[ " $* " == *" --list "* ]]; then
  case "${CHIO_ENTERPRISE_LIST_VARIANT:-valid}" in
    valid)
      echo "${test_name}: test"
      ;;
    missing)
      :
      ;;
    extra)
      echo "${test_name}: test"
      echo "unexpected_enterprise_test: test"
      ;;
    *)
      exit 21
      ;;
  esac
  exit 0
fi
case "${CHIO_ENTERPRISE_RUN_VARIANT:-valid}" in
  valid)
    cat <<OUTPUT
running 1 test
test ${test_name} ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
OUTPUT
    ;;
  ignored)
    echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    ;;
  filtered)
    cat <<OUTPUT
test ${test_name} ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s
OUTPUT
    ;;
  renamed)
    cat <<'OUTPUT'
test renamed_enterprise_test ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
OUTPUT
    ;;
  *)
    exit 22
    ;;
esac
EOF
chmod +x "${work}/bin/cargo"

export CHIO_ENTERPRISE_COMMAND_CAPTURE="${work}/cargo-arguments"
export CHIO_ENTERPRISE_ENV_CAPTURE="${work}/cargo-environment"
rm -f "${CHIO_ENTERPRISE_COMMAND_CAPTURE}" "${CHIO_ENTERPRISE_ENV_CAPTURE}"
PATH="${work}/bin:${PATH}" "./${runner}" >/dev/null

python3 - "${CHIO_ENTERPRISE_COMMAND_CAPTURE}" "${CHIO_ENTERPRISE_ENV_CAPTURE}" <<'PY'
import sys
from pathlib import Path


def records(path: str) -> list[list[str]]:
    observed = []
    current = None
    for item in Path(path).read_bytes().split(b"\0"):
        if item == b"CALL":
            current = []
            observed.append(current)
        elif item:
            if current is None:
                raise SystemExit(f"capture {path} is missing its call marker")
            current.append(item.decode("utf-8"))
    return observed


test_name = "enterprise_invocation_composes_all_controls_and_mutations_fail_closed"
base = [
    "test",
    "-p",
    "chio-conformance",
    "--features",
    "enterprise-native",
    "--test",
    "enterprise_cross_mechanism",
]
expected_commands = [
    base + ["--", "--list"],
    base,
]
observed_commands = records(sys.argv[1])
if observed_commands != expected_commands:
    raise SystemExit(
        "unexpected enterprise cross-mechanism Cargo commands:\n"
        f"  actual:   {observed_commands!r}\n"
        f"  expected: {expected_commands!r}"
    )

expected_environments = [["0", "1"], ["0", "1"]]
observed_environments = records(sys.argv[2])
if observed_environments != expected_environments:
    raise SystemExit(
        "unexpected enterprise cross-mechanism Cargo environments:\n"
        f"  actual:   {observed_environments!r}\n"
        f"  expected: {expected_environments!r}"
    )
PY

for variant in missing extra; do
  set +e
  CHIO_ENTERPRISE_LIST_VARIANT="${variant}" PATH="${work}/bin:${PATH}" \
    "./${runner}" >"${work}/list-${variant}.out" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "enterprise cross-mechanism gate accepted ${variant} inventory" >&2
    exit 1
  fi
done

for variant in ignored filtered renamed; do
  set +e
  CHIO_ENTERPRISE_RUN_VARIANT="${variant}" PATH="${work}/bin:${PATH}" \
    "./${runner}" >"${work}/run-${variant}.out" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "enterprise cross-mechanism gate accepted ${variant} execution" >&2
    exit 1
  fi
done

echo "enterprise cross-mechanism gate self-test passed"
