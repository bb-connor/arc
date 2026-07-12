#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-protocol-primitives-concurrency.sh"
production_store="crates/kernel/chio-kernel/src/budget_store/in_memory.rs"
if [[ ! -x "${runner}" ]]; then
  echo "protocol-primitives concurrency runner is missing or not executable: ${runner}" >&2
  exit 1
fi

if ! grep -Fq '#[cfg(all(test, feature = "loom-tests"))]' "${production_store}"; then
  echo "production budget store does not confine Loom synchronization substitution to tests" >&2
  exit 1
fi
if grep -Fq '#[cfg(feature = "loom-tests")]' "${production_store}"; then
  echo "production budget store enables Loom synchronization outside cfg(test)" >&2
  exit 1
fi
if ! grep -Fq 'pub(crate) fn new_loom()' "${production_store}"; then
  echo "production budget store does not isolate Loom behind its dedicated model constructor" >&2
  exit 1
fi
if ! grep -Fq 'InMemoryBudgetStoreMutex::Std' "${production_store}"; then
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
for argument in "$@"; do
  printf '%s\0' "${argument}"
done > "${CHIO_LOOM_COMMAND_CAPTURE}"
EOF
chmod +x "${work}/bin/cargo"

export CHIO_LOOM_COMMAND_CAPTURE="${work}/cargo-arguments"
PATH="${work}/bin:${PATH}" "./${runner}"

python3 - "${CHIO_LOOM_COMMAND_CAPTURE}" <<'PY'
import sys
from pathlib import Path

arguments = [
    argument.decode("utf-8")
    for argument in Path(sys.argv[1]).read_bytes().split(b"\0")
    if argument
]
expected = [
    "test",
    "-p",
    "chio-kernel",
    "--lib",
    "--features",
    "loom-tests",
    "budget_store::property_tests::loom_production_composite_quota_authorization_is_all_or_none",
    "--",
    "--exact",
]
if arguments != expected:
    raise SystemExit(
        "unexpected protocol-primitives Loom command:\n"
        f"  actual:   {arguments!r}\n"
        f"  expected: {expected!r}"
    )
PY

echo "protocol-primitives concurrency gate contract passed"
