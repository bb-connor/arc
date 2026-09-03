#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/run-exact-cargo-test-inventory.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/chio-exact-target-test.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/bin"

cat > "${work}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${CHIO_EXACT_COMMAND_CAPTURE:?command capture path is required}"
printf 'CALL\0' >> "${CHIO_EXACT_COMMAND_CAPTURE}"
for argument in "$@"; do
  printf '%s\0' "${argument}" >> "${CHIO_EXACT_COMMAND_CAPTURE}"
done

names=(alpha beta)
variant="${CHIO_EXACT_VARIANT:-valid}"
if [[ " $* " == *" --list "* ]]; then
  case "${variant}" in
    missing) names=(alpha) ;;
    extra) names=(alpha beta gamma) ;;
    duplicate) names=(alpha alpha beta) ;;
  esac
  for name in "${names[@]}"; do
    printf '%s: test\n' "${name}"
  done
  exit 0
fi

case "${variant}" in
  renamed) names=(alpha gamma) ;;
  missing_run) names=(alpha) ;;
  extra_run) names=(alpha beta gamma) ;;
  cargo_failure) exit 23 ;;
esac
for name in "${names[@]}"; do
  printf 'test %s ... ok\n' "${name}"
done
passed="${#names[@]}"
ignored=0
filtered="${CHIO_EXACT_FILTERED:-0}"
if [[ "${variant}" == "ignored" ]]; then
  ignored=1
fi
printf 'test result: ok. %s passed; 0 failed; %s ignored; 0 measured; %s filtered out; finished in 0.01s\n' \
  "${passed}" "${ignored}" "${filtered}"
EOF
chmod +x "${work}/bin/cargo"

export CHIO_EXACT_COMMAND_CAPTURE="${work}/commands"
rm -f "${CHIO_EXACT_COMMAND_CAPTURE}"
PATH="${work}/bin:${PATH}" "./${runner}" \
  --label "unfiltered fixture" \
  --expected alpha beta -- \
  cargo test -p fixture --test exact_target >/dev/null

rm -f "${CHIO_EXACT_COMMAND_CAPTURE}"
CHIO_EXACT_FILTERED=7 PATH="${work}/bin:${PATH}" "./${runner}" \
  --label "filtered fixture" \
  --allow-filtered \
  --expected alpha beta -- \
  cargo test -p fixture --lib exact::module:: >/dev/null

digest="$(printf 'alpha\nbeta\n' | shasum -a 256 | awk '{print $1}')"
PATH="${work}/bin:${PATH}" "./${runner}" \
  --label "committed fixture" \
  --expected-count 2 \
  --expected-sha256 "${digest}" -- \
  cargo test -p fixture --test exact_target >/dev/null

python3 - "${CHIO_EXACT_COMMAND_CAPTURE}" <<'PY'
import sys
from pathlib import Path

items = [
    item.decode("utf-8")
    for item in Path(sys.argv[1]).read_bytes().split(b"\0")
    if item
]
expected = [
    "CALL", "test", "-p", "fixture", "--lib", "exact::module::", "--", "--list",
    "CALL", "test", "-p", "fixture", "--lib", "exact::module::",
    "CALL", "test", "-p", "fixture", "--test", "exact_target", "--", "--list",
    "CALL", "test", "-p", "fixture", "--test", "exact_target",
]
if items != expected:
    raise SystemExit(f"unexpected exact-inventory command sequence: {items!r}")
PY

for variant in missing extra duplicate renamed missing_run extra_run ignored cargo_failure; do
  set +e
  CHIO_EXACT_VARIANT="${variant}" PATH="${work}/bin:${PATH}" "./${runner}" \
    --label "${variant} mutant" \
    --expected alpha beta -- \
    cargo test -p fixture --test exact_target >"${work}/${variant}.out" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "exact Cargo target runner accepted ${variant} mutant" >&2
    exit 1
  fi
done

set +e
CHIO_EXACT_FILTERED=7 PATH="${work}/bin:${PATH}" "./${runner}" \
  --label "undeclared filtering mutant" \
  --expected alpha beta -- \
  cargo test -p fixture --lib exact::module:: >"${work}/undeclared-filter.out" 2>&1
status=$?
set -e
if [[ "${status}" -eq 0 ]]; then
  echo "exact Cargo target runner accepted undeclared filtering" >&2
  exit 1
fi

echo "exact Cargo target runner self-test passed"
