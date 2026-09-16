#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/chio-scale-gate-test.XXXXXX")"
trap 'rm -rf "${temporary}"' EXIT
mkdir "${temporary}/bin"
cat > "${temporary}/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
name="receipt_store::tests::scale_proof::append_scale_proof_is_batch_bounded_across_history_sizes"
for required in --locked --release --lib --exact --ignored; do
  found=0
  for argument in "$@"; do
    if [[ "${argument}" == "${required}" ]]; then found=1; fi
  done
  if [[ "${found}" != 1 ]]; then
    echo "missing required execution argument ${required}" >&2
    exit 64
  fi
done
if [[ "${SCALE_TEST_MODE}" == "wrong-test" ]]; then name="some_other_test"; fi
for argument in "$@"; do
  if [[ "${argument}" == "--list" ]]; then
    if [[ "${SCALE_TEST_MODE}" != "empty" ]]; then echo "${name}: test"; fi
    exit 0
  fi
done
case "${SCALE_TEST_MODE}" in
  pass|wrong-test)
    echo "test ${name} ... ok"
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 1.00s'
    ;;
  empty)
    echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 501 filtered out; finished in 0.00s'
    ;;
  ignored)
    echo "test ${name} ... ignored, scale proof"
    echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 500 filtered out; finished in 0.00s'
    ;;
  failed)
    echo "test ${name} ... FAILED"
    exit 101
    ;;
esac
SH
chmod +x "${temporary}/bin/cargo"

for mode in pass empty ignored failed wrong-test; do
  status=0
  PATH="${temporary}/bin:${PATH}" SCALE_TEST_MODE="${mode}" \
    bash "${root}/scripts/check-receipt-append-scale.sh" \
    > "${temporary}/${mode}.log" 2>&1 || status=$?
  if [[ "${mode}" == pass ]]; then
    if [[ "${status}" != 0 ]]; then cat "${temporary}/${mode}.log"; exit 1; fi
    if ! grep -Fq 'Receipt append scale proof passed (1 exact test;' "${temporary}/${mode}.log"; then
      cat "${temporary}/${mode}.log"
      exit 1
    fi
  elif [[ "${status}" == 0 ]]; then
    echo "Scale gate accepted ${mode}" >&2
    cat "${temporary}/${mode}.log"
    exit 1
  fi
done

echo 'Receipt scale gate tests passed (execution required; empty, ignored, failed and substituted tests refused)'
