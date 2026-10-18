#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/qualification-skips.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

fail() {
  echo "qualification-skips.test.sh: $*" >&2
  exit 1
}

# shellcheck source=../lib/qualification-skips.sh
source "${REPO_ROOT}/scripts/lib/qualification-skips.sh"

skip_log="${work}/skip.log"
pass_log="${work}/pass.log"
printf 'skipping trust_control_cluster_x: loopback bind denied: eperm\ntest result: ok. 1 passed; 0 failed\n' >"${skip_log}"
printf 'running 1 test\ntest result: ok. 1 passed; 0 failed\n' >"${pass_log}"

qualification_assert_no_required_skips "${pass_log}" || fail "real pass was rejected"

if err="$(qualification_assert_no_required_skips "${skip_log}" 2>&1)"; then
  fail "self-skipping required test passed"
fi
case "${err}" in
  *"required test trust_control_cluster_x skipped itself: loopback bind denied: eperm"*) ;;
  *) fail "failure did not name the test and reason: ${err}" ;;
esac

if qualification_assert_no_required_skips "${skip_log}" other_test >/dev/null 2>&1; then
  fail "an unrelated optional entry excused the skip"
fi

err="$(qualification_assert_no_required_skips "${skip_log}" trust_control_cluster_x 2>&1)" \
  || fail "listed optional skip failed the qualification"
case "${err}" in
  *"optional test trust_control_cluster_x skipped"*) ;;
  *) fail "optional skip was not reported: ${err}" ;;
esac

# End to end: the real script against a stub cargo.
tree="${work}/tree"
mkdir -p "${tree}/scripts/lib" "${work}/bin"
cp "${REPO_ROOT}/scripts/qualify-trust-control.sh" "${tree}/scripts/"
cp "${REPO_ROOT}/scripts/lib/qualification-skips.sh" "${tree}/scripts/lib/" 2>/dev/null || true
cat >"${work}/bin/cargo" <<'EOC'
#!/usr/bin/env bash
if [ "${STUB_CARGO_MODE}" = skip ]; then
  echo "skipping $4: loopback bind denied: stub"
fi
echo "test result: ok. 1 passed; 0 failed; 0 ignored"
EOC
chmod +x "${work}/bin/cargo"

if STUB_CARGO_MODE=skip PATH="${work}/bin:${PATH}" bash "${tree}/scripts/qualify-trust-control.sh" >"${work}/e2e-skip.log" 2>&1; then
  fail "qualify-trust-control.sh passed with a self-skipping required test"
fi
grep -q "required test .* skipped itself: loopback bind denied: stub" "${work}/e2e-skip.log" \
  || fail "qualify-trust-control.sh did not name the skipped test"

STUB_CARGO_MODE=pass PATH="${work}/bin:${PATH}" bash "${tree}/scripts/qualify-trust-control.sh" >"${work}/e2e-pass.log" 2>&1 \
  || { cat "${work}/e2e-pass.log" >&2; fail "qualify-trust-control.sh failed on real passes"; }

grep -F 'qualification_assert_no_required_skips' "${REPO_ROOT}/scripts/qualify-release.sh" >/dev/null \
  || fail "qualify-release.sh does not check the trust cluster log for skips"

echo "qualification-skips.test.sh: skipped required tests fail, optional skips pass, real passes pass"
