# Source from qualification scripts. Test helpers print
# "skipping <test>: <reason>" and exit 0 when an environment precondition (for
# example a loopback bind) is denied; cargo counts that as a pass. A required
# test that skips has produced no evidence, so it fails the qualification.

# qualification_assert_no_required_skips LOG [OPTIONAL_TEST ...]
# Fails when LOG holds a skip line for a test that is not listed as optional.
# Skips of listed optional tests are reported and tolerated.
qualification_assert_no_required_skips() {
  local log_path="$1"
  shift
  local failed=0 line rest name reason optional listed
  while IFS= read -r line; do
    rest="${line#skipping }"
    name="${rest%%: *}"
    reason="${rest#*: }"
    optional=0
    for listed in "$@"; do
      if [ "${listed}" = "${name}" ]; then
        optional=1
      fi
    done
    if [ "${optional}" -eq 1 ]; then
      echo "qualification: optional test ${name} skipped: ${reason}" >&2
    else
      echo "qualification: required test ${name} skipped itself: ${reason}" >&2
      failed=1
    fi
  done < <(grep -E '^skipping .+: .+' "${log_path}" || true)
  return "${failed}"
}
