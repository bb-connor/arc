#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-protocol-provenance.py"
RECORD="$REPO_ROOT/third_party/provenance/clawdstrike-protocol-primitives.toml"

work="$(mktemp -d -t chio-protocol-provenance-XXXXXX)"
trap 'rm -rf "$work"' EXIT

grep -Fq 'python3 ./scripts/check-protocol-provenance.py' \
  "$REPO_ROOT/.github/workflows/ci.yml"
grep -Fq 'bash ./scripts/tests/check-protocol-provenance.test.sh' \
  "$REPO_ROOT/.github/workflows/ci.yml"
for gate in "$REPO_ROOT/scripts/ci-pr-tier.sh" "$REPO_ROOT/scripts/ci-workspace.sh"; do
  grep -Fq 'python3 scripts/check-protocol-provenance.py' "$gate"
  grep -Fq 'bash scripts/tests/check-protocol-provenance.test.sh' "$gate"
done

make_valid_root() {
  local root="$1"
  mkdir -p "$root/third_party/provenance"
  cp "$RECORD" "$root/third_party/provenance/clawdstrike-protocol-primitives.toml"
  python3 - "$root" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
destinations = (
    "crates/platform/chio-store-sqlite/src/approval_store_parts/part_01.rs",
    "crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs",
    "crates/platform/chio-store-sqlite/tests/approval_store.rs",
)
for destination in destinations:
    path = root / destination
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("// protocol provenance fixture\n", encoding="utf-8")
PY
}

clone_case() {
  local name="$1"
  local root="$work/$name"
  cp -R "$work/valid" "$root"
  printf '%s\n' "$root"
}

replace_once() {
  local root="$1" old="$2" new="$3"
  python3 - "$root/third_party/provenance/clawdstrike-protocol-primitives.toml" \
    "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
source = path.read_text(encoding="utf-8")
if source.count(old) < 1:
    raise SystemExit(f"fixture mutation target is absent: {old}")
path.write_text(source.replace(old, new, 1), encoding="utf-8")
PY
}

replace_last() {
  local root="$1" old="$2" new="$3"
  python3 - "$root/third_party/provenance/clawdstrike-protocol-primitives.toml" \
    "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
source = path.read_text(encoding="utf-8")
head, separator, tail = source.rpartition(old)
if not separator:
    raise SystemExit(f"fixture mutation target is absent: {old}")
path.write_text(head + new + tail, encoding="utf-8")
PY
}

assert_pass() {
  local root="$1" label="$2"
  local stdout="$work/$label.out" stderr="$work/$label.err" rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  if [[ "$rc" != 0 ]]; then
    printf 'FAIL: %s: checker returned %s\n' "$label" "$rc" >&2
    cat "$stderr" >&2
    exit 1
  fi
  grep -F 'protocol provenance check passed' "$stdout" >/dev/null
  printf 'ok: %s\n' "$label"
}

assert_failure() {
  local root="$1" expected="$2" label="$3"
  local stdout="$work/$label.out" stderr="$work/$label.err" rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  if [[ "$rc" == 0 ]]; then
    printf 'FAIL: %s: checker unexpectedly passed\n' "$label" >&2
    exit 1
  fi
  if ! grep -F "$expected" "$stderr" >/dev/null; then
    printf 'FAIL: %s: expected error not found: %s\n' "$label" "$expected" >&2
    cat "$stderr" >&2
    exit 1
  fi
  printf 'ok: %s\n' "$label"
}

make_valid_root "$work/valid"
assert_pass "$work/valid" "complete-record"

missing_record="$(clone_case missing-record)"
rm "$missing_record/third_party/provenance/clawdstrike-protocol-primitives.toml"
assert_failure "$missing_record" 'protocol provenance record is missing' "missing-record"

wrong_repository="$(clone_case wrong-repository)"
replace_once "$wrong_repository" \
  'https://github.com/backbay-labs/clawdstrike' \
  'https://github.com/example/clawdstrike'
assert_failure "$wrong_repository" \
  'source_repository does not match the reviewed repository' "wrong-repository"

wrong_commit="$(clone_case wrong-commit)"
replace_once "$wrong_commit" \
  '666303e5f3428f3b6e6b72f118c269a02388e0a4' \
  '0000000000000000000000000000000000000000'
assert_failure "$wrong_commit" \
  'source_commit does not match the reviewed commit' "wrong-commit"

wrong_blob="$(clone_case wrong-blob)"
replace_once "$wrong_blob" \
  '6dba93d7cbcf53e5d7ec0610666207c7db5e5fae' \
  '0000000000000000000000000000000000000000'
assert_failure "$wrong_blob" \
  'source blob does not match the reviewed commit' "wrong-blob"

wrong_license="$(clone_case wrong-license)"
replace_once "$wrong_license" 'license = "Apache-2.0"' 'license = "MIT"'
assert_failure "$wrong_license" 'source license must be Apache-2.0' "wrong-license"

wrong_notice="$(clone_case wrong-notice)"
replace_once "$wrong_notice" 'Copyright 2026 Backbay Industries' \
  'Copyright 2025 Backbay Industries'
assert_failure "$wrong_notice" \
  'source NOTICE does not match the reviewed notice' "wrong-notice"

wrong_source="$(clone_case wrong-source-inventory)"
replace_once "$wrong_source" \
  'crates/services/hushd/src/session/mod.rs' \
  'crates/services/hushd/src/session/unknown.rs'
assert_failure "$wrong_source" 'protocol source inventory mismatch' "wrong-source-inventory"

duplicate_source="$(clone_case duplicate-source)"
replace_once "$duplicate_source" \
  'crates/services/hushd/src/session/mod.rs' \
  'crates/services/control-api/src/routes/policies/proposals.rs'
assert_failure "$duplicate_source" \
  'protocol source inventory contains missing or duplicate entries' "duplicate-source"

wrong_reuse="$(clone_case wrong-reuse)"
replace_once "$wrong_reuse" 'reuse = "test_shape"' 'reuse = "concept"'
assert_failure "$wrong_reuse" \
  'reuse class does not match the reviewed boundary' "wrong-reuse"

copied_source="$(clone_case copied-source)"
replace_once "$copied_source" 'copied = false' 'copied = true'
assert_failure "$copied_source" 'copied source is not approved' "copied-source"

missing_modifications="$(clone_case missing-modifications)"
python3 - "$missing_modifications/third_party/provenance/clawdstrike-protocol-primitives.toml" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source, count = re.subn(r'modifications = "[^"]+"', 'modifications = ""', source, count=1)
if count != 1:
    raise SystemExit("modification fixture mutation failed")
path.write_text(source, encoding="utf-8")
PY
assert_failure "$missing_modifications" \
  'modification boundary is missing' "missing-modifications"

wrong_destination="$(clone_case wrong-destination)"
replace_once "$wrong_destination" \
  'crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs' \
  'crates/platform/chio-store-sqlite/tests/approval_store.rs'
assert_failure "$wrong_destination" \
  'destination mapping does not match the reviewed boundary' "wrong-destination"

duplicate_destination="$(clone_case duplicate-destination)"
replace_once "$duplicate_destination" \
  'destinations = ["crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs"]' \
  'destinations = ["crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs", "crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs"]'
assert_failure "$duplicate_destination" \
  'destination inventory contains duplicates' "duplicate-destination"

escaping_destination="$(clone_case escaping-destination)"
replace_once "$escaping_destination" \
  'crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs' \
  '../outside.rs'
assert_failure "$escaping_destination" \
  'destination escapes the repository' "escaping-destination"

missing_destination="$(clone_case missing-destination)"
rm "$missing_destination/crates/platform/chio-store-sqlite/tests/approval_store.rs"
assert_failure "$missing_destination" \
  'destination does not exist: crates/platform/chio-store-sqlite/tests/approval_store.rs' \
  "missing-destination"

wrong_exclusion="$(clone_case wrong-exclusion)"
replace_once "$wrong_exclusion" \
  'checkpoint_and_marketplace_witness_surfaces' \
  'unknown_witness_source'
assert_failure "$wrong_exclusion" \
  'excluded protocol input inventory mismatch' "wrong-exclusion"

used_exclusion="$(clone_case used-exclusion)"
replace_once "$used_exclusion" 'destinations = []' \
  'destinations = ["crates/platform/chio-store-sqlite/tests/approval_store.rs"]'
assert_failure "$used_exclusion" \
  'unresolved input must remain no-use with no destinations' "used-exclusion"

used_spine="$(clone_case used-spine)"
replace_last "$used_spine" 'destinations = []' \
  'destinations = ["crates/platform/chio-store-sqlite/tests/approval_store.rs"]'
assert_failure "$used_spine" \
  'Spine and AegisNet exclusion is incomplete' "used-spine"

notice_mismatch="$(clone_case notice-mismatch)"
replace_once "$notice_mismatch" \
  'notice_update_required = false' 'notice_update_required = true'
assert_failure "$notice_mismatch" \
  'NOTICE disposition must remain false for non-copied reuse' "notice-mismatch"

incomplete_review="$(clone_case incomplete-review)"
replace_once "$incomplete_review" \
  'reviewer = "Chio security review"' 'reviewer = ""'
assert_failure "$incomplete_review" \
  'protocol provenance reviewer is incomplete' "incomplete-review"

unrecorded_marker="$(clone_case unrecorded-marker)"
python3 - "$unrecorded_marker" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "crates/core/unrecorded/src/lib.rs"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("// Adapted from " + "Clawdstrike\n", encoding="utf-8")
PY
assert_failure "$unrecorded_marker" \
  'protocol Clawdstrike marker is not recorded: crates/core/unrecorded/src/lib.rs' \
  "unrecorded-marker"

invalid_utf8_candidate="$(clone_case invalid-utf8-candidate)"
python3 - "$invalid_utf8_candidate" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "crates/core/invalid-utf8/src/lib.rs"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(b"\xff")
PY
assert_failure "$invalid_utf8_candidate" \
  'protocol provenance candidate is not valid UTF-8: crates/core/invalid-utf8/src/lib.rs' \
  "invalid-utf8-candidate"

unreadable_candidate="$(clone_case unreadable-candidate)"
mkdir -p "$unreadable_candidate/crates/core/unreadable/src"
printf '%s\n' '// protocol provenance unreadable fixture' \
  >"$unreadable_candidate/crates/core/unreadable/src/lib.rs"
chmod 000 "$unreadable_candidate/crates/core/unreadable/src/lib.rs"
assert_failure "$unreadable_candidate" \
  'protocol provenance candidate could not be read: crates/core/unreadable/src/lib.rs:' \
  "unreadable-candidate"

unexpected_field="$(clone_case unexpected-field)"
python3 - "$unexpected_field/third_party/provenance/clawdstrike-protocol-primitives.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8") + "unexpected = true\n", encoding="utf-8")
PY
assert_failure "$unexpected_field" \
  'Spine and AegisNet exclusion field inventory mismatch' "unexpected-field"

printf 'check-protocol-provenance.test.sh: all assertions passed\n'
