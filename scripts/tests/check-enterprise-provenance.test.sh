#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-enterprise-provenance.py"
SOURCE_COMMIT="666303e5f3428f3b6e6b72f118c269a02388e0a4"

work="$(mktemp -d -t chio-enterprise-provenance-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_record() {
  local root="$1" commit="$2" omit="$3"
  mkdir -p "$root/third_party/provenance"
  python3 - "$root" "$commit" "$omit" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
commit = sys.argv[2]
omit = sys.argv[3]
destination = "crates/security/example/src/lib.rs"
sources = {
    "crates/libs/clawdstrike-broker-protocol/src/lib.rs": "f0a1db48826f7a11bd3a8a741f93fd7f106e12fa",
    "crates/services/clawdstrike-brokerd/src/capability.rs": "3e0461594f4dbb85c640e91ab42cd14c93ba04d8",
    "crates/services/clawdstrike-brokerd/src/provider/generic_https.rs": "95f76e68053b12438bad1943cb030c55865c8f89",
    "crates/libs/clawdstrike/src/pkg/merkle.rs": "8cd306a1b4b589687b003ccc153ad71cd87af891",
    "crates/services/clawdstrike-registry/src/keys.rs": "2d64c39aaa1e6dbf83dc9e54e9e78ea482df963e",
    "crates/services/clawdstrike-registry/src/bin/audit-monitor.rs": "dcdbf352603ff55f1887b38bc4ca292bcd3a1008",
    "crates/libs/clawdstrike/src/sandbox/capability_builder.rs": "97ae47a40eabb8b8ae35169bf44a0298652cf983",
    "crates/libs/clawdstrike/src/sandbox/preflight.rs": "5abe9620cda286b58ef933a201afe86704050bd7",
    "crates/services/hush-cli/src/sandbox_nono.rs": "ae5bc38c7b00e21b6d6b9cfc4dfa02e0c3e50f23",
    "crates/services/hush-cli/src/supervised_exec.rs": "8a2b8b8cad3ff35c78daea86594cc766c6d57cfe",
    "infra/vendor/nono/": "241cac3a3f59fb1d60ec8c460bbd5238bc693055",
}
lines = [
    'schema = "chio.enterprise-provenance.v1"',
    'source_repository = "https://github.com/backbay-labs/clawdstrike"',
    f'source_commit = "{commit}"',
    'license = "Apache-2.0"',
    'source_notice = "ClawdStrike; Copyright 2026 Backbay Industries"',
    'notice_update_required = false',
    'reviewer = "security implementation review"',
    'reviewed_at = "2026-07-12"',
    '',
]
for source, source_blob in sources.items():
    if source == omit:
        continue
    unused = source == "infra/vendor/nono/"
    lines.extend([
        '[[inputs]]',
        f'source_path = "{source}"',
        f'source_blob = "{source_blob}"',
        'destinations = []' if unused else f'destinations = ["{destination}"]',
        'reuse = "no_use"' if unused else 'reuse = "concept"',
        'copied = false',
        'modifications = "Chio-native types and invariants"',
        '',
    ])
lines.extend([
    '[excluded_spine]',
    'source_path = "crates/libs/spine/"',
    'named_upstream = "AegisNet"',
    'license_verified = false',
    'copied = false',
])
(root / "third_party/provenance/clawdstrike-enterprise-hardening.toml").write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)
target = root / destination
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("// provenance fixture\n", encoding="utf-8")
PY
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  printf '%s\n' "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL: %s: got rc=%s, want rc=%s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'ok: %s (rc=%s)\n' "$label" "$got"
}

wrong_commit="$work/wrong-commit"
write_record "$wrong_commit" "0000000000000000000000000000000000000000" ""
assert_rc "$(run_checker "$wrong_commit" "$work/wrong.out" "$work/wrong.err")" 1 \
  "an unreviewed commit fails"
grep -F 'source_commit does not match the reviewed commit' "$work/wrong.err" >/dev/null

wrong_blob="$work/wrong-blob"
write_record "$wrong_blob" "$SOURCE_COMMIT" ""
python3 -c 'from pathlib import Path; p=Path("'$wrong_blob'/third_party/provenance/clawdstrike-enterprise-hardening.toml"); s=p.read_text(); p.write_text(s.replace("f0a1db48826f7a11bd3a8a741f93fd7f106e12fa", "0000000000000000000000000000000000000000", 1))'
assert_rc "$(run_checker "$wrong_blob" "$work/wrong-blob.out" "$work/wrong-blob.err")" 1 \
  "a source blob outside the reviewed tree fails"
grep -F 'source blob does not match the reviewed commit' "$work/wrong-blob.err" >/dev/null

missing_source="$work/missing-source"
write_record "$missing_source" "$SOURCE_COMMIT" \
  "crates/services/clawdstrike-registry/src/keys.rs"
assert_rc "$(run_checker "$missing_source" "$work/missing.out" "$work/missing.err")" 1 \
  "an omitted source fails"
grep -F 'source inventory mismatch' "$work/missing.err" >/dev/null

missing_destination="$work/missing-destination"
write_record "$missing_destination" "$SOURCE_COMMIT" ""
rm "$missing_destination/crates/security/example/src/lib.rs"
assert_rc "$(run_checker "$missing_destination" "$work/missing-destination.out" "$work/missing-destination.err")" 1 \
  "a missing behavioral destination fails"
grep -F 'destination does not exist: crates/security/example/src/lib.rs' \
  "$work/missing-destination.err" >/dev/null

valid="$work/valid"
write_record "$valid" "$SOURCE_COMMIT" ""
assert_rc "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "the complete reviewed record passes"
grep -F 'enterprise provenance check passed' "$work/valid.out" >/dev/null

printf 'check-enterprise-provenance.test.sh: all assertions passed\n'
