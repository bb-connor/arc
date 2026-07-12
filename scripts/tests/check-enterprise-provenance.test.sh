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
sources = [
    "crates/libs/clawdstrike-broker-protocol/src/lib.rs",
    "crates/services/clawdstrike-brokerd/src/capability.rs",
    "crates/services/clawdstrike-brokerd/src/provider/generic_https.rs",
    "crates/libs/clawdstrike/src/pkg/merkle.rs",
    "crates/services/clawdstrike-registry/src/keys.rs",
    "crates/services/clawdstrike-registry/src/bin/audit-monitor.rs",
    "crates/libs/clawdstrike/src/sandbox/capability_builder.rs",
    "crates/libs/clawdstrike/src/sandbox/preflight.rs",
    "crates/services/hush-cli/src/sandbox_nono.rs",
    "crates/services/hush-cli/src/supervised_exec.rs",
    "infra/vendor/nono/",
]
lines = [
    'schema = "chio.enterprise-provenance.v1"',
    'source_repository = "/reviewed/clawdstrike"',
    f'source_commit = "{commit}"',
    'license = "Apache-2.0"',
    'source_notice = "ClawdStrike; Copyright 2026 Backbay Industries"',
    'notice_update_required = false',
    'reviewer = "security implementation review"',
    'reviewed_at = "2026-07-12"',
    '',
]
for source in sources:
    if source == omit:
        continue
    lines.extend([
        '[[inputs]]',
        f'source_path = "{source}"',
        'destinations = ["crates/security/example/src/lib.rs"]',
        'reuse = "concept"',
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

missing_source="$work/missing-source"
write_record "$missing_source" "$SOURCE_COMMIT" \
  "crates/services/clawdstrike-registry/src/keys.rs"
assert_rc "$(run_checker "$missing_source" "$work/missing.out" "$work/missing.err")" 1 \
  "an omitted source fails"
grep -F 'source inventory mismatch' "$work/missing.err" >/dev/null

valid="$work/valid"
write_record "$valid" "$SOURCE_COMMIT" ""
assert_rc "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "the complete reviewed record passes"
grep -F 'enterprise provenance check passed' "$work/valid.out" >/dev/null

printf 'check-enterprise-provenance.test.sh: all assertions passed\n'
