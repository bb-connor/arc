#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-stub-surfaces.py"

work="$(mktemp -d -t chio-stub-surfaces-XXXXXX)"
trap 'rm -rf "$work"' EXIT

init_case() {
  local root="$1"
  mkdir -p "$root"
  git -C "$root" init -q
}

track_case() {
  local root="$1"
  git -C "$root" add .
}

write_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  shift
  printf '%s\n' "$@" > "$path"
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

non_production="$work/non-production"
vendored_comments="$work/vendored-comments"
init_case "$vendored_comments"
write_file "$vendored_comments/third_party/aws-lc-rs-chio/src/cipher.rs" \
  "// TODO: Hopefully support CFB1, and CFB8"
track_case "$vendored_comments"
assert_rc "$(run_checker "$vendored_comments" "$work/vendor.out" "$work/vendor.err")" 0 \
  "reviewed upstream comment is allowed"
write_file "$vendored_comments/third_party/aws-lc-rs-chio/src/cipher.rs" \
  "// TODO: Hopefully support CFB1, and CFB8" \
  'pub fn encrypt() { unimplemented!(); }'
assert_rc "$(run_checker "$vendored_comments" "$work/vendor-code.out" "$work/vendor-code.err")" 1 \
  "vendored executable incomplete implementation still fails"

vendored_other="$work/vendored-other"
init_case "$vendored_other"
write_file "$vendored_other/third_party/regress-chio/src/bytesearch.rs" \
  "// TODO."
write_file "$vendored_other/third_party/ignore-chio/src/walk.rs" \
  "// Placeholder implementation to allow compiling on non-standard platforms"
track_case "$vendored_other"
assert_rc "$(run_checker "$vendored_other" "$work/vendor-other.out" "$work/vendor-other.err")" 0 \
  "exact reviewed dependency comments are allowed"
write_file "$vendored_other/third_party/regress-chio/src/bytesearch.rs" \
  "// TODO." \
  "// TODO: skip validation"
assert_rc "$(run_checker "$vendored_other" "$work/vendor-new-comment.out" "$work/vendor-new-comment.err")" 1 \
  "new dependency TODO remains rejected"
write_file "$vendored_other/third_party/regress-chio/src/bytesearch.rs" \
  "// TODO." \
  'pub fn search() { todo!(); }'
assert_rc "$(run_checker "$vendored_other" "$work/vendor-new-code.out" "$work/vendor-new-code.err")" 1 \
  "new dependency executable TODO remains rejected"

patch_context="$work/patch-context"
init_case "$patch_context"
write_file "$patch_context/third_party/aws-lc-rs-chio/CHIO-PATCH.patch.json" \
  '[' '  " // TODO: Uncomment when MSRV >= 1.64\n",' '  " context\n"' ']'
track_case "$patch_context"
assert_rc "$(run_checker "$patch_context" "$work/patch-context.out" "$work/patch-context.err")" 0 \
  "serialized reviewed upstream context comment is allowed"
write_file "$patch_context/third_party/aws-lc-rs-chio/CHIO-PATCH.patch.json" \
  '[' '  "+// TODO: Uncomment when MSRV >= 1.64\n",' '  " context\n"' ']'
assert_rc "$(run_checker "$patch_context" "$work/patch-addition.out" "$work/patch-addition.err")" 1 \
  "new patch additions cannot borrow the context exception"
write_file "$patch_context/third_party/aws-lc-rs-chio/CHIO-PATCH.patch.json" \
  '[' '  " // TODO: bypass validation\n",' '  " context\n"' ']'
assert_rc "$(run_checker "$patch_context" "$work/patch-new-comment.out" "$work/patch-new-comment.err")" 1 \
  "other serialized upstream comments still require review"

init_case "$non_production"
write_file "$non_production/docs/example.md" "TODO: documented follow-up"
write_file "$non_production/tests/replay.rs" "fn test_stub() {}"
write_file "$non_production/examples/demo/src/main.rs" "fn main() { /* placeholder */ }"
write_file "$non_production/scripts/example.sh" "# FIXME: script fixture"
write_file "$non_production/crates/chio-demo/src/_generated/wire.rs" "// not_yet_implemented generated fixture"
write_file "$non_production/fuzz/corpus/peers_lock_decode/shipped-lockfile.toml" \
  "# Unpublished peer placeholder in parser input, not executable code"
track_case "$non_production"
assert_rc "$(run_checker "$non_production" "$work/non-production.out" "$work/non-production.err")" 0 \
  "non-production stub-surface hits pass"
grep -F "Stub-surface check passed" "$work/non-production.out" >/dev/null

production_fail="$work/production-fail"
init_case "$production_fail"
write_file "$production_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    // TODO: replace placeholder implementation" \
  "}"
write_file "$production_fail/fuzz/corpus_support/src/lib.rs" \
  "pub fn parse() { todo!(); }"
track_case "$production_fail"
assert_rc "$(run_checker "$production_fail" "$work/production-fail.out" "$work/production-fail.err")" 1 \
  "unallowlisted production stub hit fails"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/production-fail.err" >/dev/null
grep -F "fuzz/corpus_support/src/lib.rs:1" \
  "$work/production-fail.err" >/dev/null

lowercase_fail="$work/lowercase-fail"
init_case "$lowercase_fail"
write_file "$lowercase_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    todo!(\"wire production evaluator\");" \
  "}" \
  "pub fn parse() {" \
  "    unimplemented!(\"parse policy input\");" \
  "}"
track_case "$lowercase_fail"
assert_rc "$(run_checker "$lowercase_fail" "$work/lowercase-fail.out" "$work/lowercase-fail.err")" 1 \
  "lowercase Rust todo and unimplemented macros fail"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/lowercase-fail.err" >/dev/null

tracked_non_prefix_fail="$work/tracked-non-prefix-fail"
init_case "$tracked_non_prefix_fail"
write_file "$tracked_non_prefix_fail/sdks/rust/chio-demo/src/lib.rs" \
  "pub fn adapter() {" \
  "    // TODO: replace placeholder SDK adapter" \
  "}"
track_case "$tracked_non_prefix_fail"
assert_rc "$(run_checker "$tracked_non_prefix_fail" "$work/tracked-non-prefix-fail.out" "$work/tracked-non-prefix-fail.err")" 1 \
  "tracked production files outside old prefixes fail"
grep -F "sdks/rust/chio-demo/src/lib.rs:2" \
  "$work/tracked-non-prefix-fail.err" >/dev/null

untracked_production_fail="$work/untracked-production-fail"
init_case "$untracked_production_fail"
write_file "$untracked_production_fail/crates/chio-demo/src/lib.rs" \
  "pub fn evaluate() {" \
  "    // TODO: untracked production placeholder" \
  "}"
assert_rc "$(run_checker "$untracked_production_fail" "$work/untracked-production-fail.out" "$work/untracked-production-fail.err")" 1 \
  "untracked production stub hit fails"
grep -F "crates/chio-demo/src/lib.rs:2" \
  "$work/untracked-production-fail.err" >/dev/null

session_split_allow="$work/session-split-allow"
init_case "$session_split_allow"
write_file "$session_split_allow/crates/products/chio-cli/src/cli/session/test_support.rs" \
  "serde_json::json!({" \
  "  \"stub\": true," \
  "})"
track_case "$session_split_allow"
assert_rc "$(run_checker "$session_split_allow" "$work/session-split-allow.out" "$work/session-split-allow.err")" 0 \
  "split session test support stub payload is allowlisted"
grep -F "Stub-surface check passed" "$work/session-split-allow.out" >/dev/null

federation_bbs_stub="$work/federation-bbs-stub"
init_case "$federation_bbs_stub"
write_file "$federation_bbs_stub/crates/trust/chio-federation/src/selective_disclosure.rs" \
  "#[cfg(feature = \"bbs-stub\")]" \
  "pub fn project() { /* bbs-stub placeholder projection */ }"
track_case "$federation_bbs_stub"
assert_rc "$(run_checker "$federation_bbs_stub" "$work/federation-bbs-stub.out" "$work/federation-bbs-stub.err")" 1 \
  "bbs-stub production feature surface fails"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/federation-bbs-stub.err" >/dev/null

federation_unrelated="$work/federation-unrelated"
init_case "$federation_unrelated"
write_file "$federation_unrelated/crates/trust/chio-federation/src/selective_disclosure.rs" \
  "#[cfg(feature = \"bbs-stub\")]" \
  "pub fn project() { /* bbs-stub placeholder projection */ }" \
  "pub fn unrelated() { /* TODO: unrelated production work */ }"
track_case "$federation_unrelated"
assert_rc "$(run_checker "$federation_unrelated" "$work/federation-unrelated.out" "$work/federation-unrelated.err")" 1 \
  "bbs-stub federation file rejects unrelated production TODO"
grep -F "production stub-surface hit is not allowlisted" \
  "$work/federation-unrelated.err" >/dev/null

guard_unrelated="$work/guard-unrelated"
init_case "$guard_unrelated"
write_file "$guard_unrelated/crates/products/chio-cli/src/guard/new.rs" \
  "// Replace this stub with real policy logic before shipping." \
  "pub fn unrelated() { /* TODO: unrelated production work */ }"
track_case "$guard_unrelated"
assert_rc "$(run_checker "$guard_unrelated" "$work/guard-unrelated.out" "$work/guard-unrelated.err")" 1 \
  "allowlisted guard file rejects unrelated production TODO"
grep -F "does not match reviewed allowlist patterns" \
  "$work/guard-unrelated.err" >/dev/null

sidecar_deny="$work/sidecar-deny"
init_case "$sidecar_deny"
write_file "$sidecar_deny/crates/products/chio-api-protect/src/proxy/sidecar.rs" \
  "// Capability attenuation (501 not_yet_implemented stub)"
track_case "$sidecar_deny"
assert_rc "$(run_checker "$sidecar_deny" "$work/sidecar-deny.out" "$work/sidecar-deny.err")" 1 \
  "sidecar attenuation stub remains a hard failure"
grep -F "crates/products/chio-api-protect/src/proxy/sidecar.rs:1" "$work/sidecar-deny.err" >/dev/null
grep -F "production stub-surface hit is not allowlisted" "$work/sidecar-deny.err" >/dev/null

supply_chain_names="$work/supply-chain-names"
init_case "$supply_chain_names"
write_file "$supply_chain_names/supply-chain/config.toml" \
  "[[exemptions.bollard-stubs]]" \
  "[[exemptions.proc-macro-hack]]"
track_case "$supply_chain_names"
assert_rc "$(run_checker "$supply_chain_names" "$work/supply-chain-names.out" "$work/supply-chain-names.err")" 0 \
  "reviewed cargo-vet package names pass"

supply_chain_unrelated="$work/supply-chain-unrelated"
init_case "$supply_chain_unrelated"
write_file "$supply_chain_unrelated/supply-chain/config.toml" \
  "[[exemptions.proc-macro-hack]] # TODO: bypass package review"
track_case "$supply_chain_unrelated"
assert_rc "$(run_checker "$supply_chain_unrelated" "$work/supply-chain-unrelated.out" "$work/supply-chain-unrelated.err")" 1 \
  "cargo-vet package-name exception rejects trailing text"
grep -F "does not match reviewed allowlist patterns" \
  "$work/supply-chain-unrelated.err" >/dev/null

denied_lints="$work/denied-lints"
init_case "$denied_lints"
write_file "$denied_lints/crates/chio-demo/src/lib.rs" \
  '#![deny(clippy::todo)]' \
  '#![cfg_attr(' \
  '    not(test),' \
  '    deny(' \
  '        clippy::indexing_slicing,' \
  '        clippy::todo,' \
  '        clippy::unimplemented,' \
  '    )' \
  ')]' \
  '#[forbid(clippy::todo, clippy::unimplemented)]' \
  'pub fn evaluate() {}'
track_case "$denied_lints"
assert_rc "$(run_checker "$denied_lints" "$work/denied-lints.out" "$work/denied-lints.err")" 0 \
  "exact todo selectors in denying lint attributes pass"

lint_case=0
for body in \
  'clippy::todo,' \
  '#![allow(clippy::todo)]' \
  '#![warn(clippy::todo)]' \
  '#![cfg_attr(test, deny(clippy::todo))]' \
  '#![cfg_attr(any(), deny(clippy::todo))]' \
  '#![deny(clippy::todo, todo)]' \
  '#![deny(clippy::todo)] // TODO: wire enforcement' \
  '#![deny(clippy::todo)] pub fn evaluate() { todo!(); }' \
  '#![deny(clippy::todo)] pub fn evaluate() { unimplemented!(); }' \
  '#![deny(clippy::todo!())]' \
  '#![deny(clippy::todo' \
  'pub fn evaluate() { clippy::todo!(); }'; do
  lint_case=$((lint_case + 1))
  write_file "$denied_lints/crates/chio-demo/src/lib.rs" "$body"
  assert_rc "$(run_checker "$denied_lints" "$work/lint-$lint_case.out" "$work/lint-$lint_case.err")" 1 \
    "lint selector classification rejects hostile case $lint_case"
done
write_file "$denied_lints/crates/chio-demo/src/lib.rs" \
  '#![cfg_attr(not(test), deny(clippy::todo))]' \
  'pub fn evaluate() { todo!(); }' \
  'pub fn parse() { unimplemented!(); }'
assert_rc "$(run_checker "$denied_lints" "$work/denied-live.out" "$work/denied-live.err")" 1 \
  "denying attributes do not hide subsequent executable macros"
grep -F 'pub fn evaluate() { todo!(); }' "$work/denied-live.err" >/dev/null
grep -F 'pub fn parse() { unimplemented!(); }' "$work/denied-live.err" >/dev/null
grep -F 'crates/chio-demo/src/lib.rs:2:' "$work/denied-live.err" >/dev/null
grep -F 'crates/chio-demo/src/lib.rs:3:' "$work/denied-live.err" >/dev/null

non_rust_lints="$work/non-rust-lints"
init_case "$non_rust_lints"
write_file "$non_rust_lints/.config/example.toml" '#![deny(clippy::todo)]'
track_case "$non_rust_lints"
assert_rc "$(run_checker "$non_rust_lints" "$work/non-rust-lints.out" "$work/non-rust-lints.err")" 1 \
  "Rust lint syntax is not an exception in non-Rust files"

review_case=0
while IFS='|' read -r reviewed_path reviewed_text; do
  review_case=$((review_case + 1))
  reviewed="$work/reviewed-$review_case"
  init_case "$reviewed"
  write_file "$reviewed/$reviewed_path" "$reviewed_text"
  track_case "$reviewed"
  assert_rc "$(run_checker "$reviewed" "$work/review-$review_case.out" "$work/review-$review_case.err")" 0 \
    "reviewed description $review_case matches exact text and owner"
  write_file "$reviewed/$reviewed_path" "$reviewed_text TODO: bypass validation"
  assert_rc "$(run_checker "$reviewed" "$work/review-changed-$review_case.out" "$work/review-changed-$review_case.err")" 1 \
    "reviewed description $review_case rejects changed text"
  write_file "$reviewed/$reviewed_path" "$reviewed_text" \
    'pub fn evaluate() { todo!(); }' \
    'pub fn parse() { unimplemented!(); }'
  assert_rc "$(run_checker "$reviewed" "$work/review-code-$review_case.out" "$work/review-code-$review_case.err")" 1 \
    "reviewed description $review_case cannot allow executable incomplete code"
  grep -F 'pub fn evaluate() { todo!(); }' "$work/review-code-$review_case.err" >/dev/null
  grep -F 'pub fn parse() { unimplemented!(); }' "$work/review-code-$review_case.err" >/dev/null
  write_file "$reviewed/$reviewed_path" "$reviewed_text"
  write_file "$reviewed/crates/chio-other/src/lib.rs" "$reviewed_text"
  assert_rc "$(run_checker "$reviewed" "$work/review-copy-$review_case.out" "$work/review-copy-$review_case.err")" 1 \
    "reviewed description $review_case cannot move to an unreviewed path"
done <<'REVIEWED'
.config/miri-crates.toml|reason = "syscall: memfd_create (aarch64 number 279) is not implemented by Miri"
crates/core/chio-response-model/src/simulation.rs|// A local model placeholder, never installed or passed to a port.
crates/platform/chio-store-sqlite/src/receipt_query/read.rs|// but must still bind placeholders if we reuse `params!`;
REVIEWED

obsolete="$work/obsolete"
init_case "$obsolete"
write_file "$obsolete/crates/core/chio-core-types/src/crypto.rs" \
  '// 32-byte placeholder'
write_file "$obsolete/crates/kernel/chio-kernel-browser/src/clock.rs" \
  '// stub intentionally returns `0`'
write_file "$obsolete/crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs" \
  '// but must still bind placeholders if we reuse `params!`;'
track_case "$obsolete"
assert_rc "$(run_checker "$obsolete" "$work/obsolete.out" "$work/obsolete.err")" 1 \
  "obsolete allowances cannot be revived at prior owners"
grep -F 'crates/core/chio-core-types/src/crypto.rs:1' "$work/obsolete.err" >/dev/null
grep -F 'crates/kernel/chio-kernel-browser/src/clock.rs:1' "$work/obsolete.err" >/dev/null
grep -F 'crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs:1' "$work/obsolete.err" >/dev/null

echo "check-stub-surfaces.test.sh: all assertions passed"
