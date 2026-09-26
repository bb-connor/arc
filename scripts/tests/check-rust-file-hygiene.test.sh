#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-rust-file-hygiene.py"

work="$(mktemp -d -t chio-rust-file-hygiene-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_lines() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub fn marker_" i "() {}" }' > "$path"
}

write_module_with_includes() {
  local path="$1" count="$2"
  shift 2
  mkdir -p "$(dirname "$path")"
  {
    for target in "$@"; do
      printf 'include!("%s");\n' "$target"
    done
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub fn marker_" i "() {}" }'
  } > "$path"
}

write_codegen_header_source() {
  local root="$1"
  mkdir -p "$root/crates/tooling/chio-spec-codegen/src"
  cat > "$root/crates/tooling/chio-spec-codegen/src/lib.rs" <<'EOF'
pub const GENERATED_HEADER: &str = "\
// DO NOT EDIT - test generated header.
//
// Source: test/schema.json
";
EOF
  cat > "$root/crates/tooling/chio-spec-codegen/src/errors_pass.rs" <<'EOF'
const ERROR_CODES_GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml
";
EOF
}

write_generated_wire() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    cat <<'EOF'
// DO NOT EDIT - test generated header.
//
// Source: test/schema.json

EOF
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub fn marker_" i "() {}" }'
  } > "$path"
}

write_generated_errors() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    cat <<'EOF'
// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml

EOF
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "pub const ERROR_" i ": &str = \"E\";" }'
  } > "$path"
}

init_case() {
  local root="$1"
  mkdir -p "$root"
  git -C "$root" init -q
  write_codegen_header_source "$root"
}

track_case() {
  local root="$1"
  git -C "$root" add .
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

run_checker_script() {
  local checker="$1" root="$2" stdout="$3" stderr="$4"
  local rc=0
  python3 "$checker" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
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

pass_case="$work/pass"
init_case "$pass_case"
write_lines "$pass_case/crates/chio-small/src/main.rs" 25
write_lines "$pass_case/crates/chio-small/tests/large.rs" 1999
write_generated_wire "$pass_case/crates/core/chio-core-types/src/_generated/chio_wire_v1.rs" 3001
write_generated_errors "$pass_case/crates/core/chio-errors/src/_generated/error_codes.rs" 2501
track_case "$pass_case"
assert_rc "$(run_checker "$pass_case" "$work/pass.out" "$work/pass.err")" 0 \
  "small production plus bounded test/generated files with canonical header pass"
grep -F "generated top" "$work/pass.out" >/dev/null
grep -F "test top" "$work/pass.out" >/dev/null

warn_production="$work/warn-production"
init_case "$warn_production"
write_lines "$warn_production/crates/chio-small/src/main.rs" 1201
write_lines "$warn_production/crates/chio-small/src/lib.rs" 901
track_case "$warn_production"
assert_rc "$(run_checker "$warn_production" "$work/warn-production.out" "$work/warn-production.err")" 0 \
  "soft-limit production and lib root files warn without failing"
grep -F "warning: crates/chio-small/src/lib.rs has 901 lines, warn limit is 900" \
  "$work/warn-production.out" >/dev/null
grep -F "warning: crates/chio-small/src/main.rs has 1201 lines, warn limit is 1200" \
  "$work/warn-production.out" >/dev/null
grep -F "Rust file hygiene warnings: 2 files exceed warning limits" \
  "$work/warn-production.out" >/dev/null

large_test="$work/large-test"
init_case "$large_test"
write_lines "$large_test/crates/chio-small/src/main.rs" 25
write_lines "$large_test/crates/chio-small/tests/large.rs" 2001
track_case "$large_test"
assert_rc "$(run_checker "$large_test" "$work/large-test.out" "$work/large-test.err")" 1 \
  "oversized unallowlisted test file fails"
grep -F "crates/chio-small/tests/large.rs: test file has 2001 lines" \
  "$work/large-test.err" >/dev/null

allowlist_growth="$work/allowlist-growth"
init_case "$allowlist_growth"
write_lines "$allowlist_growth/crates/chio-small/src/main.rs" 25
mcp_cap="$(python3 - "$CHECKER" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
entry = re.search(
    r'"crates/products/chio-cli/tests/mcp_serve_http\.rs": allow\((?:[^)]*?)max_lines=([0-9_]+)',
    source,
    re.S,
)
print(int(entry.group(1).replace("_", "")))
PY
)"
write_lines "$allowlist_growth/crates/products/chio-cli/tests/mcp_serve_http.rs" "$((mcp_cap + 1))"
track_case "$allowlist_growth"
assert_rc "$(run_checker "$allowlist_growth" "$work/allowlist-growth.out" "$work/allowlist-growth.err")" 1 \
  "oversized allowlisted test file cannot grow past cap"
grep -F "crates/products/chio-cli/tests/mcp_serve_http.rs: allowlisted file has $((mcp_cap + 1)) lines, cap is $mcp_cap" \
  "$work/allowlist-growth.err" >/dev/null

bad_generated="$work/bad-generated"
init_case "$bad_generated"
write_lines "$bad_generated/crates/chio-small/src/main.rs" 25
write_lines "$bad_generated/crates/core/chio-core-types/src/_generated/chio_wire_v1.rs" 25
track_case "$bad_generated"
assert_rc "$(run_checker "$bad_generated" "$work/bad-generated.out" "$work/bad-generated.err")" 1 \
  "generated wire file without canonical header fails"
grep -F "crates/core/chio-core-types/src/_generated/chio_wire_v1.rs: generated Rust file does not begin with chio_spec_codegen::GENERATED_HEADER" \
  "$work/bad-generated.err" >/dev/null

bad_error_generated="$work/bad-error-generated"
init_case "$bad_error_generated"
write_lines "$bad_error_generated/crates/chio-small/src/main.rs" 25
write_lines "$bad_error_generated/crates/core/chio-errors/src/_generated/error_codes.rs" 2501
track_case "$bad_error_generated"
assert_rc "$(run_checker "$bad_error_generated" "$work/bad-error-generated.out" "$work/bad-error-generated.err")" 1 \
  "generated error-code file without canonical header fails"
grep -F "crates/core/chio-errors/src/_generated/error_codes.rs: generated Rust file does not begin with chio_spec_codegen::errors_pass::ERROR_CODES_GENERATED_HEADER" \
  "$work/bad-error-generated.err" >/dev/null

em_dash_doc="$work/em-dash-doc"
init_case "$em_dash_doc"
write_lines "$em_dash_doc/crates/chio-small/src/main.rs" 25
mkdir -p "$em_dash_doc/docs"
printf 'bad \342\200\224 dash\n' > "$em_dash_doc/docs/guide.md"
track_case "$em_dash_doc"
assert_rc "$(run_checker "$em_dash_doc" "$work/em-dash-doc.out" "$work/em-dash-doc.err")" 1 \
  "tracked docs with U+2014 fail text hygiene"
grep -F "docs/guide.md:1:5: contains U+2014 em dash" \
  "$work/em-dash-doc.err" >/dev/null

large_production="$work/large-production"
init_case "$large_production"
write_lines "$large_production/crates/chio-small/src/main.rs" 2001
track_case "$large_production"
assert_rc "$(run_checker "$large_production" "$work/large-production.out" "$work/large-production.err")" 1 \
  "oversized production file fails"
grep -F "crates/chio-small/src/main.rs: production file has 2001 lines" \
  "$work/large-production.err" >/dev/null

large_untracked_production="$work/large-untracked-production"
init_case "$large_untracked_production"
write_lines "$large_untracked_production/crates/chio-small/src/main.rs" 25
track_case "$large_untracked_production"
write_lines "$large_untracked_production/crates/chio-small/src/untracked.rs" 2001
assert_rc "$(run_checker "$large_untracked_production" "$work/large-untracked-production.out" "$work/large-untracked-production.err")" 1 \
  "oversized untracked production file fails"
grep -F "crates/chio-small/src/untracked.rs: production file has 2001 lines" \
  "$work/large-untracked-production.err" >/dev/null

large_lib="$work/large-lib"
init_case "$large_lib"
write_lines "$large_lib/crates/chio-small/src/lib.rs" 1001
track_case "$large_lib"
assert_rc "$(run_checker "$large_lib" "$work/large-lib.out" "$work/large-lib.err")" 1 \
  "oversized lib root fails"
grep -F "crates/chio-small/src/lib.rs: src/lib.rs has 1001 lines" \
  "$work/large-lib.err" >/dev/null

unallowlisted_production="$work/unallowlisted-production"
init_case "$unallowlisted_production"
write_lines "$unallowlisted_production/crates/trust/chio-governance/src/lib.rs" 2101
track_case "$unallowlisted_production"
assert_rc "$(run_checker "$unallowlisted_production" "$work/unallowlisted-production.out" "$work/unallowlisted-production.err")" 1 \
  "unallowlisted oversized production file fails"
grep -F "crates/trust/chio-governance/src/lib.rs: production file has 2101 lines" \
  "$work/unallowlisted-production.err" >/dev/null

expired_allowlist="$work/expired-allowlist"
init_case "$expired_allowlist"
write_lines "$expired_allowlist/crates/chio-small/src/main.rs" 25
track_case "$expired_allowlist"
expired_checker="$work/expired-check-rust-file-hygiene.py"
sed -E 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}"/"2000-01-01"/g' "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker_script "$expired_checker" "$expired_allowlist" "$work/expired-allowlist.out" "$work/expired-allowlist.err")" 1 \
  "expired allowlist date fails"
grep -F "allowlist entry expired on 2000-01-01" \
  "$work/expired-allowlist.err" >/dev/null

orphan_example="$work/orphan-example"
init_case "$orphan_example"
write_lines "$orphan_example/examples/orphan/src/lib.rs" 25
track_case "$orphan_example"
assert_rc "$(run_checker "$orphan_example" "$work/orphan-example.out" "$work/orphan-example.err")" 1 \
  "Rust example source without a Cargo package fails"
grep -F "examples/orphan: contains Rust src files but has no Cargo.toml" \
  "$work/orphan-example.err" >/dev/null

large_example="$work/large-example"
init_case "$large_example"
write_lines "$large_example/examples/oversized/src/main.rs" 3000
cat > "$large_example/examples/oversized/Cargo.toml" <<'EOF'
[package]
name = "oversized-example"
version = "0.0.0"
edition = "2021"
EOF
track_case "$large_example"
assert_rc "$(run_checker "$large_example" "$work/large-example.out" "$work/large-example.err")" 0 \
  "large example file is classified separately"
grep -F "example top" "$work/large-example.out" >/dev/null

stale_allowlist="$work/stale-allowlist"
init_case "$stale_allowlist"
write_lines "$stale_allowlist/crates/products/chio-cli/tests/mcp_serve_http.rs" 1
track_case "$stale_allowlist"
assert_rc "$(run_checker "$stale_allowlist" "$work/stale-allowlist.out" "$work/stale-allowlist.err")" 1 \
  "an allowlist entry whose file is back under its base limit fails"
grep -F "remove its allowlist entry" "$work/stale-allowlist.err" >/dev/null

vendored_generated="$work/vendored-generated"
init_case "$vendored_generated"
for path in third_party/regress-chio/src/unicodetables.rs third_party/regress-chio/tests/unicode_property_escapes.rs; do
  mkdir -p "$vendored_generated/$(dirname "$path")"
  cp "$REPO_ROOT/$path" "$vendored_generated/$path"
done
track_case "$vendored_generated"
assert_rc "$(run_checker "$vendored_generated" "$work/vendored.out" "$work/vendored.err")" 0 \
  "reviewed upstream generated bytes pass"
for path in third_party/regress-chio/src/unicodetables.rs third_party/regress-chio/tests/unicode_property_escapes.rs; do
  printf '\n// changed generated source\n' >> "$vendored_generated/$path"
  assert_rc "$(run_checker "$vendored_generated" "$work/tampered.out" "$work/tampered.err")" 1 \
    "generated header does not excuse a changed upstream file"
  grep -F 'vendored generated source differs from reviewed archive' "$work/tampered.err" >/dev/null
  cp "$REPO_ROOT/$path" "$vendored_generated/$path"
done
write_lines "$vendored_generated/third_party/regress-chio/src/other.rs" 2001
assert_rc "$(run_checker "$vendored_generated" "$work/vendor-handwritten.out" "$work/vendor-handwritten.err")" 1 \
  "other vendored Rust remains subject to the size limit"

assembled_over_limit="$work/assembled-over-limit"
init_case "$assembled_over_limit"
write_module_with_includes "$assembled_over_limit/crates/chio-small/src/module.rs" 1500 \
  "module_parts/part.inc"
write_lines "$assembled_over_limit/crates/chio-small/src/module_parts/part.inc" 600
track_case "$assembled_over_limit"
assert_rc "$(run_checker "$assembled_over_limit" "$work/assembled-over-limit.out" "$work/assembled-over-limit.err")" 1 \
  "a parent under the cap fails once its include! fragment is counted"
grep -F "crates/chio-small/src/module.rs: production file has 2101 lines (1501 own plus 1 include! fragments), limit is 2000" \
  "$work/assembled-over-limit.err" >/dev/null

assembled_nested="$work/assembled-nested"
init_case "$assembled_nested"
write_module_with_includes "$assembled_nested/crates/chio-small/src/module.rs" 10 \
  "module_parts/mid.inc"
write_module_with_includes "$assembled_nested/crates/chio-small/src/module_parts/mid.inc" 10 \
  "deep.inc"
write_lines "$assembled_nested/crates/chio-small/src/module_parts/deep.inc" 2100
track_case "$assembled_nested"
assert_rc "$(run_checker "$assembled_nested" "$work/assembled-nested.out" "$work/assembled-nested.err")" 1 \
  "include! is resolved transitively through a nested fragment"
grep -F "crates/chio-small/src/module.rs: production file has 2122 lines (11 own plus 2 include! fragments), limit is 2000" \
  "$work/assembled-nested.err" >/dev/null

fragment_not_a_module="$work/fragment-not-a-module"
init_case "$fragment_not_a_module"
write_module_with_includes "$fragment_not_a_module/crates/chio-small/src/module.rs" 4 \
  "module_parts/part.inc"
write_lines "$fragment_not_a_module/crates/chio-small/src/module_parts/part.inc" 2500
track_case "$fragment_not_a_module"
assert_rc "$(run_checker "$fragment_not_a_module" "$work/fragment-not-a-module.out" "$work/fragment-not-a-module.err")" 1 \
  "an oversized fragment is charged to the module that splices it in"
grep -F "crates/chio-small/src/module.rs: production file has 2505 lines (5 own plus 1 include! fragments), limit is 2000" \
  "$work/fragment-not-a-module.err" >/dev/null
if grep -F "crates/chio-small/src/module_parts/part.inc: production file has" \
  "$work/fragment-not-a-module.err" >/dev/null; then
  echo "FAIL: a fragment was measured as a module of its own" >&2
  exit 1
fi

fragment_em_dash="$work/fragment-em-dash"
init_case "$fragment_em_dash"
write_module_with_includes "$fragment_em_dash/crates/chio-small/src/module.rs" 4 \
  "module_parts/part.inc"
mkdir -p "$fragment_em_dash/crates/chio-small/src/module_parts"
printf 'bad \342\200\224 dash\n' > "$fragment_em_dash/crates/chio-small/src/module_parts/part.inc"
track_case "$fragment_em_dash"
assert_rc "$(run_checker "$fragment_em_dash" "$work/fragment-em-dash.out" "$work/fragment-em-dash.err")" 1 \
  "an include! fragment with U+2014 fails text hygiene"
grep -F "crates/chio-small/src/module_parts/part.inc:1:5: contains U+2014 em dash" \
  "$work/fragment-em-dash.err" >/dev/null

new_fragment="$work/new-fragment"
init_case "$new_fragment"
write_module_with_includes "$new_fragment/crates/chio-small/src/module.rs" 4 \
  "module_parts/part.inc"
write_lines "$new_fragment/crates/chio-small/src/module_parts/part.inc" 4
track_case "$new_fragment"
assert_rc "$(run_checker "$new_fragment" "$work/new-fragment.out" "$work/new-fragment.err")" 1 \
  "a new include! fragment fails even when the assembled module is small"
grep -F "crates/chio-small/src/module.rs: module is assembled from 1 include! fragments" \
  "$work/new-fragment.err" >/dev/null

manifest_dir_include="$work/manifest-dir-include"
init_case "$manifest_dir_include"
mkdir -p "$manifest_dir_include/crates/chio-small/src/module_parts"
cat > "$manifest_dir_include/crates/chio-small/Cargo.toml" <<'EOF'
[package]
name = "chio-small"
version = "0.0.0"
edition = "2021"
EOF
{
  printf 'include!(concat!(\n'
  printf '    env!("CARGO_MANIFEST_DIR"),\n'
  printf '    "/src/module_parts/part.inc"\n'
  printf '));\n'
} > "$manifest_dir_include/crates/chio-small/src/module.rs"
write_lines "$manifest_dir_include/crates/chio-small/src/module_parts/part.inc" 2100
track_case "$manifest_dir_include"
assert_rc "$(run_checker "$manifest_dir_include" "$work/manifest-dir-include.out" "$work/manifest-dir-include.err")" 1 \
  "a CARGO_MANIFEST_DIR include! resolves against the package root"
grep -F "crates/chio-small/src/module.rs: production file has 2104 lines (4 own plus 1 include! fragments), limit is 2000" \
  "$work/manifest-dir-include.err" >/dev/null

undeclared_generated_include="$work/undeclared-generated-include"
init_case "$undeclared_generated_include"
mkdir -p "$undeclared_generated_include/crates/chio-small/src"
printf 'include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n' \
  > "$undeclared_generated_include/crates/chio-small/src/module.rs"
mkdir -p "$undeclared_generated_include/crates/products/chio-proof-room/src"
printf 'include!(concat!(env!("OUT_DIR"), "/proof_fixture_files.rs"));\n' \
  > "$undeclared_generated_include/crates/products/chio-proof-room/src/lib.rs"
track_case "$undeclared_generated_include"
assert_rc "$(run_checker "$undeclared_generated_include" "$work/undeclared-generated-include.out" "$work/undeclared-generated-include.err")" 1 \
  "an undeclared build-script include! fails instead of being skipped"
grep -F "crates/chio-small/src/module.rs:1: include! path is not a literal and not declared as build script output" \
  "$work/undeclared-generated-include.err" >/dev/null
if grep -F "crates/products/chio-proof-room/src/lib.rs:1: include!" \
  "$work/undeclared-generated-include.err" >/dev/null; then
  echo "FAIL: a declared build-script include! was reported" >&2
  exit 1
fi

missing_fragment="$work/missing-fragment"
init_case "$missing_fragment"
write_module_with_includes "$missing_fragment/crates/chio-small/src/module.rs" 4 "absent.inc"
track_case "$missing_fragment"
assert_rc "$(run_checker "$missing_fragment" "$work/missing-fragment.out" "$work/missing-fragment.err")" 1 \
  "an include! naming a file that does not exist fails"
grep -F "crates/chio-small/src/module.rs:1: include! target crates/chio-small/src/absent.inc does not exist" \
  "$work/missing-fragment.err" >/dev/null

include_cycle="$work/include-cycle"
init_case "$include_cycle"
write_module_with_includes "$include_cycle/crates/chio-small/src/module.rs" 4 "module_parts/a.inc"
write_module_with_includes "$include_cycle/crates/chio-small/src/module_parts/a.inc" 4 "b.inc"
write_module_with_includes "$include_cycle/crates/chio-small/src/module_parts/b.inc" 4 "a.inc"
track_case "$include_cycle"
assert_rc "$(run_checker "$include_cycle" "$work/include-cycle.out" "$work/include-cycle.err")" 1 \
  "an include! cycle fails instead of being measured"
grep -F "include! cycle: crates/chio-small/src/module_parts/a.inc -> crates/chio-small/src/module_parts/b.inc -> crates/chio-small/src/module_parts/a.inc" \
  "$work/include-cycle.err" >/dev/null

commented_include="$work/commented-include"
init_case "$commented_include"
mkdir -p "$commented_include/crates/chio-small/src"
{
  printf '/*\n'
  printf 'include!("module_parts/part.inc");\n'
  printf '*/\n'
  printf 'pub fn marker() {}\n'
} > "$commented_include/crates/chio-small/src/module.rs"
track_case "$commented_include"
assert_rc "$(run_checker "$commented_include" "$work/commented-include.out" "$work/commented-include.err")" 1 \
  "a line-anchored include! the source scan cannot read fails"
grep -F "crates/chio-small/src/module.rs:2: include! was not readable by the source scan" \
  "$work/commented-include.err" >/dev/null

allowlisted_fragment="$work/allowlisted-fragment"
init_case "$allowlisted_fragment"
write_lines "$allowlisted_fragment/crates/chio-small/src/main.rs" 25
write_module_with_includes "$allowlisted_fragment/crates/products/chio-cli/tests/wrapper.rs" 4 \
  "mcp_serve_http.rs"
write_lines "$allowlisted_fragment/crates/products/chio-cli/tests/mcp_serve_http.rs" 4
track_case "$allowlisted_fragment"
assert_rc "$(run_checker "$allowlisted_fragment" "$work/allowlisted-fragment.out" "$work/allowlisted-fragment.err")" 1 \
  "an allowlist entry that names an include! fragment fails"
grep -F "crates/products/chio-cli/tests/mcp_serve_http.rs: allowlist entry names an include! fragment; the cap belongs to crates/products/chio-cli/tests/wrapper.rs" \
  "$work/allowlisted-fragment.err" >/dev/null

echo "check-rust-file-hygiene.test.sh: all assertions passed"
