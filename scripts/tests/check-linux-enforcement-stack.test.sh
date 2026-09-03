#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-linux-enforcement-stack.py"

work="$(mktemp -d -t chio-linux-enforcement-stack-XXXXXX)"
trap 'rm -rf "$work"' EXIT

make_fixture() {
  local root="$1"
  mkdir -p \
    "$root/third_party/provenance" \
    "$root/third_party/nono-chio/src" \
    "$root/crates/security/chio-cage/src/launch" \
    "$root/crates/security/chio-cage/src/launch/linux_parts" \
    "$root/crates/security/chio-cage/src/launch/linux_parts/part_01_sections" \
    "$root/crates/security/chio-cage/scripts" \
    "$root/crates/security/chio-cage/tests"
  cp "$REPO_ROOT/NOTICE" "$root/"
  cp "$REPO_ROOT/third_party/provenance/linux-enforcement-stack.toml" \
    "$root/third_party/provenance/"
  cp \
    "$REPO_ROOT/third_party/nono-chio/Cargo.toml" \
    "$REPO_ROOT/third_party/nono-chio/README.md" \
    "$REPO_ROOT/third_party/nono-chio/PATCHES.md" \
    "$REPO_ROOT/third_party/nono-chio/LICENSE-APACHE" \
    "$root/third_party/nono-chio/"
  cp "$REPO_ROOT/third_party/nono-chio/src/lib.rs" \
    "$root/third_party/nono-chio/src/"
  cp "$REPO_ROOT/crates/security/chio-cage/Cargo.toml" \
    "$root/crates/security/chio-cage/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/lib.rs" \
    "$root/crates/security/chio-cage/src/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/linux.rs" \
    "$root/crates/security/chio-cage/src/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/receipt.rs" \
    "$root/crates/security/chio-cage/src/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/launch/linux.rs" \
    "$root/crates/security/chio-cage/src/launch/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/launch/linux_parts/part_01.rs" \
    "$REPO_ROOT/crates/security/chio-cage/src/launch/linux_parts/part_02.rs" \
    "$root/crates/security/chio-cage/src/launch/linux_parts/"
  cp "$REPO_ROOT/crates/security/chio-cage/src/launch/linux_parts/part_01_sections/bootstrap.inc" \
    "$REPO_ROOT/crates/security/chio-cage/src/launch/linux_parts/part_01_sections/sandbox.inc" \
    "$root/crates/security/chio-cage/src/launch/linux_parts/part_01_sections/"
  cp "$REPO_ROOT/crates/security/chio-cage/scripts/check-linux-enforcement.sh" \
    "$root/crates/security/chio-cage/scripts/"
  cp "$REPO_ROOT/crates/security/chio-cage/tests/linux_enforcement.rs" \
    "$root/crates/security/chio-cage/tests/"
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  printf '%s\n' "$rc"
}

valid="$work/valid"
make_fixture "$valid"
test "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" = 0
grep -F 'linux enforcement stack check passed' "$work/valid.out" >/dev/null

wrong_nono="$work/wrong-nono"
cp -R "$valid" "$wrong_nono"
python3 -c 'from pathlib import Path; p=Path("'$wrong_nono'/third_party/provenance/linux-enforcement-stack.toml"); s=p.read_text(); p.write_text(s.replace("version = \"0.53.0\"", "version = \"0.67.1\"", 1))'
test "$(run_checker "$wrong_nono" "$work/wrong-nono.out" "$work/wrong-nono.err")" = 1
grep -F 'nono pin does not match the reviewed source' "$work/wrong-nono.err" >/dev/null

partial="$work/partial"
cp -R "$valid" "$partial"
python3 -c 'from pathlib import Path; p=Path("'$partial'/third_party/provenance/linux-enforcement-stack.toml"); s=p.read_text(); p.write_text(s.replace("partially_enforced = \"reject\"", "partially_enforced = \"accept\""))'
test "$(run_checker "$partial" "$work/partial.out" "$work/partial.err")" = 1
grep -F 'partial Landlock enforcement must be rejected' "$work/partial.err" >/dev/null

tampered_wrapper="$work/tampered-wrapper"
cp -R "$valid" "$tampered_wrapper"
printf '\n// provenance tamper\n' >>"$tampered_wrapper/third_party/nono-chio/src/lib.rs"
test "$(run_checker "$tampered_wrapper" "$work/tampered.out" "$work/tampered.err")" = 1
grep -F 'nono-chio wrapper source digest does not match provenance' "$work/tampered.err" >/dev/null

missing_notice="$work/missing-notice"
cp -R "$valid" "$missing_notice"
python3 -c 'from pathlib import Path; p=Path("'$missing_notice'/NOTICE"); s=p.read_text(); p.write_text(s.replace("Copyright Luke Hinds", "Copyright omitted", 1))'
test "$(run_checker "$missing_notice" "$work/missing-notice.out" "$work/missing-notice.err")" = 1
grep -F 'repository NOTICE is missing nono attribution: Luke Hinds' "$work/missing-notice.err" >/dev/null

raw_bpf="$work/raw-bpf"
cp -R "$valid" "$raw_bpf"
printf '\n// sock_fprog bypass\n' >>"$raw_bpf/crates/security/chio-cage/src/launch/linux_parts/part_01.rs"
test "$(run_checker "$raw_bpf" "$work/raw-bpf.out" "$work/raw-bpf.err")" = 1
grep -F 'Linux launcher bypasses the reviewed compiler or adapter: sock_fprog' "$work/raw-bpf.err" >/dev/null

pathname_helper="$work/pathname-helper"
cp -R "$valid" "$pathname_helper"
python3 -c 'from pathlib import Path; p=Path("'$pathname_helper'/crates/security/chio-cage/src/launch/linux_parts/part_01_sections/bootstrap.inc"); s=p.read_text(); p.write_text(s.replace("Command::new(helper_exec_path)", "Command::new(helper_path)", 1))'
test "$(run_checker "$pathname_helper" "$work/pathname-helper.out" "$work/pathname-helper.err")" = 1
grep -F 'Linux launcher is missing required enforcement token: Command::new(helper_exec_path)' "$work/pathname-helper.err" >/dev/null
grep -F 'Linux launcher reopens the admitted helper by pathname' "$work/pathname-helper.err" >/dev/null

missing_launcher_part="$work/missing-launcher-part"
cp -R "$valid" "$missing_launcher_part"
rm "$missing_launcher_part/crates/security/chio-cage/src/launch/linux_parts/part_02.rs"
test "$(run_checker "$missing_launcher_part" "$work/missing-launcher-part.out" "$work/missing-launcher-part.err")" = 1
grep -F 'chio-cage Linux launcher part_02.rs is missing' "$work/missing-launcher-part.err" >/dev/null

unreviewed_arch="$work/unreviewed-arch"
cp -R "$valid" "$unreviewed_arch"
python3 -c 'from pathlib import Path; p=Path("'$unreviewed_arch'/crates/security/chio-cage/scripts/check-linux-enforcement.sh"); s=p.read_text(); p.write_text(s.replace("Linux:x86_64)", "Linux:x86_64|Linux:aarch64)", 1))'
test "$(run_checker "$unreviewed_arch" "$work/unreviewed-arch.out" "$work/unreviewed-arch.err")" = 1
grep -F 'real Linux runner enables an architecture outside the reviewed set' "$work/unreviewed-arch.err" >/dev/null

missing_atomic_receipt="$work/missing-atomic-receipt"
cp -R "$valid" "$missing_atomic_receipt"
python3 -c 'from pathlib import Path; p=Path("'$missing_atomic_receipt'/crates/security/chio-cage/src/receipt.rs"); s=p.read_text(); p.write_text(s.replace("ChioReceipt::sign_with_backend_using_handle", "ChioReceipt::sign_without_atomic_identity", 1))'
test "$(run_checker "$missing_atomic_receipt" "$work/missing-atomic-receipt.out" "$work/missing-atomic-receipt.err")" = 1
grep -F 'signed cage receipt adapter is missing required token: ChioReceipt::sign_with_backend_using_handle' "$work/missing-atomic-receipt.err" >/dev/null

printf 'check-linux-enforcement-stack.test.sh: all assertions passed\n'
