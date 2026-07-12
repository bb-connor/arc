#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-linux-enforcement-stack.py"

work="$(mktemp -d -t chio-linux-enforcement-stack-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_record() {
  local root="$1" nono_version="$2" partial_disposition="$3"
  mkdir -p "$root/third_party/provenance"
  cat >"$root/third_party/provenance/linux-enforcement-stack.toml" <<EOF
schema = "chio.linux-enforcement-stack.v1"
reviewed_at = "2026-07-12"
reviewer = "Chio security review"
minimum_linux = "6.7"
minimum_landlock_abi = 4
supported_architectures = ["x86_64"]
required_kernel_features = ["landlock", "seccomp_filter", "openat2", "execveat", "memfd_seals", "o_path", "pidfd", "ptrace_traceexec"]

[nono]
name = "nono"
version = "$nono_version"
source = "registry+https://github.com/rust-lang/crates.io-index"
repository = "https://github.com/always-further/nono"
tag = "v0.53.0"
commit = "c4b25b827330640cb95f85809d88d977191b42e7"
checksum = "ae7eb523cc2036e9ad6527411c3da5dc2172dc454cc3447a03b910420a39bfee"
license = "Apache-2.0"
default_network = "blocked"
partially_enforced = "$partial_disposition"
caller_owned_path_fds = true
patch_required = true

[seccompiler]
name = "seccompiler"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
repository = "https://github.com/rust-vmm/seccompiler"
tag = "v0.5.0"
commit = "c3cf77d65815037931ae5bc2fca010713defdc8c"
checksum = "a4ae55de56877481d112a559bbc12667635fdaf5e005712fd4e2b2fa50ffc884"
license = "Apache-2.0 OR BSD-3-Clause"
production_default_action = "kill_process"
independent_from_nono_notify = true
EOF
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  printf '%s\n' "$rc"
}

valid="$work/valid"
write_record "$valid" "0.53.0" "reject"
test "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" = 0
grep -F 'linux enforcement stack check passed' "$work/valid.out" >/dev/null

wrong_nono="$work/wrong-nono"
write_record "$wrong_nono" "0.67.1" "reject"
test "$(run_checker "$wrong_nono" "$work/wrong-nono.out" "$work/wrong-nono.err")" = 1
grep -F 'nono pin does not match the reviewed source' "$work/wrong-nono.err" >/dev/null

partial="$work/partial"
write_record "$partial" "0.53.0" "accept"
test "$(run_checker "$partial" "$work/partial.out" "$work/partial.err")" = 1
grep -F 'partial Landlock enforcement must be rejected' "$work/partial.err" >/dev/null

printf 'check-linux-enforcement-stack.test.sh: all assertions passed\n'
