#!/usr/bin/env bash
set -euo pipefail
umask 022

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) ;;
  *) exit 64 ;;
esac
for command in awk cargo cc ldd readelf readlink; do
  command -v "$command" >/dev/null
done

challenge="${CHIO_CAGE_EVIDENCE_CHALLENGE:-}"
if [[ ! "$challenge" =~ ^[a-f0-9]{64}$ ]]; then
  echo "real-Linux evidence challenge is absent or invalid" >&2
  exit 64
fi

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" == "1" ]]; then
  root="${CHIO_SECURITY_WORKSPACE:-}"
  inventory_checker="${CHIO_SECURITY_CAGE_INVENTORY_CHECKER:-}"
  candidate_artifacts="${CHIO_SECURITY_CANDIDATE_ARTIFACTS:-}"
  verifier_artifacts="${CHIO_SECURITY_VERIFIER_ARTIFACTS:-}"
  if [[ "$root" != "/private/candidate" ]] ||
    [[ "$inventory_checker" != "/opt/chio-security/gates/check-cage-all-target-inventory.py" ]] ||
    [[ "$candidate_artifacts" != "/target/artifacts" ]] ||
    [[ ! "$verifier_artifacts" =~ ^/baseline/candidate-state/[a-f0-9]{64}/verifier/artifacts$ ]]; then
    echo "designated Linux cage paths do not match the trusted contract" >&2
    exit 1
  fi
  if [[ ! -f "$inventory_checker" ]] || [[ -L "$inventory_checker" ]]; then
    echo "designated Linux cage inventory checker is missing or symbolic" >&2
    exit 1
  fi
  for artifact_root in "$candidate_artifacts" "$verifier_artifacts"; do
    if [[ ! -d "$artifact_root" ]] || [[ -L "$artifact_root" ]]; then
      echo "designated Linux cage artifact root is missing or symbolic: $artifact_root" >&2
      exit 1
    fi
  done
  probe_dir="$candidate_artifacts"
  log_dir="$verifier_artifacts"
else
  for variable in \
    CHIO_SECURITY_WORKSPACE \
    CHIO_SECURITY_CAGE_INVENTORY_CHECKER \
    CHIO_SECURITY_CANDIDATE_ARTIFACTS \
    CHIO_SECURITY_VERIFIER_ARTIFACTS; do
    if [[ -n "${!variable:-}" ]]; then
      echo "trusted Linux cage path leaked into a portable invocation: $variable" >&2
      exit 1
    fi
  done
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
  inventory_checker="$root/scripts/check-cage-all-target-inventory.py"
  probe_dir="${TMPDIR:-/tmp}/chio-cage-probes-$$"
  log_dir="$probe_dir"
  mkdir -p "$probe_dir"
  trap 'rm -rf "$probe_dir"' EXIT
fi
crate="$root/crates/security/chio-cage"

for mode in $(seq 1 27); do
  if [[ "$mode" == 10 ]]; then
    continue
  fi
  cc -nostdlib -static -fno-stack-protector -fno-pie -no-pie \
    -Wl,--build-id=none -DPROBE_MODE="$mode" \
    "$crate/tests/fixtures/cage_probe.c" -o "$probe_dir/probe-$mode"
done

reexec_probe="$probe_dir/probe-10"
cc -nostdlib -static -fno-stack-protector -fno-pie -no-pie \
  -Wl,--build-id=none -DPROBE_MODE=10 -DPROBE_PATH="\"$reexec_probe\"" \
  "$crate/tests/fixtures/cage_probe.c" -o "$reexec_probe"

dynamic_probe="$probe_dir/dynamic-probe"
cc -O2 -fno-stack-protector -Wl,--build-id=none \
  "$crate/tests/fixtures/cage_dynamic_probe.c" -o "$dynamic_probe"
dynamic_dependencies="$(LC_ALL=C ldd "$dynamic_probe")"
dynamic_paths=()
while IFS= read -r dynamic_path; do
  dynamic_paths+=("$dynamic_path")
done < <(
  awk '
    /=> \// { print $3 }
    /^[[:space:]]*\// { print $1 }
  ' <<<"$dynamic_dependencies"
)
if [[ -f /etc/ld.so.cache ]]; then
  dynamic_paths+=(/etc/ld.so.cache)
fi
dynamic_runtime_paths=()
for path in "${dynamic_paths[@]}"; do
  resolved="$(readlink -e -- "$path")"
  if [[ ! -f "$resolved" ]]; then
    echo "dynamic runtime artifact is not a regular file: $path" >&2
    exit 1
  fi
  duplicate=0
  if [[ "${#dynamic_runtime_paths[@]}" -gt 0 ]]; then
    for existing in "${dynamic_runtime_paths[@]}"; do
      if [[ "$existing" == "$resolved" ]]; then
        duplicate=1
        break
      fi
    done
  fi
  if [[ "$duplicate" -eq 0 ]]; then
    dynamic_runtime_paths+=("$resolved")
  fi
done
if [[ "${#dynamic_runtime_paths[@]}" -lt 2 ]]; then
  echo "dynamic probe did not resolve an interpreter and shared library" >&2
  exit 1
fi

export CHIO_CAGE_TEST_SUCCESS="$probe_dir/probe-1"
export CHIO_CAGE_TEST_SOCKET="$probe_dir/probe-2"
export CHIO_CAGE_TEST_LANDLOCK="$probe_dir/probe-3"
export CHIO_CAGE_TEST_WAIT="$probe_dir/probe-4"
export CHIO_CAGE_TEST_CLONE="$probe_dir/probe-5"
export CHIO_CAGE_TEST_CREATE="$probe_dir/probe-6"
export CHIO_CAGE_TEST_WRITE="$probe_dir/probe-7"
export CHIO_CAGE_TEST_READ="$probe_dir/probe-8"
export CHIO_CAGE_TEST_READ_SWAP="$probe_dir/probe-9"
export CHIO_CAGE_TEST_REEXEC="$reexec_probe"
export CHIO_CAGE_TEST_STDIO="$probe_dir/probe-11"
export CHIO_CAGE_TEST_FD_LEAK="$probe_dir/probe-12"
export CHIO_CAGE_TEST_WRITE_FORBIDDEN="$probe_dir/probe-13"
export CHIO_CAGE_TEST_REMOVE="$probe_dir/probe-14"
export CHIO_CAGE_TEST_RENAME="$probe_dir/probe-15"
export CHIO_CAGE_TEST_HARD_LINK="$probe_dir/probe-16"
export CHIO_CAGE_TEST_SYMLINK="$probe_dir/probe-17"
export CHIO_CAGE_TEST_CONNECT_IPV4="$probe_dir/probe-18"
export CHIO_CAGE_TEST_BIND_IPV4="$probe_dir/probe-19"
export CHIO_CAGE_TEST_CONNECT_IPV6="$probe_dir/probe-20"
export CHIO_CAGE_TEST_BIND_IPV6="$probe_dir/probe-21"
export CHIO_CAGE_TEST_FORBIDDEN_SYSCALL="$probe_dir/probe-22"
export CHIO_CAGE_TEST_ENVIRONMENT="$probe_dir/probe-23"
export CHIO_CAGE_TEST_UNDECLARED_EXEC="$probe_dir/probe-24"
export CHIO_CAGE_TEST_IGNORE_TERM="$probe_dir/probe-25"
export CHIO_CAGE_TEST_DIRECTORY_READ="$probe_dir/probe-26"
export CHIO_CAGE_TEST_DIRECTORY_HARD_LINK="$probe_dir/probe-27"
export CHIO_CAGE_TEST_DYNAMIC="$dynamic_probe"
CHIO_CAGE_TEST_DYNAMIC_RUNTIME="$(printf '%s\n' "${dynamic_runtime_paths[@]}")"
export CHIO_CAGE_TEST_DYNAMIC_RUNTIME
export CHIO_CAGE_PARENT_SECRET="must-not-cross"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/chio-cage-target}"

cd "$root"

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" == "1" ]]; then
  static_target_dir="$candidate_artifacts/static-pie-target"
else
  static_target_dir="$CARGO_TARGET_DIR/static-pie"
fi
static_rustflags="${RUSTFLAGS:+${RUSTFLAGS} }-C target-feature=+crt-static -C relocation-model=pie"
RUSTFLAGS="$static_rustflags" CARGO_TARGET_DIR="$static_target_dir" \
  cargo build -p chio-cage --bin chio-cage-init --features real-linux-enforcement
static_helper="$static_target_dir/debug/chio-cage-init"
if [[ ! -x "$static_helper" ]]; then
  echo "static PIE cage-init build did not produce an executable" >&2
  exit 1
fi
if ! readelf -hW "$static_helper" | awk '$1 == "Type:" && $2 == "DYN" { found = 1 } END { exit !found }'; then
  echo "cage-init is not an ELF static PIE image" >&2
  exit 1
fi
if readelf -lW "$static_helper" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
  echo "cage-init contains a forbidden ELF interpreter" >&2
  exit 1
fi
if readelf -dW "$static_helper" 2>/dev/null | grep -Eq '\((NEEDED|RPATH|RUNPATH)\)'; then
  echo "cage-init contains a forbidden dynamic dependency or search path" >&2
  exit 1
fi
export CHIO_CAGE_TEST_HELPER="$static_helper"

run_cargo_lane() {
  local label="$1"
  local output="$2"
  shift 2
  set +e
  "$@" 2>&1 | tee "$output"
  local status=${PIPESTATUS[0]}
  set -e
  if [[ "$status" -ne 0 ]]; then
    echo "$label failed with status $status" >&2
    return "$status"
  fi
}

passed_total() {
  awk '
    /test result: ok\./ {
      for (field_index = 1; field_index <= NF; field_index++) {
        if ($field_index == "passed;") {
          total += $(field_index - 1)
        }
      }
    }
    END { print total + 0 }
  ' "$1"
}

all_targets_output="$log_dir/all-targets.out"
run_cargo_lane \
  "real-Linux all-target cage lane" \
  "$all_targets_output" \
  cargo test -p chio-cage --all-targets \
    --features real-linux-enforcement -- --test-threads=1
python3 -I "$inventory_checker" \
  --root "$root" \
  --run-output "$all_targets_output"
all_targets_passed="$(passed_total "$all_targets_output")"
if [[ "$all_targets_passed" -ne 69 ]]; then
  echo "real-Linux all-target cage lane did not execute exactly 69 tests" >&2
  exit 1
fi

probe_output="$log_dir/linux-enforcement-probes.out"
awk '
  /Running tests\/linux_enforcement\.rs \(/ {
    in_probe_target = 1
    next
  }
  in_probe_target {
    print
    if ($0 ~ /^test result:/) {
      exit
    }
  }
' "$all_targets_output" >"$probe_output"

expected_probes=(
  real_kernel_reports_fully_enforced_then_clean_exit
  execution_identity_is_exact_after_root_drop_or_unprivileged_launch
  sealed_launch_preparation_is_secret_free_and_owns_descriptors_without_launching
  launch_prepared_revalidates_mutated_retained_target_before_spawn
  real_launch_consumes_the_observed_sealed_preparation_contract
  dynamically_linked_target_uses_only_retained_runtime_artifacts
  fully_enforced_child_exposes_authenticated_stdio_and_exact_argv
  target_exec_has_no_leaked_control_or_resource_descriptors
  independent_seccomp_filter_kills_forbidden_socket
  landlock_denies_ungranted_path_after_fd_based_target_exec
  seccomp_kills_forbidden_process_creation
  landlock_denies_file_creation_without_a_grant
  retained_target_survives_path_replacement
  retained_helper_survives_path_replacement_without_reopening
  pidfd_forwards_an_allowed_termination_signal
  exact_write_and_read_grants_are_enforced_from_retained_descriptors
  directory_read_grant_denies_a_forbidden_hard_link_created_after_compilation
  landlock_grant_does_not_follow_a_replaced_path
  target_exec_exception_cannot_be_recreated_after_exec
  landlock_denies_write_to_existing_ungranted_file
  default_deny_blocks_remove_rename_and_hard_link
  landlock_denies_symlink_traversal_escape
  default_deny_blocks_ipv4_and_ipv6_connect_and_bind
  default_deny_blocks_unreviewed_syscall
  target_receives_no_parent_secret_or_loader_injection_environment
  default_deny_blocks_undeclared_executable_path
)
for test_name in "${expected_probes[@]}"; do
  if [[ "$(grep -Fxc "test $test_name ... ok" "$probe_output")" -ne 1 ]]; then
    echo "real-Linux cage probe lane omitted, skipped, or duplicated $test_name" >&2
    exit 1
  fi
done
probe_passed="$(passed_total "$probe_output")"
observed_probe_results="$(
  grep -Ec '^test [a-z0-9_]+ \.\.\. (ok|ignored)$' "$probe_output" || true
)"
observed_ignored_probes="$(
  grep -Ec '^test [a-z0-9_]+ \.\.\. ignored$' "$probe_output" || true
)"
if [[ "$probe_passed" -ne "${#expected_probes[@]}" ]] ||
  [[ "$observed_probe_results" -ne "${#expected_probes[@]}" ]] ||
  [[ "$observed_ignored_probes" -ne 0 ]] ||
  ! grep -Eq "^test result: ok\\. ${#expected_probes[@]} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" "$probe_output"; then
  echo "real-Linux cage probe lane did not execute the declared test inventory" >&2
  exit 1
fi

mutation_output="$log_dir/enforcement-mutations.out"
run_cargo_lane \
  "real-Linux cage mutation lane" \
  "$mutation_output" \
  cargo test -p chio-cage --test linux_enforcement \
    --features real-linux-enforcement,enforcement-mutants \
    mutation_ -- --test-threads=1

expected_mutations=(
  enforcement_mutation_disabling_landlock_denies_launch
  enforcement_mutation_partial_landlock_denies_launch
  enforcement_mutation_disabling_seccomp_denies_launch
  bootstrap_mutation_unsealed_plan_denies_launch
  bootstrap_mutation_corrupt_plan_digest_denies_launch
  bootstrap_mutation_missing_descriptor_denies_launch
  bootstrap_mutation_malformed_status_denies_launch
  bootstrap_mutation_trace_binding_mismatch_denies_launch
  bootstrap_mutation_exit_before_exec_denies_launch
  bootstrap_mutation_skipped_execution_identity_denies_launch
)
for test_name in "${expected_mutations[@]}"; do
  if [[ "$(grep -Fxc "test $test_name ... ok" "$mutation_output")" -ne 1 ]]; then
    echo "real-Linux cage mutation lane omitted, skipped, or duplicated $test_name" >&2
    exit 1
  fi
done
mutation_passed="$(passed_total "$mutation_output")"
observed_mutation_results="$(
  grep -Ec '^test (enforcement|bootstrap)_mutation_[A-Za-z0-9_]+ \.\.\. (ok|ignored)$' \
    "$mutation_output" || true
)"
observed_ignored_mutations="$(
  grep -Ec '^test (enforcement|bootstrap)_mutation_[A-Za-z0-9_]+ \.\.\. ignored$' \
    "$mutation_output" || true
)"
if [[ "$mutation_passed" -ne "${#expected_mutations[@]}" ]] ||
  [[ "$observed_mutation_results" -ne "${#expected_mutations[@]}" ]] ||
  [[ "$observed_ignored_mutations" -ne 0 ]] ||
  ! grep -Eq "^test result: ok\\. ${#expected_mutations[@]} passed; 0 failed; 0 ignored;" \
    "$mutation_output"; then
  echo "real-Linux cage mutation lane did not execute the declared test inventory" >&2
  exit 1
fi

printf 'CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=%s all_targets=%s probes=%s mutations=%s\n' \
  "$challenge" "$all_targets_passed" "$probe_passed" "$mutation_passed"
