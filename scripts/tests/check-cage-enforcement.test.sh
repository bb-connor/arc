#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
real_python3="$(command -v python3)"
work="$(mktemp -d -t chio-cage-enforcement-gate-XXXXXX)"
trap 'rm -rf "$work"' EXIT
fake_bin="$work/bin"
mkdir -p "$fake_bin"
trusted_root="$work/trusted"
gate_fixture="$work/check-cage-enforcement.sh"
candidate_artifacts="$work/candidate-artifacts"
verifier_artifacts="$work/verifier-artifacts"
mkdir -p "$trusted_root" "$candidate_artifacts" "$verifier_artifacts"
cp "$repo_root/scripts/check-linux-enforcement-stack.py" \
  "$trusted_root/check-linux-enforcement-stack.py"
cp "$repo_root/scripts/check-cage-all-target-inventory.py" \
  "$trusted_root/check-cage-all-target-inventory.py"
cp "$repo_root/crates/security/chio-cage/scripts/check-linux-enforcement.sh" \
  "$trusted_root/check-cage-linux-enforcement.sh"
python3 - \
  "$repo_root" \
  "$trusted_root" \
  "$gate_fixture" \
  "$candidate_artifacts" \
  "$verifier_artifacts" <<'PY'
import sys
from pathlib import Path


repo_root = Path(sys.argv[1])
trusted_root = Path(sys.argv[2])
fixture = Path(sys.argv[3])
candidate_artifacts = Path(sys.argv[4])
verifier_artifacts = Path(sys.argv[5])
source = (repo_root / "scripts/check-cage-enforcement.sh").read_text(encoding="utf-8")
replacements = {
    "/private/candidate": str(repo_root),
    "/opt/chio-security/gates/check-linux-enforcement-stack.py": str(
        trusted_root / "check-linux-enforcement-stack.py"
    ),
    "/opt/chio-security/gates/check-cage-all-target-inventory.py": str(
        trusted_root / "check-cage-all-target-inventory.py"
    ),
    "/opt/chio-security/gates/check-cage-linux-enforcement.sh": str(
        trusted_root / "check-cage-linux-enforcement.sh"
    ),
    "/proc/self/status": "/dev/null",
}
for old, new in replacements.items():
    if old not in source:
        raise SystemExit(f"cage gate fixture source is missing {old!r}")
    source = source.replace(old, new)
fixture.write_text(source, encoding="utf-8")

linux_runner = trusted_root / "check-cage-linux-enforcement.sh"
runner_source = linux_runner.read_text(encoding="utf-8")
runner_replacements = {
    "/private/candidate": str(repo_root),
    "/opt/chio-security/gates/check-cage-all-target-inventory.py": str(
        trusted_root / "check-cage-all-target-inventory.py"
    ),
    "/target/artifacts": str(candidate_artifacts),
    '[[ ! "$verifier_artifacts" =~ ^/baseline/candidate-state/[a-f0-9]{64}/verifier/artifacts$ ]]': (
        f'[[ "$verifier_artifacts" != "{verifier_artifacts}" ]]'
    ),
}
for old, new in runner_replacements.items():
    if old not in runner_source:
        raise SystemExit(f"Linux cage fixture source is missing {old!r}")
    runner_source = runner_source.replace(old, new)
linux_runner.write_text(runner_source, encoding="utf-8")
PY
chmod 700 "$gate_fixture" "$trusted_root/check-cage-linux-enforcement.sh"

cat >"$fake_bin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) printf 'Linux\n' ;;
esac
EOF

cat >"$fake_bin/python3" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == *"/check-cage-all-target-inventory.py" ]] ||
  [[ "${1:-}" == "scripts/check-cage-all-target-inventory.py" ]]; then
  exec "${CHIO_REAL_PYTHON3:?}" "$@"
fi
exit 0
EOF

cat >"$fake_bin/cc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
while (($#)); do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$output" ]]
printf '#!/bin/true\n' >"$output"
chmod 700 "$output"
EOF

cat >"$fake_bin/ldd" <<'EOF'
#!/usr/bin/env bash
printf 'libc.so.6 => /bin/sh (0x1)\n'
printf 'libm.so.6 => /bin/ls (0x2)\n'
EOF

cat >"$fake_bin/readlink" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-e" ]]
shift
if [[ "${1:-}" == "--" ]]; then
  shift
fi
/bin/realpath "$1"
EOF

cat >"$fake_bin/readelf" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -hW) printf '  Type:                              DYN (Position-Independent Executable file)\n' ;;
  -lW) printf 'Elf file type is DYN (Position-Independent Executable file)\n' ;;
  -dW) printf 'Dynamic section contains 8 entries:\n 0x0000000000000000 (NULL) 0x0\n' ;;
  *) exit 64 ;;
esac
EOF

cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
if [[ "$args" == *" build "* ]] && [[ "$args" == *" --bin chio-cage-init "* ]]; then
  helper="${CARGO_TARGET_DIR:?}/debug/chio-cage-init"
  mkdir -p "$(dirname "$helper")"
  printf '#!/bin/true\n' >"$helper"
  chmod 700 "$helper"
  exit 0
fi
if [[ "$args" == *" --test enforcement_evidence "* ]] ||
   [[ "$args" == *" --test linux_compile "* ]]; then
  printf 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'
  exit 0
fi
if [[ "$args" == *" --all-targets "* ]] ||
   [[ "$args" == *" --test linux_enforcement "* ]]; then
  mode="${FAKE_CARGO_MODE:-success}"
  if [[ "$mode" == "unavailable" ]]; then
    exit 127
  fi
  if [[ "$args" == *"enforcement-mutants"* ]]; then
    tests=(
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
    case "$mode" in
      zero_mutations)
        printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 35 filtered out\n'
        exit 0
        ;;
      removed_mutation) tests=("${tests[@]:0:9}") ;;
      extra_mutation) tests+=(enforcement_mutation_unratcheted) ;;
    esac
    if [[ "$mode" == "skipped_mutation" ]]; then
      for ((index = 0; index < 9; index++)); do
        printf 'test %s ... ok\n' "${tests[$index]}"
      done
      printf 'test %s ... ignored\n' "${tests[9]}"
      printf 'test result: ok. 9 passed; 0 failed; 1 ignored; 0 measured; 26 filtered out\n'
      exit 0
    fi
    for test_name in "${tests[@]}"; do
      printf 'test %s ... ok\n' "$test_name"
    done
    printf 'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 26 filtered out\n' "${#tests[@]}"
    exit 0
  fi

  probes=(
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
  case "$mode" in
    zero_probes) probes=() ;;
    removed_probe) probes=("${probes[@]:0:25}") ;;
    extra_probe) probes+=(unratcheted_real_linux_probe) ;;
  esac

  print_target() {
    local header="$1"
    shift
    printf '     %s\n' "$header"
    printf 'running %d tests\n' "$#"
    for test_name in "$@"; do
      printf 'test %s ... ok\n' "$test_name"
    done
    printf 'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n' "$#"
  }

  if [[ "$args" == *" --all-targets "* ]]; then
    lib_tests=(
      accepts_bounded_canonical_non_root_identity
      acknowledged_child_reaper_handoff_reaps
      admission_consumes_nonforgeable_registry_authorization
      admission_fails_closed_on_unqualified_linux_architecture
      architecture_syscall_tables_cover_reviewed_profiles
      child_reaper_send_failure_reaps_synchronously
      child_reaper_start_failure_reaps_synchronously
      child_supervisor_retries_sigkill_until_reaped
      constrained_exec_filter_fails_closed
      descriptor_purpose_rejects_unknown_nested_fields
      environment_is_minimal_and_credentials_fail_closed
      every_syscall_profile_is_default_deny_and_has_no_network_creation
      exact_target_argv_is_used_and_mutation_is_rejected
      helper_identity_control_rejects_same_bytes_different_identity
      path_identity_control_rejects_changed_retained_resource_identity
      rejects_root_zero_unsorted_duplicate_and_primary_groups
      required_enforcement_comparison_is_exact
      seccomp_control_rejects_forbidden_socket_before_default_deny
      signature_is_verified_before_permissions_are_read
      swapped_extra_and_missing_stdio_roles_fail_plan_validation
      swapped_live_stdio_descriptors_fail_identity_verification
    )
    evidence_tests=(
      bootstrap_failure_cannot_claim_enforcement_or_exit
      cage_receipt_rejects_missing_or_forged_enforcement_bindings
      cage_receipt_tampering_and_sink_failure_fail_closed
      evidence_shapes_reject_unknown_fields_and_noncanonical_digests
      exit_is_bound_to_a_previously_fully_enforced_process
      fully_enforced_release_receipt_is_signed_verified_and_persistable
      fully_enforced_requires_prepared_exec_identity_and_status_eof
      rejection_bootstrap_and_exit_have_distinct_truthful_signed_receipts
    )
    compile_tests=(
      arbitrary_secret_runtime_file_requires_exact_signed_read_authority
      broker_profile_requires_a_connected_authenticated_unix_descriptor
      compile_is_deterministic_and_starts_from_deny_all
      compiled_profile_binds_the_exact_registry_snapshot
      directory_read_grant_is_bounded_to_its_admitted_descendant_inode_closure
      dynamically_linked_cage_init_is_rejected_before_descriptor_transfer
      executable_runtime_file_gets_exact_execute_read_grant
      forbidden_hard_link_alias_is_rejected_before_compilation
      header_only_cage_init_is_rejected_before_descriptor_transfer
      missing_write_parent_and_runtime_aliases_fail_closed
      retained_grant_survives_path_replacement_without_reopening
      runtime_file_rebound_to_forbidden_descriptor_fails_closed
      script_target_is_rejected_before_launch
      target_argv_is_bounded_and_bound_into_the_plan_digest
    )
    print_target "Running unittests src/lib.rs (/tmp/chio_cage-lib)" "${lib_tests[@]}"
    print_target "Running unittests src/bin/chio-cage-init.rs (/tmp/chio_cage_init-bin)"
    print_target "Running tests/enforcement_evidence.rs (/tmp/enforcement_evidence)" "${evidence_tests[@]}"
    print_target "Running tests/linux_compile.rs (/tmp/linux_compile)" "${compile_tests[@]}"
    printf '     Running tests/linux_enforcement.rs (/tmp/linux_enforcement)\n'
    printf 'running %d tests\n' "${#probes[@]}"
    if [[ "$mode" == "skipped_probe" ]]; then
      for ((index = 0; index < 25; index++)); do
        printf 'test %s ... ok\n' "${probes[$index]}"
      done
      printf 'test %s ... ignored\n' "${probes[25]}"
      printf 'test result: ok. 25 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
      exit 0
    fi
    for test_name in "${probes[@]}"; do
      printf 'test %s ... ok\n' "$test_name"
    done
    printf 'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n' "${#probes[@]}"
    exit 0
  fi

  for test_name in "${probes[@]}"; do
    printf 'test %s ... ok\n' "$test_name"
  done
  printf 'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' "${#probes[@]}"
  exit 0
fi
printf 'unexpected fake cargo invocation: %s\n' "$*" >&2
exit 65
EOF

chmod 700 "$fake_bin"/*

run_gate() {
  local runner="$1"
  local cargo_mode="$2"
  local output="$work/$runner-$cargo_mode.out"
  set +e
  (
    cd "$repo_root"
    if [[ "$runner" == "1" ]]; then
      PATH="$fake_bin:$PATH" \
        CHIO_REAL_PYTHON3="$real_python3" \
        CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
        CHIO_SECURITY_WORKSPACE="$repo_root" \
        CHIO_SECURITY_LINUX_STACK_CHECKER="$trusted_root/check-linux-enforcement-stack.py" \
        CHIO_SECURITY_CAGE_INVENTORY_CHECKER="$trusted_root/check-cage-all-target-inventory.py" \
        CHIO_SECURITY_CAGE_LINUX_RUNNER="$trusted_root/check-cage-linux-enforcement.sh" \
        CHIO_SECURITY_CANDIDATE_ARTIFACTS="$candidate_artifacts" \
        CHIO_SECURITY_VERIFIER_ARTIFACTS="$verifier_artifacts" \
        FAKE_CARGO_MODE="$cargo_mode" \
        "$gate_fixture" --release
    else
      PATH="$fake_bin:$PATH" \
        CHIO_REAL_PYTHON3="$real_python3" \
        CHIO_ENTERPRISE_SECURITY_RUNNER=0 \
        FAKE_CARGO_MODE="$cargo_mode" \
        "$gate_fixture" --release
    fi
  ) >"$output" 2>&1
  local status=$?
  set -e
  printf '%s\n' "$status"
}

status="$(run_gate 0 success)"
if [[ "$status" -eq 0 ]]; then
  echo "release mode accepted a non-designated runner" >&2
  exit 1
fi

for mode in \
  zero_probes removed_probe skipped_probe extra_probe \
  zero_mutations removed_mutation skipped_mutation extra_mutation \
  unavailable; do
  status="$(run_gate 1 "$mode")"
  if [[ "$status" -eq 0 ]]; then
    echo "release mode accepted invalid cage evidence mode $mode" >&2
    exit 1
  fi
done

status="$(run_gate 1 success)"
if [[ "$status" -ne 0 ]]; then
  cat "$work/1-success.out" >&2
  exit "$status"
fi
grep -Eq '^CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=[a-f0-9]{64} all_targets=69 probes=26 mutations=10$' \
  "$work/1-success.out"

python3 scripts/tests/check-cage-all-target-inventory.test.py

printf 'check-cage-enforcement.test.sh: all assertions passed\n'
