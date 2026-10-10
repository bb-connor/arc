#!/usr/bin/env python3
"""Exercise the real broker inventory callers with independent test-name fixtures."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Independent fixtures from the Linux broker test binary. These replay caller
# contracts without compiling or claiming execution of the underlying Rust tests.
FIXTURES = {'host Docker resource lifetime and bounded stream': {'argv': ['test',
                                                               '--locked',
                                                               '-p',
                                                               'chio-secret-broker',
                                                               '--lib',
                                                               'docker_adapter::'],
                                                      'names': ['docker_adapter::native_cause_tests::broker_native_cause_docker_healthy_connection_control',
                                                                'docker_adapter::native_cause_tests::broker_native_cause_docker_peer_validation',
                                                                'docker_adapter::native_cause_tests::broker_native_cause_docker_refused_connect',
                                                                'docker_adapter::native_cause_tests::broker_native_cause_docker_vanished_socket',
                                                                'docker_adapter::native_cause_tests::broker_native_cause_docker_wrong_peer_control',
                                                                'docker_adapter::tests::restart_during_exec_creation_or_completion_never_certifies_success',
                                                                'docker_adapter::wire::tests::complete_frames_keep_both_streams_and_incomplete_output_never_completes']},
 'kernel broker capability and composite quota admission': {'argv': ['test',
                                                                     '--locked',
                                                                     '-p',
                                                                     'chio-secret-broker',
                                                                     '--features',
                                                                     'native-mcp',
                                                                     '--lib',
                                                                     'kernel_admission::'],
                                                            'names': ['kernel_admission::registration::tests::registered_generation_cannot_sign_with_a_rotated_authority_key',
                                                                      'kernel_admission::tests::broker_admission_rejects_substitution_even_when_kernel_hash_is_updated',
                                                                      'kernel_admission::tests::broker_admission_requires_bounded_exact_typed_canonical_json',
                                                                      'kernel_admission::tests::broker_admission_uses_installed_trust_and_live_clock',
                                                                      'kernel_admission::tests::broker_quota_identity_stays_constant_across_separate_invocations',
                                                                      'kernel_admission::tests::daemon_response_ceiling_is_checked_before_admission_custody',
                                                                      'kernel_admission::tests::kernel::issued_nonce_cannot_adopt_a_changed_or_removed_broker_participant',
                                                                      'kernel_admission::tests::kernel::kernel_captures_parent_family_and_broker_once_and_denies_exhaustion',
                                                                      'kernel_admission::tests::kernel::strict_nonce_registers_original_broker_attempt_before_both_holds',
                                                                      'kernel_admission::tests::original_selection::broker_prepares_a_unique_original_and_refuses_unknown_or_reused_requests',
                                                                      'kernel_admission::tests::original_selection::broker_prepares_its_dispatch_committed_original_after_another_tenant_reuses_the_request_id',
                                                                      'kernel_admission::tests::original_selection::selector_controls::external_corrupt_duplicate_hold_index_poisoning_returns_no_original',
                                                                      'kernel_admission::tests::original_selection::selector_controls::immutable_composite_hold_rejects_external_operation_id_update_without_changing_custody',
                                                                      'kernel_admission::tests::original_selection::selector_controls::malformed_selector_is_integrity_and_external_index_tamper_poisoned',
                                                                      'kernel_admission::tests::original_selection::selector_controls::wrong_installed_native_and_participant_refuse_the_live_captured_original',
                                                                      'kernel_admission::tests::registration::registration_generation_binds_transport_tenant_signers_domain_and_verifier',
                                                                      'kernel_admission::tests::registration::registration_quota_aliases_preserve_all_owners_and_reject_collisions',
                                                                      'kernel_admission::tests::routes::route_set_binds_all_members_without_order_dependence',
                                                                      'kernel_admission::tests::routes::route_set_rejects_ambiguous_and_unbounded_composition',
                                                                      'kernel_admission::tests::routes::route_set_verifies_each_audience_and_rejects_cross_route_authority',
                                                                      'kernel_admission::tests::signed_broker_request_cannot_move_between_kernel_requests',
                                                                      'kernel_admission::tests::signed_broker_request_produces_original_operation_bound_quota']}}


# Release controls use independent source names and the real libtest substring
# selectors. These fixtures exercise the gate, not native enforcement.
RELEASE_NAMES = (
    "process_boundary_tests::native::confined::native_kernel_confined_broker_mcp_preserves_capture_and_terminal_receipts",
    "process_boundary_tests::native::cutpoints::confined_broker_process_cutpoints_preserve_provider_and_quota_observations",
    "process_boundary_tests::native::keyring::recovery::confined_broker_public_keyring_startup_recovers_exact_activation_after_auditor_and_receipt_loss",
    "process_boundary_tests::native::process_host::confined_broker_process_host_exports_original_call_and_replays_after_restart",
    "process_boundary_tests::native::process_host::governed_broker_process_host_verifies_original_keyring_authority",
)
RELEASE_FIXTURES = {
    label: {
        "argv": [
            "test", "--locked", "-p", "chio-secret-broker",
            "--features", "real-linux-enforcement", "--lib", selector,
        ],
        "names": [name for name in RELEASE_NAMES if selector in name],
    }
    for label, selector in (
        ("confined native broker MCP, process death and terminal cage receipts", "confined_broker_"),
        (
            "governed native broker original keyring authority",
            "process_boundary_tests::native::process_host::governed_broker_process_host_verifies_original_keyring_authority",
        ),
    )
}


class BrokerInventoryCallers(unittest.TestCase):
    def test_exact_library_inventories_accept_owned_names(self):
        source = (ROOT / "scripts/check-secret-broker-boundary.sh").read_text()
        start = source.index("run_tests() {")
        function = source[start:source.index("\n}\n", start) + 3]
        for label, fixture in (FIXTURES | RELEASE_FIXTURES).items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                pattern = (
                    r'run_tests "' + re.escape(label)
                    + r'" yes "\$\(cat <<\x27EOF\x27\n.*?\nEOF\n\)"(?:[^\n]*\\\n)*[^\n]+'
                )
                call = re.search(pattern, source, re.S)
                self.assertIsNotNone(call, "exact broker target caller disappeared")
                fake = work / "cargo"
                fake.write_text(
                    "#!/usr/bin/env python3\nimport sys\n"
                    + f"expected = {fixture['argv']!r}\n"
                    + f"names = {fixture['names']!r}\n"
                    + "if sys.argv[1:] == expected + ['--', '--list']:\n"
                    + "    print('\\n'.join(name + ': test' for name in names))\n"
                    + "elif sys.argv[1:] == expected:\n"
                    + "    print('\\n'.join('test ' + name + ' ... ok' for name in names))\n"
                    + "    print(f'test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s')\n"
                    + "else:\n    raise SystemExit('broker Cargo target or features changed')\n"
                )
                fake.chmod(0o700)
                probe = work / "probe.sh"
                probe.write_text(
                    '#!/usr/bin/env bash\nset -euo pipefail\n'
                    'inventory_checker="$1"\nexport PATH="$2:$PATH"\n'
                    + function + "\n" + call[0] + "\n"
                )
                result = subprocess.run(
                    ["bash", str(probe), str(ROOT / "scripts/check-exact-cargo-test-inventory.py"), str(work)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
