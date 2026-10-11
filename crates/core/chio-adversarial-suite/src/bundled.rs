/// One statically bundled adversarial case file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledCase {
    /// Repository-relative path to the case JSON.
    pub path: &'static str,
    /// Embedded JSON payload.
    pub contents: &'static str,
}

/// Case files embedded into the crate for downstream test harnesses.
pub const BUNDLED_CASES: &[BundledCase] = &[
    BundledCase {
        path: "cases/broker_destination_rebinding/broker-destination-rebinding-001.json",
        contents: include_str!(
            "../cases/broker_destination_rebinding/broker-destination-rebinding-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_execution_overspend/broker-execution-overspend-001.json",
        contents: include_str!(
            "../cases/broker_execution_overspend/broker-execution-overspend-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_orphan_hold/broker-orphan-hold-001.json",
        contents: include_str!("../cases/broker_orphan_hold/broker-orphan-hold-001.json"),
    },
    BundledCase {
        path: "cases/broker_parent_double_charge/broker-parent-double-charge-001.json",
        contents: include_str!(
            "../cases/broker_parent_double_charge/broker-parent-double-charge-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_plaintext_custody/broker-plaintext-custody-001.json",
        contents: include_str!(
            "../cases/broker_plaintext_custody/broker-plaintext-custody-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_proof_replay/broker-proof-replay-001.json",
        contents: include_str!("../cases/broker_proof_replay/broker-proof-replay-001.json"),
    },
    BundledCase {
        path: "cases/broker_revocation_race/broker-revocation-race-001.json",
        contents: include_str!("../cases/broker_revocation_race/broker-revocation-race-001.json"),
    },
    BundledCase {
        path: "cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json",
        contents: include_str!(
            "../cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_unbound_headers/broker-unbound-headers-001.json",
        contents: include_str!("../cases/broker_unbound_headers/broker-unbound-headers-001.json"),
    },
    BundledCase {
        path: "cases/canary_evasion/canary-evasion-001.json",
        contents: include_str!("../cases/canary_evasion/canary-evasion-001.json"),
    },
    BundledCase {
        path: "cases/containment_rollback/containment-rollback-001.json",
        contents: include_str!("../cases/containment_rollback/containment-rollback-001.json"),
    },
    BundledCase {
        path: "cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json",
        contents: include_str!(
            "../cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json"
        ),
    },
    BundledCase {
        path: "cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json",
        contents: include_str!(
            "../cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json"
        ),
    },
    BundledCase {
        path: "cases/key_log_omission/key-log-omission-001.json",
        contents: include_str!("../cases/key_log_omission/key-log-omission-001.json"),
    },
    BundledCase {
        path: "cases/key_log_split_view/key-log-split-view-001.json",
        contents: include_str!("../cases/key_log_split_view/key-log-split-view-001.json"),
    },
    BundledCase {
        path: "cases/label_downgrade/label-downgrade-001.json",
        contents: include_str!("../cases/label_downgrade/label-downgrade-001.json"),
    },
    BundledCase {
        path: "cases/old_key_backdating/old-key-backdating-001.json",
        contents: include_str!("../cases/old_key_backdating/old-key-backdating-001.json"),
    },
    BundledCase {
        path: "cases/rotation_partial_commit/rotation-partial-commit-001.json",
        contents: include_str!("../cases/rotation_partial_commit/rotation-partial-commit-001.json"),
    },
    BundledCase {
        path: "cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json",
        contents: include_str!(
            "../cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json",
        contents: include_str!(
            "../cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json",
        contents: include_str!("../cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json",
        contents: include_str!(
            "../cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json",
        contents: include_str!(
            "../cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_path_swap/sandbox-path-swap-001.json",
        contents: include_str!("../cases/sandbox_path_swap/sandbox-path-swap-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json",
        contents: include_str!("../cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json",
        contents: include_str!("../cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json",
        contents: include_str!(
            "../cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json"
        ),
    },
    BundledCase {
        path: "cases/temporal_evasion/temporal-evasion-001.json",
        contents: include_str!("../cases/temporal_evasion/temporal-evasion-001.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-001.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-001.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-002.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-002.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-003.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-003.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-004.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-004.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-005.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-005.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-001.json",
        contents: include_str!("../cases/future_dated/future-dated-001.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-002.json",
        contents: include_str!("../cases/future_dated/future-dated-002.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-003.json",
        contents: include_str!("../cases/future_dated/future-dated-003.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-004.json",
        contents: include_str!("../cases/future_dated/future-dated-004.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-005.json",
        contents: include_str!("../cases/future_dated/future-dated-005.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-001.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-001.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-002.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-002.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-003.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-003.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-004.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-004.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-005.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-005.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-001.json",
        contents: include_str!("../cases/partial_signature/partial-signature-001.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-002.json",
        contents: include_str!("../cases/partial_signature/partial-signature-002.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-003.json",
        contents: include_str!("../cases/partial_signature/partial-signature-003.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-004.json",
        contents: include_str!("../cases/partial_signature/partial-signature-004.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-005.json",
        contents: include_str!("../cases/partial_signature/partial-signature-005.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-001.json",
        contents: include_str!("../cases/scope_superset/scope-superset-001.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-002.json",
        contents: include_str!("../cases/scope_superset/scope-superset-002.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-003.json",
        contents: include_str!("../cases/scope_superset/scope-superset-003.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-004.json",
        contents: include_str!("../cases/scope_superset/scope-superset-004.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-005.json",
        contents: include_str!("../cases/scope_superset/scope-superset-005.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-001.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-001.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-002.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-002.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-003.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-003.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-004.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-004.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-005.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-005.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-001.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-001.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-002.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-002.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-003.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-003.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-004.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-004.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-005.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-005.json"),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json"
        ),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json"
        ),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/threshold-proposal-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/threshold-proposal-mutations-001.json"
        ),
    },
];
