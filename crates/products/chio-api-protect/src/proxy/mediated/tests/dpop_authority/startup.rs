use super::*;
use chio_http_core::HttpAuthorityError;
use chio_store_sqlite::{DpopReplayMigrationRecordV1, SqliteAuthorityStore};

fn mismatched_descriptors(
    domain: &DpopReplayAuthority,
) -> [(&'static str, DpopReplayAuthority, &'static str); 5] {
    let policy_refusal = "DPoP authority is not activated with the exact configured policy";
    [
        (
            "destination_store_uuid",
            serde_json::json!("018f9878-7047-7abc-8c98-120dc65700ea"),
            policy_refusal,
        ),
        (
            "expectation_id",
            serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            policy_refusal,
        ),
        (
            "dpop_authority_id",
            serde_json::json!("unregistered-api-protect-dpop"),
            "DPoP authority is not registered",
        ),
        ("proof_ttl_secs", serde_json::json!(61), policy_refusal),
        ("max_clock_skew_secs", serde_json::json!(31), policy_refusal),
    ]
    .map(|(field, replacement, reason)| {
        let mut configured = serde_json::to_value(domain).test_unwrap();
        configured[field] = replacement;
        let configured: DpopReplayAuthority = serde_json::from_value(configured).test_unwrap();
        assert_ne!(&configured, domain, "{field}");
        (field, configured, reason)
    })
}

fn active_record(
    authority: &SqliteAuthorityStore,
    domain: &DpopReplayAuthority,
) -> DpopReplayMigrationRecordV1 {
    authority
        .admission_operation_store()
        .load_dpop_replay_migration(
            domain.dpop_authority_id(),
            &authority.mutation_fence(),
            chio_test_support::clock::unix_millis(),
        )
        .test_unwrap()
        .test_unwrap()
}

fn assert_activation_unchanged(
    authority: &SqliteAuthorityStore,
    domain: &DpopReplayAuthority,
    configured: &DpopReplayAuthority,
    expected: &DpopReplayMigrationRecordV1,
    field: &str,
) {
    assert_eq!(
        &active_record(authority, domain),
        expected,
        "{field}: construction changed the persisted activation"
    );
    if configured.dpop_authority_id() != domain.dpop_authority_id() {
        assert_eq!(
            authority
                .admission_operation_store()
                .load_dpop_replay_migration(
                    configured.dpop_authority_id(),
                    &authority.mutation_fence(),
                    chio_test_support::clock::unix_millis(),
                )
                .test_unwrap(),
            None,
            "{field}: construction registered another authority"
        );
    }
}

#[test]
fn mediation_refuses_mismatched_dpop_descriptor_without_replacing_activation() {
    let _time = chio_test_support::clock::scope_unix_secs(1_800_000_000);
    let directory = tempfile::tempdir().test_unwrap();
    let (authority, domain) = activated_authority(directory.path());
    let active = active_record(&authority, &domain);
    assert!(active.is_active());
    assert_eq!(active.authority(), Some(&domain));
    let signer = Keypair::generate();
    let build = |configured: &DpopReplayAuthority| {
        build_mediation_kernel(
            &signer,
            MediationBudget::Durable(DurableAdmissionStores::serving(&authority)),
            MediationPolicy {
                dpop_replay_authority: Some(configured),
                issuers: &[],
                hash: None,
                receipt_store: None,
            },
            Vec::new(),
            None,
            chio_test_support::clock::clock(),
        )
    };
    for (field, configured, reason) in mismatched_descriptors(&domain) {
        let error = build(&configured).err().test_unwrap();
        let ProtectError::Config(message) = error else {
            panic!("{field}: unexpected construction error: {error}");
        };
        assert_eq!(
            message,
            format!("durable admission failed: admission operation invariant failed: {reason}"),
            "{field}"
        );
        assert_activation_unchanged(&authority, &domain, &configured, &active, field);
    }
    let kernel = build(&domain).test_unwrap();
    assert_eq!(kernel.operation_owned_dpop_authority(), Some(&domain));
    assert_eq!(active_record(&authority, &domain), active);
}

#[test]
fn evaluator_refuses_mismatched_dpop_descriptor_without_replacing_activation() {
    let _time = chio_test_support::clock::scope_unix_secs(1_800_000_000);
    let directory = tempfile::tempdir().test_unwrap();
    let (authority, domain) = activated_authority(directory.path());
    let active = active_record(&authority, &domain);
    assert!(active.is_active());
    assert_eq!(active.authority(), Some(&domain));
    let signer = Keypair::generate();
    let build = |configured: &DpopReplayAuthority| {
        RequestEvaluator::new_with_durable_stores_and_admission(
            Vec::new(),
            signer.clone(),
            chio_core_types::sha256_hex(b"dpop-http-startup-policy"),
            Arc::new(InMemoryApprovalStore::new()),
            Vec::new(),
            None,
            None,
            Some(DurableAdmissionStores::serving(&authority)),
            Some(configured.clone()),
            true,
            chio_test_support::clock::clock(),
        )
    };
    for (field, configured, reason) in mismatched_descriptors(&domain) {
        let error = build(&configured).err().test_unwrap();
        let HttpAuthorityError::Kernel(message) = error else {
            panic!("{field}: unexpected construction error: {error}");
        };
        assert_eq!(
            message,
            format!("durable admission failed: admission operation invariant failed: {reason}"),
            "{field}"
        );
        assert_activation_unchanged(&authority, &domain, &configured, &active, field);
    }
    let _evaluator = build(&domain).test_unwrap();
    assert_eq!(active_record(&authority, &domain), active);
}
