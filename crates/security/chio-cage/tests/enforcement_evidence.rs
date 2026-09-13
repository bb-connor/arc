use chio_cage::{
    persist_signed_cage_receipt, persist_signed_cage_receipt_with_trusted_key, sign_cage_receipt,
    verify_signed_cage_receipt, verify_signed_cage_receipt_with_trusted_key,
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord,
    CageEnforcementState, CageReceiptBindings, CageReceiptBody, CageReceiptPersistenceError,
    CageReceiptSigningContext, EnforcementPrepared, ExecTransitionObserved, ExecutionIdentity,
    FullyEnforcedEvidence, ObservedRulesetStatus, ProcessExitEvidence, SandboxArchitecture,
    SeccompEnforcementStatus, CAGE_ENFORCEMENT_RECORD_SCHEMA, ENFORCEMENT_PREPARED_SCHEMA,
    EXEC_TRANSITION_OBSERVED_SCHEMA, NONO_PATCH_VERSION, PINNED_NONO_VERSION,
    PINNED_SECCOMPILER_VERSION,
};
use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_test_support::prelude::*;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn identity() -> chio_cage::FileIdentity {
    serde_json::from_value(serde_json::json!({
        "device": 1,
        "inode": 2,
        "mount_id": 3,
        "mode": 0o100700,
        "uid": 1000,
        "gid": 1000,
        "kind": "regular_file"
    }))
    .test_expect("valid identity")
}

fn prepared() -> EnforcementPrepared {
    EnforcementPrepared {
        schema: ENFORCEMENT_PREPARED_SCHEMA.to_string(),
        process_id: 42,
        manifest_digest: digest('1'),
        profile_digest: digest('2'),
        plan_digest: digest('3'),
        fd_table_digest: digest('4'),
        helper_binding_digest: digest('5'),
        target_binding_digest: digest('6'),
        target_identity: identity(),
        applied_execution_identity: ExecutionIdentity::new(10001, 10001, vec![10002])
            .test_expect("valid execution identity"),
        nono_version: PINNED_NONO_VERSION.to_string(),
        nono_patch_version: NONO_PATCH_VERSION.to_string(),
        landlock_abi: 6,
        landlock_filesystem_status: ObservedRulesetStatus::FullyEnforced,
        landlock_network_status: ObservedRulesetStatus::FullyEnforced,
        seccompiler_version: PINNED_SECCOMPILER_VERSION.to_string(),
        seccomp_status: SeccompEnforcementStatus::FullyEnforced,
        seccomp_architecture: SandboxArchitecture::X86_64,
        seccomp_filter_digest: digest('7'),
        trace_session_digest: digest('8'),
        prepared_at_unix_ms: 1_000,
    }
}

fn exec_transition() -> ExecTransitionObserved {
    ExecTransitionObserved {
        schema: EXEC_TRANSITION_OBSERVED_SCHEMA.to_string(),
        process_id: 42,
        trace_session_digest: digest('8'),
        target_binding_digest: digest('6'),
        target_identity: identity(),
        observed_at_unix_ms: 1_001,
    }
}

fn evidence() -> FullyEnforcedEvidence {
    FullyEnforcedEvidence::new(prepared(), exec_transition(), true).test_expect("complete evidence")
}

fn signing_context() -> CageReceiptSigningContext {
    CageReceiptSigningContext::new(
        "capability-1",
        "native-server",
        "launch",
        digest('2'),
        Some("tenant-1".to_string()),
    )
    .test_expect("valid signing context")
}

#[test]
fn fully_enforced_requires_prepared_exec_identity_and_status_eof() {
    let evidence = FullyEnforcedEvidence::new(prepared(), exec_transition(), true)
        .test_expect("complete evidence");
    let record = CageEnforcementRecord::fully_enforced(evidence).test_expect("enforced record");
    assert_eq!(record.state, CageEnforcementState::FullyEnforced);
    assert_eq!(record.schema, CAGE_ENFORCEMENT_RECORD_SCHEMA);
    record.validate().test_expect("valid record");

    assert!(FullyEnforcedEvidence::new(prepared(), exec_transition(), false).is_err());
    let mut wrong_process = exec_transition();
    wrong_process.process_id = 43;
    assert!(FullyEnforcedEvidence::new(prepared(), wrong_process, true).is_err());
    let mut wrong_target = exec_transition();
    wrong_target.target_binding_digest = digest('9');
    assert!(FullyEnforcedEvidence::new(prepared(), wrong_target, true).is_err());

    let forged = FullyEnforcedEvidence {
        prepared: prepared(),
        exec_transition: ExecTransitionObserved {
            process_id: 43,
            ..exec_transition()
        },
        status_eof_observed: true,
    };
    assert!(CageEnforcementRecord::fully_enforced(forged).is_err());

    let forged_without_status_eof = FullyEnforcedEvidence {
        prepared: prepared(),
        exec_transition: exec_transition(),
        status_eof_observed: false,
    };
    assert!(CageEnforcementRecord::fully_enforced(forged_without_status_eof).is_err());
}

#[test]
fn bootstrap_failure_cannot_claim_enforcement_or_exit() {
    let failure = CageEnforcementFailure::new(
        CageEnforcementFailureCode::SeccompInstallFailed,
        "seccomp_install",
    )
    .test_expect("failure");
    let record = CageEnforcementRecord::bootstrap_failed(failure).test_expect("failure record");
    assert_eq!(record.state, CageEnforcementState::BootstrapFailed);
    record.validate().test_expect("valid failure");

    let mut value = serde_json::to_value(record).test_expect("record json");
    value["state"] = serde_json::json!("fully_enforced");
    let forged: CageEnforcementRecord = serde_json::from_value(value).test_expect("shape decodes");
    assert!(forged.validate().is_err());
}

#[test]
fn exit_is_bound_to_a_previously_fully_enforced_process() {
    let evidence = FullyEnforcedEvidence::new(prepared(), exec_transition(), true)
        .test_expect("complete evidence");
    let exit = ProcessExitEvidence {
        process_id: 42,
        exit_code: Some(0),
        signal: None,
        exited_at_unix_ms: 1_002,
    };
    let record = CageEnforcementRecord::exited(evidence.clone(), exit).test_expect("exit record");
    assert_eq!(record.state, CageEnforcementState::Exited);
    record.validate().test_expect("valid exit");

    let invalid = ProcessExitEvidence {
        process_id: 42,
        exit_code: Some(0),
        signal: Some(9),
        exited_at_unix_ms: 1_002,
    };
    assert!(CageEnforcementRecord::exited(evidence, invalid).is_err());
}

#[test]
fn evidence_shapes_reject_unknown_fields_and_noncanonical_digests() {
    let mut value = serde_json::to_value(prepared()).test_expect("prepared json");
    value["legacy"] = serde_json::json!(true);
    assert!(serde_json::from_value::<EnforcementPrepared>(value).is_err());

    let mut invalid = prepared();
    invalid.plan_digest = "ABC".to_string();
    assert!(invalid.validate().is_err());

    let mut partial = prepared();
    partial.landlock_network_status = ObservedRulesetStatus::PartiallyEnforced;
    assert!(partial.validate().is_err());

    let mut missing_seccomp = prepared();
    missing_seccomp.seccomp_status = SeccompEnforcementStatus::NotEnforced;
    assert!(missing_seccomp.validate().is_err());

    for forged_identity in [
        serde_json::json!({"uid": 0, "gid": 10001, "supplementary_gids": []}),
        serde_json::json!({"uid": 10001, "gid": 0, "supplementary_gids": []}),
        serde_json::json!({"uid": 10001, "gid": 10001, "supplementary_gids": [10001]}),
        serde_json::json!({"uid": 10001, "gid": 10001, "supplementary_gids": [10003, 10002]}),
    ] {
        let mut value = serde_json::to_value(prepared()).test_expect("prepared json");
        value["applied_execution_identity"] = forged_identity;
        let forged = serde_json::from_value::<EnforcementPrepared>(value)
            .test_expect("identity shape decodes");
        assert!(forged.validate().is_err());
    }
}

#[test]
fn fully_enforced_release_receipt_is_signed_verified_and_persistable() {
    let record = CageEnforcementRecord::fully_enforced(evidence()).test_expect("enforced record");
    let body = CageReceiptBody::new("attempt-1", None, record, 900, 1_001)
        .test_expect("truthful cage receipt body");
    let keypair = Keypair::from_seed(&[91; 32]);
    let backend = Ed25519Backend::new(keypair.clone());
    let receipt = sign_cage_receipt(body.clone(), &signing_context(), &backend)
        .test_expect("signed cage receipt");
    assert!(receipt
        .verify_signature()
        .test_expect("signature verification"));
    assert_eq!(
        verify_signed_cage_receipt(&receipt).test_expect("cage receipt verification"),
        body
    );

    let mut persisted = Vec::new();
    persist_signed_cage_receipt(&receipt, |verified| {
        persisted.push(verified.id.clone());
        Ok::<_, ()>(())
    })
    .test_expect("existing Chio receipt append boundary");
    assert_eq!(persisted, vec![receipt.id.clone()]);

    let trusted_key = keypair.public_key();
    verify_signed_cage_receipt_with_trusted_key(&receipt, &trusted_key)
        .test_expect("configured signer verification");
    persist_signed_cage_receipt_with_trusted_key(&receipt, &trusted_key, |_| Ok::<_, ()>(()))
        .test_expect("trusted receipt persistence");
    let attacker_key = Keypair::from_seed(&[94; 32]).public_key();
    assert!(verify_signed_cage_receipt_with_trusted_key(&receipt, &attacker_key).is_err());
    let mut called = false;
    assert!(
        persist_signed_cage_receipt_with_trusted_key(&receipt, &attacker_key, |_| {
            called = true;
            Ok::<_, ()>(())
        })
        .is_err()
    );
    assert!(!called);
}

#[test]
fn rejection_bootstrap_and_exit_have_distinct_truthful_signed_receipts() {
    let keypair = Keypair::from_seed(&[92; 32]);
    let backend = Ed25519Backend::new(keypair);
    let rejection = CageEnforcementRecord::rejected(
        CageEnforcementFailure::new(CageEnforcementFailureCode::InvalidPlan, "admission")
            .test_expect("rejection"),
    )
    .test_expect("rejection record");
    let rejection_body = CageReceiptBody::new("attempt-reject", None, rejection, 8_000, 9_000)
        .test_expect("rejection body");
    let rejection_receipt = sign_cage_receipt(rejection_body, &signing_context(), &backend)
        .test_expect("signed rejection");
    assert_eq!(
        verify_signed_cage_receipt(&rejection_receipt)
            .test_expect("verified rejection")
            .enforcement_record
            .state,
        CageEnforcementState::Rejected
    );

    let bootstrap = CageEnforcementRecord::bootstrap_failed(
        CageEnforcementFailure::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_install",
        )
        .test_expect("bootstrap failure"),
    )
    .test_expect("bootstrap record");
    let bootstrap_body = CageReceiptBody::new(
        "attempt-bootstrap",
        Some(CageReceiptBindings::from_prepared(&prepared())),
        bootstrap,
        8_000,
        9_000,
    )
    .test_expect("bootstrap body");
    let bootstrap_receipt = sign_cage_receipt(bootstrap_body, &signing_context(), &backend)
        .test_expect("signed bootstrap failure");
    assert_eq!(
        verify_signed_cage_receipt(&bootstrap_receipt)
            .test_expect("verified bootstrap failure")
            .enforcement_record
            .state,
        CageEnforcementState::BootstrapFailed
    );

    let exit = ProcessExitEvidence {
        process_id: 42,
        exit_code: Some(0),
        signal: None,
        exited_at_unix_ms: 1_002,
    };
    let exit_record = CageEnforcementRecord::exited(evidence(), exit).test_expect("exit record");
    let exit_body = CageReceiptBody::new("attempt-exit", None, exit_record, 900, 1_002)
        .test_expect("terminal body");
    let exit_receipt =
        sign_cage_receipt(exit_body, &signing_context(), &backend).test_expect("signed exit");
    assert_eq!(
        verify_signed_cage_receipt(&exit_receipt)
            .test_expect("verified exit")
            .enforcement_record
            .state,
        CageEnforcementState::Exited
    );
}

#[test]
fn cage_receipt_rejects_missing_or_forged_enforcement_bindings() {
    let bootstrap = CageEnforcementRecord::bootstrap_failed(
        CageEnforcementFailure::new(
            CageEnforcementFailureCode::LandlockPartial,
            "landlock_enforcement",
        )
        .test_expect("failure"),
    )
    .test_expect("bootstrap record");
    assert!(CageReceiptBody::new("attempt", None, bootstrap, 8_000, 9_000).is_err());

    let mut forged = CageReceiptBindings::from_prepared(&prepared());
    forged.target_binding_digest = digest('9');
    let record = CageEnforcementRecord::fully_enforced(evidence()).test_expect("enforced record");
    assert!(CageReceiptBody::new("attempt", Some(forged), record, 900, 1_001).is_err());
}

#[test]
fn cage_receipt_tampering_and_sink_failure_fail_closed() {
    let record = CageEnforcementRecord::fully_enforced(evidence()).test_expect("enforced record");
    let body = CageReceiptBody::new("attempt-tamper", None, record, 900, 1_001)
        .test_expect("receipt body");
    let keypair = Keypair::from_seed(&[93; 32]);
    let backend = Ed25519Backend::new(keypair);
    let receipt =
        sign_cage_receipt(body, &signing_context(), &backend).test_expect("signed cage receipt");

    let result = persist_signed_cage_receipt(&receipt, |_| Err::<(), _>("offline"));
    assert!(matches!(
        result,
        Err(CageReceiptPersistenceError::Sink("offline"))
    ));

    let mut tampered = receipt;
    tampered.metadata.as_mut().test_expect("cage metadata")["cage_receipt"]["stage"] =
        serde_json::json!("rejection");
    assert!(verify_signed_cage_receipt(&tampered).is_err());
    let mut called = false;
    let result = persist_signed_cage_receipt(&tampered, |_| {
        called = true;
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(CageReceiptPersistenceError::Invalid(_))
    ));
    assert!(!called);
}
