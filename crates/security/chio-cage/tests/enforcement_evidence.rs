use chio_cage::{
    persist_signed_cage_receipt, persist_signed_cage_receipt_with_trusted_key, sign_cage_receipt,
    verify_signed_cage_receipt, verify_signed_cage_receipt_with_trusted_key,
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord,
    CageEnforcementState, CageReceiptBindings, CageReceiptBody, CageReceiptError,
    CageReceiptPersistenceError, CageReceiptSigningContext, EnforcementEvidenceError,
    EnforcementPrepared, ExecTransitionObserved, ExecutionIdentity, FullyEnforcedEvidence,
    ObservedRulesetStatus, ProcessExitEvidence, SandboxArchitecture, SeccompEnforcementStatus,
    CAGE_ENFORCEMENT_RECORD_SCHEMA, ENFORCEMENT_PREPARED_SCHEMA, EXEC_TRANSITION_OBSERVED_SCHEMA,
    NONO_PATCH_VERSION, PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION,
};
use chio_cage::{
    render_tool_confinement, ConfinementBackendKind, ConfinementDisclosure, UnconfinedReason,
    NATIVE_LAUNCH_METADATA_KEY,
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

    assert_eq!(
        FullyEnforcedEvidence::new(prepared(), exec_transition(), false),
        Err(EnforcementEvidenceError::MissingStatusEof)
    );
    let mut wrong_process = exec_transition();
    wrong_process.process_id = 43;
    assert_eq!(
        FullyEnforcedEvidence::new(prepared(), wrong_process, true),
        Err(EnforcementEvidenceError::BindingMismatch)
    );
    let mut wrong_target = exec_transition();
    wrong_target.target_binding_digest = digest('9');
    assert_eq!(
        FullyEnforcedEvidence::new(prepared(), wrong_target, true),
        Err(EnforcementEvidenceError::BindingMismatch)
    );

    // Millisecond timestamps may tie, but a backwards wall clock must deny
    // launch rather than mint apparently ordered enforcement evidence.
    let mut same_millisecond = exec_transition();
    same_millisecond.observed_at_unix_ms = prepared().prepared_at_unix_ms;
    FullyEnforcedEvidence::new(prepared(), same_millisecond, true)
        .test_expect("equal observation timestamps remain valid");
    let mut earlier_exec = exec_transition();
    earlier_exec.observed_at_unix_ms = prepared().prepared_at_unix_ms - 1;
    assert_eq!(
        FullyEnforcedEvidence::new(prepared(), earlier_exec.clone(), true),
        Err(EnforcementEvidenceError::BindingMismatch)
    );
    assert_eq!(
        CageEnforcementRecord::fully_enforced(FullyEnforcedEvidence {
            prepared: prepared(),
            exec_transition: earlier_exec,
            status_eof_observed: true,
        })
        .err(),
        Some(EnforcementEvidenceError::BindingMismatch)
    );

    let forged = FullyEnforcedEvidence {
        prepared: prepared(),
        exec_transition: ExecTransitionObserved {
            process_id: 43,
            ..exec_transition()
        },
        status_eof_observed: true,
    };
    assert_eq!(
        CageEnforcementRecord::fully_enforced(forged).err(),
        Some(EnforcementEvidenceError::BindingMismatch)
    );

    let forged_without_status_eof = FullyEnforcedEvidence {
        prepared: prepared(),
        exec_transition: exec_transition(),
        status_eof_observed: false,
    };
    assert_eq!(
        CageEnforcementRecord::fully_enforced(forged_without_status_eof).err(),
        Some(EnforcementEvidenceError::MissingStatusEof)
    );
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
    assert_eq!(
        forged.validate(),
        Err(EnforcementEvidenceError::InvalidStateShape)
    );
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
    assert_eq!(
        CageEnforcementRecord::exited(evidence, invalid).err(),
        Some(EnforcementEvidenceError::InvalidExit)
    );
}

#[test]
fn evidence_shapes_reject_unknown_fields_and_noncanonical_digests() {
    let mut value = serde_json::to_value(prepared()).test_expect("prepared json");
    value["legacy"] = serde_json::json!(true);
    let unknown = serde_json::from_value::<EnforcementPrepared>(value)
        .err()
        .test_expect("unknown field must be rejected");
    assert!(
        unknown.to_string().contains("unknown field `legacy`"),
        "{unknown}"
    );

    let mut invalid = prepared();
    invalid.plan_digest = "ABC".to_string();
    assert_eq!(
        invalid.validate(),
        Err(EnforcementEvidenceError::InvalidDigest)
    );

    let mut partial = prepared();
    partial.landlock_network_status = ObservedRulesetStatus::PartiallyEnforced;
    assert_eq!(
        partial.validate(),
        Err(EnforcementEvidenceError::IncompleteEnforcement)
    );

    let mut missing_seccomp = prepared();
    missing_seccomp.seccomp_status = SeccompEnforcementStatus::NotEnforced;
    assert_eq!(
        missing_seccomp.validate(),
        Err(EnforcementEvidenceError::IncompleteEnforcement)
    );

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
        assert_eq!(
            forged.validate(),
            Err(EnforcementEvidenceError::BindingMismatch)
        );
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
        .verify_integrity_embedded_key()
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
    assert!(matches!(
        verify_signed_cage_receipt_with_trusted_key(&receipt, &attacker_key),
        Err(CageReceiptError::UntrustedSigner)
    ));
    let mut called = false;
    assert!(matches!(
        persist_signed_cage_receipt_with_trusted_key(&receipt, &attacker_key, |_| {
            called = true;
            Ok::<_, ()>(())
        }),
        Err(CageReceiptPersistenceError::Invalid(
            CageReceiptError::UntrustedSigner
        ))
    ));
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
    let original = CageReceiptBindings::from_prepared(&prepared());
    let mut bound = original.clone();
    bound.profile_digest = digest('a');
    bound.plan_digest = digest('b');
    bound.fd_table_digest = digest('c');
    let context = signing_context()
        .with_admitted_policy_digest(digest('e'))
        .test_expect("complete admitted policy")
        .with_launch_bindings(&original, &bound)
        .test_expect("stdio preparation updates plan bindings");
    assert!(matches!(
        context.with_launch_bindings(&original, &bound),
        Err(CageReceiptError::BindingMismatch)
    ));
    for field in [
        "manifest_digest",
        "helper_binding_digest",
        "target_binding_digest",
        "target_identity",
    ] {
        let mut value = serde_json::to_value(&bound).test_unwrap();
        if field == "target_identity" {
            value[field]["inode"] = serde_json::json!(99);
        } else {
            value[field] = serde_json::json!(digest('d'));
        }
        let altered = serde_json::from_value(value).test_unwrap();
        assert!(
            matches!(
                signing_context().with_launch_bindings(&original, &altered),
                Err(CageReceiptError::BindingMismatch)
            ),
            "{field}"
        );
    }
    let mut observed = prepared();
    observed.profile_digest.clone_from(&bound.profile_digest);
    observed.plan_digest.clone_from(&bound.plan_digest);
    observed.fd_table_digest.clone_from(&bound.fd_table_digest);
    let record = CageEnforcementRecord::fully_enforced(
        FullyEnforcedEvidence::new(observed, exec_transition(), true).test_unwrap(),
    )
    .test_unwrap();
    let body =
        CageReceiptBody::new("prepared-stdio", Some(bound), record, 900, 1_001).test_unwrap();
    let backend = Ed25519Backend::new(Keypair::from_seed(&[94; 32]));
    assert!(matches!(
        sign_cage_receipt(body.clone(), &signing_context(), &backend),
        Err(CageReceiptError::BindingMismatch)
    ));
    let signed = sign_cage_receipt(body, &context, &backend).test_unwrap();
    assert_eq!(signed.policy_hash, digest('a'));
    let verified = verify_signed_cage_receipt(&signed).test_unwrap();
    assert_eq!(
        verified.admitted_policy_digest.as_deref(),
        Some(digest('e').as_str())
    );
    let mut tampered = signed.clone();
    tampered.metadata.as_mut().test_unwrap()["cage_receipt"]["admitted_policy_digest"] =
        serde_json::json!(digest('f'));
    assert!(matches!(
        verify_signed_cage_receipt(&tampered),
        Err(CageReceiptError::InvalidSignature)
    ));
    let wrong_context = context
        .clone()
        .with_admitted_policy_digest(digest('f'))
        .test_unwrap();
    assert!(matches!(
        sign_cage_receipt(verified, &wrong_context, &backend),
        Err(CageReceiptError::BindingMismatch)
    ));
    assert!(matches!(
        context.with_admitted_policy_digest("invalid"),
        Err(CageReceiptError::InvalidDigest)
    ));

    let bootstrap = CageEnforcementRecord::bootstrap_failed(
        CageEnforcementFailure::new(
            CageEnforcementFailureCode::LandlockPartial,
            "landlock_enforcement",
        )
        .test_expect("failure"),
    )
    .test_expect("bootstrap record");
    assert!(matches!(
        CageReceiptBody::new("attempt", None, bootstrap, 8_000, 9_000),
        Err(CageReceiptError::MissingBindings)
    ));

    let mut forged = CageReceiptBindings::from_prepared(&prepared());
    forged.target_binding_digest = digest('9');
    let record = CageEnforcementRecord::fully_enforced(evidence()).test_expect("enforced record");
    assert!(matches!(
        CageReceiptBody::new("attempt", Some(forged), record, 900, 1_001),
        Err(CageReceiptError::BindingMismatch)
    ));
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
    assert!(matches!(
        verify_signed_cage_receipt(&tampered),
        Err(CageReceiptError::InvalidSignature)
    ));
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

fn signed_launch(
    record: CageEnforcementRecord,
    signer: &Keypair,
) -> chio_core::receipt::body::ChioReceipt {
    let bindings = (record.state == CageEnforcementState::BootstrapFailed)
        .then(|| CageReceiptBindings::from_prepared(&prepared()));
    let body = CageReceiptBody::new("attempt-dispatch", bindings, record, 900, 1_002)
        .test_expect("launch receipt body");
    sign_cage_receipt(
        body,
        &signing_context(),
        &Ed25519Backend::new(signer.clone()),
    )
    .test_expect("signed launch receipt")
}

fn fully_enforced_launch(signer: &Keypair) -> chio_core::receipt::body::ChioReceipt {
    signed_launch(
        CageEnforcementRecord::fully_enforced(evidence()).test_expect("enforced record"),
        signer,
    )
}

fn launch_reference(launch: &chio_core::receipt::body::ChioReceipt) -> serde_json::Value {
    let bytes = chio_core::canonical_json_bytes(launch).test_expect("canonical launch");
    serde_json::json!({
        "receipt_id": launch.id,
        "receipt_sha256": chio_core::sha256_hex(&bytes),
    })
}

fn tool_receipt(
    kernel: &Keypair,
    tool_server: &str,
    native_launch: Option<serde_json::Value>,
) -> chio_core::receipt::body::ChioReceipt {
    use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core::receipt::decision::{Decision, ToolCallAction};
    use chio_core::receipt::kinds::ToolOrigin;
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "tool-call-receipt".to_string(),
            timestamp: 2,
            capability_id: "capability-1".to_string(),
            tool_server: tool_server.to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .test_expect("tool action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: digest('a'),
            policy_hash: digest('b'),
            evidence: Vec::new(),
            metadata: native_launch
                .map(|reference| serde_json::json!({ NATIVE_LAUNCH_METADATA_KEY: reference })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        kernel,
    )
    .test_expect("signed tool receipt")
}

const UNCONFINED: ConfinementDisclosure =
    ConfinementDisclosure::Unconfined(UnconfinedReason::HostExecuted);

#[test]
fn fully_enforced_launch_bound_at_dispatch_renders_confined() {
    let kernel = Keypair::from_seed(&[101; 32]);
    let launcher = Keypair::from_seed(&[102; 32]);
    let launch = fully_enforced_launch(&launcher);
    let receipt = tool_receipt(&kernel, "native-server", Some(launch_reference(&launch)));
    let disclosure = render_tool_confinement(
        &receipt,
        Some(&launch),
        &kernel.public_key(),
        &launcher.public_key(),
    );
    assert_eq!(
        disclosure,
        ConfinementDisclosure::Confined(ConfinementBackendKind::LinuxCage)
    );
    assert_eq!(disclosure.to_string(), "confined by Chio (Linux cage)");
}

#[test]
fn missing_unverified_or_partial_launch_renders_unconfined() {
    let kernel = Keypair::from_seed(&[103; 32]);
    let launcher = Keypair::from_seed(&[104; 32]);
    let attacker = Keypair::from_seed(&[105; 32]);
    let launch = fully_enforced_launch(&launcher);
    let bound = tool_receipt(&kernel, "native-server", Some(launch_reference(&launch)));
    let render = |receipt: &chio_core::receipt::body::ChioReceipt,
                  launch: Option<&chio_core::receipt::body::ChioReceipt>| {
        render_tool_confinement(
            receipt,
            launch,
            &kernel.public_key(),
            &launcher.public_key(),
        )
    };

    assert_eq!(render(&bound, None), UNCONFINED);
    assert_eq!(
        render(&tool_receipt(&kernel, "native-server", None), Some(&launch)),
        UNCONFINED
    );
    assert_eq!(
        UNCONFINED.to_string(),
        "unconfined: host-executed; not sandboxed by Chio"
    );

    let mut wrong_digest = launch_reference(&launch);
    wrong_digest["receipt_sha256"] = serde_json::json!(digest('c'));
    let mut extra_field = launch_reference(&launch);
    extra_field["state"] = serde_json::json!("fully_enforced");
    for reference in [wrong_digest, extra_field] {
        let receipt = tool_receipt(&kernel, "native-server", Some(reference));
        assert_eq!(render(&receipt, Some(&launch)), UNCONFINED);
    }

    let other_server = tool_receipt(&kernel, "other-server", Some(launch_reference(&launch)));
    assert_eq!(render(&other_server, Some(&launch)), UNCONFINED);

    let forged_kernel = tool_receipt(&attacker, "native-server", Some(launch_reference(&launch)));
    assert_eq!(render(&forged_kernel, Some(&launch)), UNCONFINED);
    let mut tampered = bound.clone();
    tampered.tool_name = "write".to_string();
    assert_eq!(render(&tampered, Some(&launch)), UNCONFINED);

    let untrusted_launch = fully_enforced_launch(&attacker);
    let receipt = tool_receipt(
        &kernel,
        "native-server",
        Some(launch_reference(&untrusted_launch)),
    );
    assert_eq!(render(&receipt, Some(&untrusted_launch)), UNCONFINED);

    let partial = CageEnforcementRecord::bootstrap_failed(
        CageEnforcementFailure::new(CageEnforcementFailureCode::LandlockPartial, "landlock")
            .test_expect("partial enforcement failure"),
    )
    .test_expect("partial record");
    let rejected = CageEnforcementRecord::rejected(
        CageEnforcementFailure::new(CageEnforcementFailureCode::InvalidPlan, "admission")
            .test_expect("rejection"),
    )
    .test_expect("rejection record");
    let exited = CageEnforcementRecord::exited(
        evidence(),
        ProcessExitEvidence {
            process_id: 42,
            exit_code: Some(0),
            signal: None,
            exited_at_unix_ms: 1_002,
        },
    )
    .test_expect("exit record");
    for record in [partial, rejected, exited] {
        let state = record.state;
        let launch = signed_launch(record, &launcher);
        let receipt = tool_receipt(&kernel, "native-server", Some(launch_reference(&launch)));
        assert_eq!(render(&receipt, Some(&launch)), UNCONFINED, "{state:?}");
    }
}

#[test]
fn confinement_backend_kinds_are_closed_at_decode() {
    for (kind, wire) in [
        (ConfinementBackendKind::LinuxCage, "linux_cage"),
        (
            ConfinementBackendKind::FirecrackerGuest,
            "firecracker_guest",
        ),
        (
            ConfinementBackendKind::ProcessContainer,
            "process_container",
        ),
        (ConfinementBackendKind::AgentHostBwrap, "agent_host_bwrap"),
        (ConfinementBackendKind::Seatbelt, "seatbelt"),
    ] {
        assert_eq!(
            serde_json::to_value(kind).test_expect("encode backend kind"),
            wire
        );
        assert_eq!(
            serde_json::from_value::<ConfinementBackendKind>(wire.into())
                .test_expect("decode backend kind"),
            kind
        );
    }
    for unknown in ["microkernel", "LinuxCage", "best_effort", ""] {
        let error = serde_json::from_value::<ConfinementBackendKind>(unknown.into())
            .test_unwrap_err()
            .to_string();
        assert!(error.starts_with("unknown variant"), "{error}");
    }
    let error = serde_json::from_value::<ConfinementDisclosure>(serde_json::json!({
        "status": "confined",
        "detail": "gvisor",
    }))
    .test_unwrap_err()
    .to_string();
    assert!(error.starts_with("unknown variant `gvisor`"), "{error}");
}

#[test]
fn unconfined_reason_follows_signed_tool_origin() {
    use chio_core::receipt::kinds::ToolOrigin;
    for (origin, reason) in [
        (ToolOrigin::ChioInternal, UnconfinedReason::InProcess),
        (ToolOrigin::CallerExecuted, UnconfinedReason::CallerExecuted),
        (
            ToolOrigin::HostExecutedProviderReported,
            UnconfinedReason::HostExecuted,
        ),
        (
            ToolOrigin::HostExecutedUnmediated,
            UnconfinedReason::HostExecuted,
        ),
    ] {
        let disclosure = ConfinementDisclosure::Unconfined(origin.into());
        assert_eq!(disclosure, ConfinementDisclosure::Unconfined(reason));
        assert!(!disclosure.is_confined());
        assert!(disclosure.to_string().starts_with("unconfined: "));
    }
}
