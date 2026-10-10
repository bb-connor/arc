//! Continue a measured legacy capture under a current kernel without opening
//! or rebinding the original Process journal.
use super::near_capacity_historical_signing::retained_native_policy_and_ledger;
use super::*;

struct CapturedKernelFixture {
    kernel: ChioKernel,
    authority: SqliteAuthorityStore,
    control: CapabilityToken,
    seed: ToolCallRequest,
}

fn retained_physical_workflow(path: &Path) -> TestResult<Vec<u8>> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?)
}

fn retained_process_charge_count(path: &Path) -> TestResult<u64> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let charges: i64 = db.query_row(
        "SELECT tree_calls FROM processes WHERE id='root'",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(charges)?)
}

fn open_captured_kernel_only(
    path: &Path,
    scope: &RecoveryScopeV1,
) -> TestResult<CapturedKernelFixture> {
    assert!(path.join("legacy-near-capacity").exists());
    assert!(path.join("current-recovery-receipt-signer").exists());
    let authority =
        SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks"))?;
    let current_key = Keypair::from_seed(&[207; 32]);
    let (mut kernel, effects) = open_kernel(path, &authority, &current_key)?;
    kernel.register_tool_server(Box::new(PersistentEffectServer::new(
        path.join("effects.db"),
        effects,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    )?));
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    let (seed, old_control): (ToolCallRequest, CapabilityToken) =
        serde_json::from_slice(&std::fs::read(path.join("fixture.json"))?)?;
    let profile = authority.admission_operation_store().deployment(
        scope,
        &authority.mutation_fence(),
        now_ms()?,
    )?;
    let subject = old_control.subject.clone();
    assert!(profile
        .actors
        .as_slice()
        .iter()
        .any(|actor| actor.subject == subject
            && actor
                .permissions
                .as_slice()
                .contains(&RecoveryPermission::Inspect)));
    let control = kernel.issue_capability(&subject, old_control.scope.clone(), 600)?;
    // This is the same real native verifier configuration as the ordinary
    // fixture. The selected native authority comes from its authenticated
    // current deployment. No current Process/source owner is constructed.
    let config = FlowResolverConfig::new(
        if path.join("public-original-profile").exists() {
            InformationLabel::bottom()
        } else {
            restricted_label()
        },
        category_labels(),
        BTreeMap::from([(
            profile.aggregate_issuer_id.clone(),
            profile.aggregate_issuer,
        )]),
        60000,
    )?;
    let flow = Arc::new(
        NativeFlowResolver::new(
            profile.native_authority,
            declassification_registry_with_output_floor(
                &profile.purpose,
                fixture_output_floor(path)?,
            ),
            fixture_classifier(path),
            fixture_native_clock(path),
            config,
        )?
        .with_captured_lifecycle(),
    );
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    configure_fixture_history_hooks(&mut kernel, path, flow, &authority, &control)?;
    Ok(CapturedKernelFixture {
        kernel,
        authority,
        control,
        seed,
    })
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
#[ignore = "requires the reviewed measured40 state after genuine old35 Process boot refusal"]
async fn recovery_retained_near_capacity_capture_settles_with_current_kernel_without_rebinding_process(
) -> TestResult {
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::ReceiptStore;
    use rusqlite::OptionalExtension;
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_LEGACY_NEAR_CAP_ROOT")
            .ok_or("genuine reviewed old35 near-capacity capture root")?,
    );
    let before = retained_workflow(&path)?;
    let physical_before = retained_physical_workflow(&path)?;
    assert_eq!(chio_core::canonical_json_bytes(&before)?, physical_before);
    assert_eq!(physical_before.len(), 262_050);
    assert_eq!(
        chio_core::sha256_hex(&physical_before),
        "f894c109647e017268bedfff2054ea1bffca359a6eb67ca178df8609a8001c19"
    );
    assert!(before.captured && !before.admission_closed);
    assert!(before.captured_deployment.is_none() && before.historical_hold.is_none());
    let intent = before
        .admission
        .as_ref()
        .ok_or("old35 captured native intent")?;
    let operation_id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
    let native_before = native_original_bytes(&path, &before)?;
    let native_capture = chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
        serde_json::from_slice(&native_before)?,
    )?;
    assert_eq!(native_capture.state(), AdmissionOperationState::Finalizing);
    assert_eq!(native_capture.version(), 7);
    assert_eq!(
        native_capture.binding().to_persisted(),
        intent.native_binding
    );
    let raw_before = captured_return_bytes(&path, &before)?.1;
    let original_signer = captured_receipt_signer(&path, &before)?;
    assert_eq!(
        original_signer.algorithm(),
        chio_core::SigningAlgorithm::Ed25519
    );
    assert_eq!(
        original_signer,
        chio_core::PublicKey::from_hex(
            "fcbe38632417bb5b875d49a3c02270633917c6093fd01ebb59ff6416e37afe0c",
        )?
    );
    assert_eq!(raw_before.len(), 101_210);
    assert_eq!(
        chio_core::sha256_hex(&raw_before),
        "d2d035d1e2e6942c0ba941ea7e3d91fb9ed064d13d5ffe5ed5e5279413a01b2f"
    );
    let raw: serde_json::Value = serde_json::from_slice(&raw_before)?;
    assert_eq!(
        raw["receipt_signing_identity"]["crypto_floor"],
        "allow_classical"
    );
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        40
    );
    assert_eq!(
        db.query_row(
            "SELECT state FROM admission_operations WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get::<_, String>(0),
        )?,
        "finalizing"
    );
    assert_eq!(db.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*'", [],
        |row| row.get::<_, i64>(0),
    )?, 1);
    assert_eq!(db.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'workflow-quota:*'", [],
        |row| row.get::<_, i64>(0),
    )?, 0);
    let scope_hash = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&before.scope)?);
    let allocation_key = format!(
        "recovery-workflow-allocation:{scope_hash}:{}",
        before.workflow_id.as_str()
    );
    let allocation_before: Option<Vec<u8>> = db
        .query_row(
            "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [&allocation_key],
            |row| row.get(0),
        )
        .optional()?;
    let banks_before: i64 = db.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*'",
        [],
        |row| row.get(0),
    )?;
    assert!(allocation_before.is_none());
    assert_eq!(banks_before, 0);
    let original_profile_key = format!(
        "deployment-history:{scope_hash}:{}",
        hex::encode(before.deployment_digest.as_bytes())
    );
    let profile_bytes: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&original_profile_key],
        |row| row.get(0),
    )?;
    let profile: RecoveryDeploymentV1 = serde_json::from_slice(&profile_bytes)?;
    assert_eq!(
        DeploymentDigest::from_bytes(recovery_digest(RecoveryDigestDomain::Deployment, &profile,)?),
        before.deployment_digest
    );
    let retained_request_before: Vec<u8> = db.query_row(
        "SELECT request_json FROM admission_operation_tool_requests WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get(0),
    )?;
    let retained_request =
        chio_kernel::admission_operation::RetainedToolAdmissionRequestV1::from_canonical_bytes(
            &retained_request_before,
        )?;
    retained_request.validate_binding(native_capture.binding())?;
    retained_request.validate_native_security_authority(&profile.native_authority)?;
    retained_request.validate_native_security_context(&profile.security_context)?;
    let policy_and_ledger_before = retained_native_policy_and_ledger(&path, &operation_id)?;
    assert_eq!(policy_and_ledger_before.0.len(), 166_194);
    assert_eq!(policy_and_ledger_before.1.len(), 169_248);
    assert_eq!(
        chio_core::sha256_hex(&policy_and_ledger_before.0),
        "ab9734006bd67972166f058a163035a23d3257c5c199f643a1bf20f258b9d4c9"
    );
    assert_eq!(
        chio_core::sha256_hex(&policy_and_ledger_before.1),
        "3fd35c9072351c1995626bbaca281ffa69157c169658238915fc16de16bd60ee"
    );
    assert_eq!(retained_request_before.len(), 33_615);
    assert_eq!(
        chio_core::sha256_hex(&retained_request_before),
        "c05cd4ffc0ed06e48bbdd2434dbedc63d1ddd0852677cb4a15a9694beda3c2ea"
    );
    assert_eq!(
        native_capture
            .native_dispatch_ledger_digest()
            .map(|digest| digest.as_str()),
        Some(chio_core::sha256_hex(&policy_and_ledger_before.1).as_str())
    );
    drop(db);
    assert_eq!(external_count(&path)?, 1);
    // Read-only model of the exact earlier writer's growth. Never persist it.
    let mut old_hold_clone = before.clone();
    old_hold_clone.control = WorkflowControlV1::Quarantined;
    old_hold_clone.revision = SafeInteger::new(before.revision.get() + 1)?;
    let original_binding_digest: [u8; 32] =
        hex::decode(native_capture.binding().request_binding_hash().as_str())?
            .try_into()
            .map_err(|_| "original native binding digest width")?;
    old_hold_clone.historical_hold = Some(RecoveryHistoricalHoldV1 {
        operation: OperationRef::new(
            intent.native_operation_id.clone(),
            NativeAdmissionDigest::from_bytes(original_binding_digest),
            SafeInteger::new(7)?,
        )?,
        reason: RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable,
    });
    assert_eq!(
        chio_core::canonical_json_bytes(&old_hold_clone)?.len(),
        262_380
    );
    assert_eq!(
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&old_hold_clone)?),
        "32ddd0c69e38b1b9d22e8df3765145f9e9d9d346df8f822943b8b8a261d1fb1b"
    );
    assert!(262_380 > 262_144);
    assert!(path.join("current-recovery-receipt-signer").exists());
    let fixture = open_captured_kernel_only(&path, &before.scope)?;
    fixture.kernel.reconcile_durable_admission_startup()?;
    let current_signer = fixture.kernel.receipt_signing_public_key();
    assert_ne!(current_signer, original_signer);
    assert_ne!(fixture.kernel.public_key(), original_signer);
    let store = fixture.authority.admission_operation_store();
    let native = store
        .load_by_operation_id(&operation_id)?
        .ok_or("old35 private terminal")?;
    assert_eq!(native.state(), AdmissionOperationState::Completed);
    assert_eq!(native.binding().to_persisted(), intent.native_binding);
    assert_ne!(native_original_bytes(&path, &before)?, native_before);
    let terminal =
        store.inspect_captured_workflow_terminal_for_test(&before.scope, &before.workflow_id)?;
    assert!(terminal.captured && terminal.admission_closed && terminal.historical_hold.is_none());
    assert!(matches!(
        terminal.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        terminal.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&path)?)?,
        physical_before
    );
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    let receipt_id = match native.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("old35 private terminal receipt absent".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("old35 private receipt")?;
    assert_eq!(receipt.kernel_key, current_signer);
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    let marker = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.get(chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
        })
        .ok_or("old35 distinct private settlement")?;
    assert_eq!(
        marker["original_signing_identity"]["public_key"],
        serde_json::to_value(&original_signer)?
    );
    assert_eq!(
        marker["settlement_signing_identity"]["public_key"],
        serde_json::to_value(&current_signer)?
    );
    assert_eq!(
        marker["raw_output_digest"],
        chio_core::sha256_hex(&raw_before)
    );
    assert_eq!(
        marker["captured_deployment_digest"],
        serde_json::to_value(before.deployment_digest)?
    );
    assert_eq!(marker["disposition"], "permanently_withheld");
    assert_eq!(marker["operation_id"], operation_id.as_str());
    assert_eq!(
        marker["request_binding_hash"],
        native_capture.binding().request_binding_hash().as_str()
    );
    assert_eq!(marker["source_operation_version"], native_capture.version());
    assert_eq!(
        marker["store_fence"],
        serde_json::to_value(fixture.authority.mutation_fence())?
    );
    assert_eq!(
        marker["original_signing_identity"]["crypto_floor"],
        "allow_classical"
    );
    assert!(marker["historical_signing_hold"].is_null());
    let actor = fixture.kernel.authenticate_recovery_actor(
        &before.scope,
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(fixture
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    let db = rusqlite::Connection::open(path.join("admission.db"))?;
    let quota: serde_json::Value =
        serde_json::from_slice(&retained_workflow_quota_bytes(&path, &before)?.1)?;
    let terminal_digest: ProjectionDigest =
        serde_json::from_value(quota["native_terminal"]["record_digest"].clone())?;
    assert_ne!(terminal_digest, ProjectionDigest::from_bytes([0; 32]));
    let allocation_after: Option<Vec<u8>> = db
        .query_row(
            "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [&allocation_key],
            |row| row.get(0),
        )
        .optional()?;
    assert_eq!(allocation_after, allocation_before);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        banks_before
    );
    eprintln!("old35 capacity custody: entry absence preserved; private terminal quota owned");
    let policy_and_ledger_after = retained_native_policy_and_ledger(&path, &operation_id)?;
    assert_eq!(policy_and_ledger_after, policy_and_ledger_before);
    let retained_request_after: Vec<u8> = db.query_row(
        "SELECT request_json FROM admission_operation_tool_requests WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(retained_request_after, retained_request_before);
    drop(db);
    let terminal_bytes = native_original_bytes(&path, &before)?;
    let events = recovery_event_count(&path)?;
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
    }
    assert_eq!(native_original_bytes(&path, &before)?, terminal_bytes);
    assert_eq!(recovery_event_count(&path)?, events);
    // A fresh ordinary issuer-signed request is denied by its actual current
    // boundary. It still commits native compensation while old private debt is terminal.
    let mut request = fixture.seed.clone();
    request.request_id = "current-after-old35-kernel-private-settlement".to_owned();
    request.capability = fixture.kernel.issue_capability(
        &request.capability.subject,
        request.capability.scope.clone(),
        600,
    )?;
    let response = Box::pin(fixture.kernel.evaluate_tool_call(&request)).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    let (unrelated, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("unrelated native denial absent")?;
    assert_eq!(
        unrelated.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&path)?)?,
        physical_before
    );
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    drop(store);
    drop(fixture);
    let reopened = open_captured_kernel_only(&path, &before.scope)?;
    reopened.kernel.reconcile_durable_admission_startup()?;
    assert_eq!(native_original_bytes(&path, &before)?, terminal_bytes);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&path)?)?,
        physical_before
    );
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
#[ignore = "requires the reviewed private Completed state after the genuine old35 Kernel continuation"]
async fn recovery_current_kernel_reopens_retained_private_fate_and_admits_a_fresh_native_process(
) -> TestResult {
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::tool_outcome::{PrivateRecoverySettlementReceiptV1, ToolOutcomeStore};
    use chio_kernel::ReceiptStore;

    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_LEGACY_NEAR_CAP_ROOT")
            .ok_or("reviewed genuine post-Completed near-capacity root absent")?,
    );
    let current_process_path = path.join("current-native-process.db");
    assert!(
        !current_process_path.exists(),
        "new current journal must be genuinely fresh"
    );
    let before = retained_workflow(&path)?;
    let physical_before = retained_physical_workflow(&path)?;
    assert_eq!(chio_core::canonical_json_bytes(&before)?, physical_before);
    assert_eq!(physical_before.len(), 262_050);
    assert_eq!(
        chio_core::sha256_hex(&physical_before),
        "f894c109647e017268bedfff2054ea1bffca359a6eb67ca178df8609a8001c19"
    );
    let intent = before
        .admission
        .as_ref()
        .ok_or("original captured native intent absent")?;
    let operation_id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
    let terminal_before = native_original_bytes(&path, &before)?;
    let raw_before = captured_return_bytes(&path, &before)?.1;
    assert_eq!(raw_before.len(), 101_210);
    assert_eq!(
        chio_core::sha256_hex(&raw_before),
        "d2d035d1e2e6942c0ba941ea7e3d91fb9ed064d13d5ffe5ed5e5279413a01b2f"
    );
    let policy_and_ledger_before = retained_native_policy_and_ledger(&path, &operation_id)?;
    assert_eq!(policy_and_ledger_before.0.len(), 166_194);
    assert_eq!(policy_and_ledger_before.1.len(), 169_248);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    assert_eq!(external_count(&path)?, 1);

    let fixture = open_captured_kernel_only(&path, &before.scope)?;
    fixture.kernel.reconcile_durable_admission_startup()?;
    let store = fixture.authority.admission_operation_store();
    let outcomes = fixture.authority.tool_outcome_store();
    let original = store
        .load_by_operation_id(&operation_id)?
        .ok_or("private original absent at second current serving reopen")?;
    assert_eq!(original.state(), AdmissionOperationState::Completed);
    assert_eq!(original.version(), 8);
    assert_eq!(original.binding().to_persisted(), intent.native_binding);
    assert_eq!(native_original_bytes(&path, &before)?, terminal_before);
    let terminal =
        store.inspect_captured_workflow_terminal_for_test(&before.scope, &before.workflow_id)?;
    assert!(terminal.captured && terminal.admission_closed && terminal.historical_hold.is_none());
    assert!(matches!(
        terminal.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        terminal.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    let original_outcome = outcomes
        .lookup_by_operation(&operation_id)?
        .ok_or("private original outcome absent")?;
    original_outcome.validate_against(&original)?;
    let original_raw = outcomes
        .load_raw_invocation_by_operation(&operation_id)?
        .ok_or("private original raw absent")?;
    let original_blob = original_raw.canonical_blob()?;
    original_outcome.validate_canonical_blob(&original, &original_blob)?;
    assert_eq!(original_blob.bytes(), raw_before.as_slice());
    let frozen_outcome = chio_core::canonical_json_bytes(&original_outcome.to_persisted())?;
    let frozen_release = outcomes
        .lookup_security_release(&operation_id)?
        .ok_or("original private security release absent")?
        .canonical_bytes()?;
    let receipt_id = match original.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("original private terminal receipt absent".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("retained current signed private receipt absent")?;
    let frozen_receipt = chio_core::canonical_json_bytes(&receipt)?;
    assert_eq!(
        receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    let marker = PrivateRecoverySettlementReceiptV1::from_receipt(&receipt)?
        .ok_or("original private settlement marker absent")?;
    marker.validate_receipt(
        &receipt,
        &original,
        &original_outcome,
        before.deployment_digest,
        &fixture.authority.mutation_fence(),
        None,
    )?;
    marker.validate_completed_raw_return(&original_raw)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        &before.scope,
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(fixture
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    let events = recovery_event_count(&path)?;
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
    }
    assert_eq!(native_original_bytes(&path, &before)?, terminal_before);
    assert_eq!(recovery_event_count(&path)?, events);

    // A distinct real current Process selects its own persisted namespace and
    // capability lineage. It never opens or rebinds the predecessor journal.
    let current_key = fixture.kernel.public_key();
    assert_ne!(
        current_key,
        chio_core::PublicKey::from_hex(
            "fcbe38632417bb5b875d49a3c02270633917c6093fd01ebb59ff6416e37afe0c"
        )?
    );
    let new_capability = fixture.kernel.issue_capability(
        &fixture.seed.capability.subject,
        fixture.seed.capability.scope.clone(),
        600,
    )?;
    assert_eq!(new_capability.issuer, current_key);
    let current_kernel = Arc::new(fixture.kernel);
    let current_process = ProcessRuntime::open(&current_process_path, current_kernel.clone())?
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: "native-tenant".into(),
            isolation_epoch_id: "native-epoch".into(),
            generation: 1,
        })?;
    current_process.create_root(
        "current-root",
        &new_capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 32,
            state: Default::default(),
        },
    )?;
    let context = current_process.recovery_security_context("current-root")?;
    assert_eq!(
        context.as_v1().session_id().as_str(),
        current_process.runtime_id()
    );
    assert_eq!(
        context.as_v1().lineage_root_id().as_str(),
        new_capability.id
    );
    let request = current_process.tool_request(
        "current-root",
        "guarded-current-denial",
        "server-a",
        "send",
        fixture.seed.arguments.clone(),
    )?;
    let response = Box::pin(current_process.invoke_known_only(
        "current-root",
        "guarded-current-denial",
        &request,
    ))
    .await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    let (unrelated, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine current-context native denial absent")?;
    retained.validate_request_material(&request)?;
    let context = current_kernel.refresh_native_security_context(&context)?;
    retained.validate_native_security_context(&context)?;
    assert_eq!(
        unrelated.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_ne!(unrelated.binding().operation_id(), &operation_id);
    assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(native_original_bytes(&path, &before)?, terminal_before);
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        retained_native_policy_and_ledger(&path, &operation_id)?,
        policy_and_ledger_before
    );
    assert_eq!(
        chio_core::canonical_json_bytes(
            &outcomes
                .lookup_by_operation(&operation_id)?
                .ok_or("original outcome lost after current call")?
                .to_persisted()
        )?,
        frozen_outcome
    );
    assert_eq!(
        outcomes
            .lookup_security_release(&operation_id)?
            .ok_or("original release lost after current call")?
            .canonical_bytes()?,
        frozen_release
    );
    assert_eq!(
        chio_core::canonical_json_bytes(
            &store
                .load_chio_receipt(receipt_id.as_str())?
                .ok_or("original receipt lost after current call")?
        )?,
        frozen_receipt
    );
    for _ in 0..2 {
        current_kernel.reconcile_durable_admission_startup()?;
        current_kernel.reconcile_recoverable_admissions()?;
    }
    assert_eq!(native_original_bytes(&path, &before)?, terminal_before);
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(retained_process_charge_count(&path)?, 2);
    assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    assert_eq!(external_count(&path)?, 1);
    drop(current_process);
    drop(current_kernel);
    drop(outcomes);
    drop(store);
    drop(fixture.authority);

    let reopened = open_captured_kernel_only(&path, &before.scope)?;
    reopened.kernel.reconcile_durable_admission_startup()?;
    reopened.kernel.reconcile_recoverable_admissions()?;
    let reopened_store = reopened.authority.admission_operation_store();
    let reopened_outcomes = reopened.authority.tool_outcome_store();
    let original = reopened_store
        .load_by_operation_id(&operation_id)?
        .ok_or("original private fate absent after final current serving reopen")?;
    let outcome = reopened_outcomes
        .lookup_by_operation(&operation_id)?
        .ok_or("original outcome absent after final current serving reopen")?;
    let receipt = reopened_store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("original private receipt absent after final current serving reopen")?;
    assert_eq!(native_original_bytes(&path, &before)?, terminal_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&outcome.to_persisted())?,
        frozen_outcome
    );
    assert_eq!(chio_core::canonical_json_bytes(&receipt)?, frozen_receipt);
    assert_eq!(
        reopened_outcomes
            .lookup_security_release(&operation_id)?
            .ok_or("original private release absent after final reopen")?
            .canonical_bytes()?,
        frozen_release
    );
    marker.validate_receipt(
        &receipt,
        &original,
        &outcome,
        before.deployment_digest,
        &reopened.authority.mutation_fence(),
        None,
    )?;
    let actor = reopened.kernel.authenticate_recovery_actor(
        &before.scope,
        &reopened.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(reopened
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    assert_eq!(retained_physical_workflow(&path)?, physical_before);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        retained_native_policy_and_ledger(&path, &operation_id)?,
        policy_and_ledger_before
    );
    assert_eq!(retained_process_charge_count(&path)?, 2);
    assert_eq!(external_count(&path)?, 1);
    let current_journal = rusqlite::Connection::open_with_flags(
        &current_process_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let current_charges: i64 = current_journal.query_row(
        "SELECT tree_calls FROM processes WHERE id='current-root'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(current_charges, 1);
    Ok(())
}
