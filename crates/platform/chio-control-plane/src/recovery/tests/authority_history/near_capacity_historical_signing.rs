//! Consume one independently reviewed actual schema-35 captured native effect.
//! This never creates, resizes or repairs its original workflow or raw return.
use super::*;

pub(super) fn retained_native_policy_and_ledger(
    path: &Path,
    operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (digest, ledger): (String, Vec<u8>) = db.query_row(
        "SELECT record_digest,canonical_record FROM admission_operation_native_dispatch_ledger WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let value: serde_json::Value = serde_json::from_slice(&ledger)?;
    assert_eq!(chio_core::canonical_json_bytes(&value)?, ledger);
    assert_eq!(chio_core::sha256_hex(&ledger), digest);
    let policy = chio_core::canonical_json_bytes(
        value.get("policy").ok_or("original native ledger policy")?,
    )?;
    Ok((policy, ledger))
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
#[ignore = "requires the independently reviewed genuine old35 legal-band capture"]
async fn recovery_legacy_near_capacity_capture_reaches_current_signed_withheld_terminal(
) -> TestResult {
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::ReceiptStore;
    use rusqlite::OptionalExtension;
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_LEGACY_NEAR_CAP_ROOT")
            .ok_or("genuine reviewed old35 near-capacity capture root")?,
    );
    let before = retained_workflow(&path)?;
    let physical_before = chio_core::canonical_json_bytes(&before)?;
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
        35
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
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*' OR record_key GLOB 'workflow-quota:*'", [],
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
    let profile_bytes: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment:*'", [], |row| row.get(0),
    )?;
    let mut profile: RecoveryDeploymentV1 = serde_json::from_slice(&profile_bytes)?;
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
    assert!(!path.join("current-recovery-receipt-signer").exists());
    // A new qualified boot signer, not the predecessor's classical identity.
    std::fs::write(path.join("current-recovery-receipt-signer"), b"1")?;
    let mut assignments = profile.actors.as_slice().to_vec();
    for assignment in &mut assignments {
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            assignment.preview_clearance = restricted_label();
        }
    }
    profile.actors = NonEmptyBoundedList::new(assignments)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    // The normal operator installation archives the authentic original public
    // profile before changing current finite clearance. No old root is invented.
    install_current_profile(&path, &profile)?;
    let mut fixture = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    fixture.control = fixture.kernel.issue_capability(
        &fixture.approval_key.public_key(),
        fixture.control.scope.clone(),
        600,
    )?;
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
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
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
        fixture
            .runtime
            .settle(&fixture.control, &before.workflow_id)?;
    }
    assert_eq!(native_original_bytes(&path, &before)?, terminal_bytes);
    assert_eq!(recovery_event_count(&path)?, events);
    // A fresh ordinary issuer-signed request is denied by its actual current
    // boundary. It still commits native compensation while old private debt is terminal.
    let mut request = fixture.seed.clone();
    request.request_id = "current-after-old35-private-settlement".to_owned();
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
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&path)?)?,
        physical_before
    );
    drop(store);
    drop(fixture);
    let reopened = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    assert_eq!(native_original_bytes(&path, &before)?, terminal_bytes);
    assert_eq!(captured_return_bytes(&path, &before)?.1, raw_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&path)?)?,
        physical_before
    );
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, 2);
    Ok(())
}
