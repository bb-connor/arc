//! Settle a genuine recorded local return after the application signer changes.
//! Each ignored case consumes a different independently retained predecessor root.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationV1, AdmissionReceiptMetadataV1,
    AdmissionTerminalReplay, RetainedToolAdmissionRequestV1,
};
use chio_kernel::tool_outcome::{
    PostReturnEvaluationStateV1, PrivateRecoverySettlementReceiptV1, RawInvocationOutcomeV1,
    ResolvedToolOutcomeV1, ToolOutcomeRecordV1, ToolOutcomeStore,
};
use chio_kernel::ReceiptStore;
use rusqlite::{Connection, OpenFlags};

fn digest_denial_stage(stage: &'static str) {
    if std::env::var_os("CHIO_RECORDED_DIGEST_STAGE_DIAGNOSTIC").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        eprintln!("recorded-digest-denial-stage: {stage}");
    }
}

struct OriginalDigestCapture {
    workflow: RecoveryWorkflowRecordV1,
    workflow_bytes: Vec<u8>,
    operation: AdmissionOperationV1,
    retained_request: Vec<u8>,
    raw: Vec<u8>,
    ledger: Vec<u8>,
    policy: Vec<u8>,
    original_signer: chio_core::PublicKey,
    fixture_bytes: Vec<u8>,
}

fn read_only(path: &Path) -> TestResult<Connection> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    Ok(db)
}

fn original_process_charge(path: &Path) -> TestResult<i64> {
    Ok(read_only(&path.join("process.db"))?.query_row(
        "SELECT tree_calls FROM processes WHERE id='root'",
        [],
        |row| row.get(0),
    )?)
}

fn read_original_digest_capture(path: &Path) -> TestResult<OriginalDigestCapture> {
    assert_eq!(
        std::fs::read(path.join("original-recovery-receipt-signer"))?,
        b"1"
    );
    assert_eq!(std::fs::read(path.join("mismatched-output-digest"))?, b"1");
    assert!(!path.join("current-recovery-receipt-signer").exists());
    assert!(!path.join("current-digest-denial-process.db").exists());
    let workflow = retained_workflow(path)?;
    let db = read_only(&path.join("admission.db"))?;
    let workflow_bytes: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(chio_core::canonical_json_bytes(&workflow)?, workflow_bytes);
    assert!(workflow.captured && !workflow.admission_closed);
    assert!(workflow.historical_hold.is_none());
    let intent = workflow
        .admission
        .as_ref()
        .ok_or("recorded digest denial intent")?;
    let operation_id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
    let native = native_original_bytes(path, &workflow)?;
    let operation = AdmissionOperationV1::from_persisted(serde_json::from_slice(&native)?)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&operation.to_persisted())?,
        native
    );
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    assert_eq!(operation.version(), 7);
    assert_eq!(operation.binding().to_persisted(), intent.native_binding);
    assert!(operation.dispatch_commit().is_some());
    let retained_request: Vec<u8> = db.query_row(
        "SELECT request_json FROM admission_operation_tool_requests WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get(0),
    )?;
    let retained = RetainedToolAdmissionRequestV1::from_canonical_bytes(&retained_request)?;
    retained.validate_binding(operation.binding())?;
    assert!(
        retained.native_output_retention().is_none(),
        "the actual predecessor selected no future retention profile"
    );
    let wire: serde_json::Value = serde_json::from_slice(&retained_request)?;
    let request: ToolCallRequest = serde_json::from_value(wire["request"].clone())?;
    retained.validate_request_material(&request)?;
    let expected_digest = chio_core::sha256_hex(b"an output the provider will never return");
    assert!(request.capability.scope.grants.iter().any(|grant| {
        grant.server_id == request.server_id
            && grant.tool_name == request.tool_name
            && grant.constraints.iter().any(|constraint| {
                matches!(constraint, chio_core::capability::scope::Constraint::OutputDigestSha256(digest) if digest == &expected_digest)
            })
    }));
    let (outcome_bytes, raw) = captured_return_bytes(path, &workflow)?;
    let outcome = ToolOutcomeRecordV1::from_persisted(serde_json::from_slice(&outcome_bytes)?)?;
    let decoded = RawInvocationOutcomeV1::from_canonical_bytes(&raw)?;
    let blob = decoded.canonical_blob()?;
    assert_eq!(blob.bytes(), raw.as_slice());
    outcome.validate_canonical_blob(&operation, &blob)?;
    assert!(matches!(
        outcome.disposition(),
        ResolvedToolOutcomeV1::Returned
    ));
    assert!(matches!(
        decoded.to_persisted().output,
        chio_kernel::tool_outcome::InvocationOutputV1::Value { .. }
    ));
    let original_signer = captured_receipt_signer(path, &workflow)?;
    assert_eq!(
        original_signer.algorithm(),
        chio_core::SigningAlgorithm::Hybrid
    );
    let ledger: Vec<u8> = db.query_row(
        "SELECT canonical_record FROM admission_operation_native_dispatch_ledger WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get(0),
    )?;
    let ledger_wire: serde_json::Value = serde_json::from_slice(&ledger)?;
    assert_eq!(chio_core::canonical_json_bytes(&ledger_wire)?, ledger);
    let policy = chio_core::canonical_json_bytes(
        ledger_wire
            .get("policy")
            .ok_or("original captured policy")?,
    )?;
    assert_eq!(external_count(path)?, 1);
    assert_eq!(original_process_charge(path)?, 2);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM post_return_evaluations WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM tool_outcome_security_releases WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    let fixture_bytes = std::fs::read(path.join("fixture.json"))?;
    Ok(OriginalDigestCapture {
        workflow,
        workflow_bytes,
        operation,
        retained_request,
        raw,
        ledger,
        policy,
        original_signer,
        fixture_bytes,
    })
}

fn require_original_bytes(path: &Path, original: &OriginalDigestCapture) -> TestResult {
    let db = read_only(&path.join("admission.db"))?;
    let workflow: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(workflow, original.workflow_bytes);
    let request: Vec<u8> = db.query_row(
        "SELECT request_json FROM admission_operation_tool_requests WHERE operation_id=?1",
        [original.operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(request, original.retained_request);
    let ledger: Vec<u8> = db.query_row(
        "SELECT canonical_record FROM admission_operation_native_dispatch_ledger WHERE operation_id=?1",
        [original.operation.binding().operation_id().as_str()], |row| row.get(0),
    )?;
    assert_eq!(ledger, original.ledger);
    let wire: serde_json::Value = serde_json::from_slice(&ledger)?;
    assert_eq!(
        chio_core::canonical_json_bytes(wire.get("policy").ok_or("retained original policy")?)?,
        original.policy
    );
    assert_eq!(
        captured_return_bytes(path, &original.workflow)?.1,
        original.raw
    );
    assert_eq!(
        std::fs::read(path.join("fixture.json"))?,
        original.fixture_bytes
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(original_process_charge(path)?, 2);
    let count: i64 = db.query_row("SELECT count(*) FROM admission_operations WHERE operation_id=?1 AND state='denied_after_delivery'", [original.operation.binding().operation_id().as_str()], |row| row.get(0))?;
    assert_eq!(count, 1);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct TerminalDigestCustody {
    native: Vec<u8>,
    outcome: Vec<u8>,
    evaluation: Vec<u8>,
    release: Vec<u8>,
    receipt: Vec<u8>,
}

fn require_private_digest_terminal(
    fixture: &RecoveryFixture,
    original: &OriginalDigestCapture,
    current_signer: &chio_core::PublicKey,
    old_hold: Option<&chio_kernel::recovery::RecoveryHistoricalHoldV1>,
    inspect: &CapabilityToken,
) -> TestResult<TerminalDigestCustody> {
    let id = original.operation.binding().operation_id();
    let store = fixture.authority.admission_operation_store();
    let outcomes = fixture.authority.tool_outcome_store();
    let operation = store
        .load_by_operation_id(id)?
        .ok_or("private digest terminal absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    assert_eq!(operation.version(), original.operation.version() + 1);
    assert_eq!(operation.binding(), original.operation.binding());
    assert_eq!(
        operation.dispatch_commit(),
        original.operation.dispatch_commit()
    );
    assert_eq!(
        operation.native_dispatch_ledger_digest(),
        original.operation.native_dispatch_ledger_digest()
    );
    let (_, retained) = store
        .load_retained_tool_request(id, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("retained digest request absent")?;
    retained.validate_binding(operation.binding())?;
    assert_eq!(
        retained.canonical_bytes(),
        original.retained_request.as_slice()
    );
    let ledger = store
        .load_native_dispatch_ledger(id, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("authenticated original digest ledger absent")?;
    assert_eq!(ledger.canonical_record, original.ledger);
    assert_eq!(
        Some(&ledger.record_digest),
        operation.native_dispatch_ledger_digest()
    );
    let outcome = outcomes
        .lookup_by_operation(id)?
        .ok_or("private digest outcome absent")?;
    let raw = outcomes
        .load_raw_invocation_by_operation(id)?
        .ok_or("authenticated original digest return absent")?;
    outcome.validate_canonical_blob(&operation, &raw.canonical_blob()?)?;
    assert_eq!(raw.canonical_blob()?.bytes(), original.raw.as_slice());
    assert!(matches!(
        outcome.disposition(),
        ResolvedToolOutcomeV1::Resolved { .. }
    ));
    let evaluation = outcomes
        .lookup_post_return_evaluation(id)?
        .ok_or("original frozen digest evaluation absent")?;
    evaluation.validate_against(&operation, &outcome)?;
    assert!(matches!(
        evaluation.state(),
        PostReturnEvaluationStateV1::Resolved { .. }
    ));
    let release = outcomes
        .lookup_security_release(id)?
        .ok_or("private digest release checkpoint absent")?;
    release.validate_against(&operation, &raw, &outcome, &evaluation)?;
    let receipt_id = match operation.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("private digest receipt reference absent".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("private digest receipt absent")?;
    assert_eq!(&receipt.kernel_key, current_signer);
    assert_ne!(receipt.kernel_key, original.original_signer);
    assert!(matches!(
        receipt.decision,
        Some(chio_core_types::receipt::decision::Decision::Deny { .. })
    ));
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    let mut redacted = b"chio.delivery-mismatch.redacted.v1\0".to_vec();
    redacted.extend_from_slice(
        chio_core::sha256_hex(b"an output the provider will never return").as_bytes(),
    );
    assert_eq!(receipt.content_hash, chio_core::sha256_hex(&redacted));
    assert_ne!(receipt.content_hash, chio_core::sha256_hex(&original.raw));
    let marker = PrivateRecoverySettlementReceiptV1::from_receipt(&receipt)?
        .ok_or("signed private digest marker absent")?;
    marker.validate_receipt(
        &receipt,
        &operation,
        &outcome,
        original.workflow.deployment_digest,
        &fixture.authority.mutation_fence(),
        old_hold,
    )?;
    marker.validate_completed_raw_return(&raw)?;
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or("private digest metadata absent")?;
    let admission: AdmissionReceiptMetadataV1 = serde_json::from_value(
        metadata[chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY].clone(),
    )?;
    assert_eq!(
        admission.projected_state,
        AdmissionOperationState::DeniedAfterDelivery
    );
    assert!(admission.tool_outcome_id.is_none() && admission.tool_outcome_version.is_none());
    assert_eq!(
        metadata[chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY]
            ["disposition"],
        "permanently_withheld"
    );
    let db = read_only(&fixture.path.join("admission.db"))?;
    let projection: Vec<u8> = db.query_row("SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id=?1", [id.as_str()], |row| row.get(0))?;
    let projection: serde_json::Value = serde_json::from_slice(&projection)?;
    assert_eq!(projection["terminal"], "denied_after_delivery");
    assert_eq!(projection["reason"], "digest_mismatch");
    let actor = fixture.kernel.authenticate_recovery_actor(
        &original.workflow.scope,
        inspect,
        RecoveryPermission::Inspect,
    )?;
    let settled = fixture
        .kernel
        .read_recovery_workflow(&actor, &original.workflow.workflow_id)?;
    assert!(settled.captured && settled.admission_closed);
    assert!(settled.historical_hold.is_none());
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        settled.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    assert!(fixture
        .kernel
        .replay_recovery_result(&actor, &original.workflow.workflow_id)
        .is_err());
    let quota: serde_json::Value = serde_json::from_slice(
        &retained_workflow_quota_bytes(&fixture.path, &original.workflow)?.1,
    )?;
    assert!(
        quota["native_terminal"].is_object(),
        "private terminal must retain its actual native quota custody"
    );
    require_original_bytes(&fixture.path, original)?;
    Ok(TerminalDigestCustody {
        native: native_original_bytes(&fixture.path, &original.workflow)?,
        outcome: chio_core::canonical_json_bytes(&outcome.to_persisted())?,
        evaluation: chio_core::canonical_json_bytes(&evaluation.to_persisted())?,
        release: release.canonical_bytes()?,
        receipt: chio_core::canonical_json_bytes(&receipt)?,
    })
}

fn require_retained_signer_hold_audit(
    path: &Path,
    workflow: &RecoveryWorkflowRecordV1,
    retained_hold: Option<&(
        chio_kernel::recovery::RecoveryHistoricalHoldV1,
        serde_json::Value,
        String,
    )>,
) -> TestResult {
    if let Some((_, native_hold, audit_digest)) = retained_hold {
        let db = read_only(&path.join("admission.db"))?;
        let quota: serde_json::Value =
            serde_json::from_slice(&retained_workflow_quota_bytes(path, workflow)?.1)?;
        assert_eq!(&quota["native_hold"], native_hold);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM admission_operation_recovery_events WHERE record_digest=?1",
                [audit_digest],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
    }
    Ok(())
}

async fn consume_genuine_digest_capture(previously_held: bool) -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECORDED_DIGEST_CAPTURE_ROOT")
            .ok_or("reviewed genuine local recorded digest-mismatch root")?,
    );
    digest_denial_stage("original-custody-enter");
    let original = Box::new(read_original_digest_capture(&path)?);
    digest_denial_stage("original-custody-complete");
    let id = original.operation.binding().operation_id();
    let retained_hold = if previously_held {
        let authority =
            SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks"))?;
        authority
            .admission_operation_store()
            .recovery_authority()
            .ok_or("owning original digest authority")?
            .quarantine_historical(
                id,
                RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable,
                &authority.mutation_fence(),
                now_ms()?,
            )?;
        let quota = retained_workflow_quota_bytes(&path, &original.workflow)?.1;
        let value: serde_json::Value = serde_json::from_slice(&quota)?;
        let hold: chio_kernel::recovery::RecoveryHistoricalHoldV1 =
            serde_json::from_value(value["native_hold"]["hold"].clone())?;
        let db = read_only(&path.join("admission.db"))?;
        let audit_digest: String = db.query_row(
            "SELECT e.record_digest FROM admission_operation_recovery_events e JOIN admission_operation_recovery_records r ON e.record_key=r.record_key AND e.record_version=r.version WHERE r.record_key GLOB 'workflow-quota:*' AND r.payload=?1",
            [&quota], |row| row.get(0),
        )?;
        Some((hold, value["native_hold"].clone(), audit_digest))
    } else {
        None
    };
    std::fs::write(path.join("current-recovery-receipt-signer"), b"1")?;
    std::fs::remove_file(path.join("original-recovery-receipt-signer"))?;
    digest_denial_stage("current-serving-open-enter");
    let fixture = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    digest_denial_stage("current-serving-open-complete");
    let first_fence = fixture.authority.mutation_fence();
    let current_signer = fixture.kernel.receipt_signing_public_key();
    assert_eq!(
        current_signer.algorithm(),
        chio_core::SigningAlgorithm::Hybrid
    );
    assert_ne!(current_signer, original.original_signer);
    let inspect = fixture.kernel.issue_capability(
        &fixture.control.subject,
        fixture.control.scope.clone(),
        600,
    )?;
    let frozen = require_private_digest_terminal(
        &fixture,
        &original,
        &current_signer,
        retained_hold.as_ref().map(|value| &value.0),
        &inspect,
    )?;
    require_retained_signer_hold_audit(&path, &original.workflow, retained_hold.as_ref())?;
    digest_denial_stage("initial-terminal-custody-complete");
    let events = recovery_event_count(&path)?;
    digest_denial_stage("before-current-call-reconcile-enter");
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            require_private_digest_terminal(
                &fixture,
                &original,
                &current_signer,
                retained_hold.as_ref().map(|value| &value.0),
                &inspect
            )?,
            frozen
        );
        require_retained_signer_hold_audit(&path, &original.workflow, retained_hold.as_ref())?;
        assert_eq!(recovery_event_count(&path)?, events);
    }
    digest_denial_stage("before-current-call-reconcile-complete");
    // Only a new local Process supplies the genuine current trusted session.
    // Its call is independently refused before capture by current guards.
    let current_process_path = path.join("current-digest-denial-process.db");
    assert!(!current_process_path.exists());
    let capability = fixture.kernel.issue_capability(
        &fixture.seed.capability.subject,
        fixture.seed.capability.scope.clone(),
        600,
    )?;
    let current_process = ProcessRuntime::open(&current_process_path, fixture.kernel.clone())?
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: "native-tenant".into(),
            isolation_epoch_id: "native-epoch".into(),
            generation: 1,
        })?;
    current_process.create_root(
        "current-root",
        &capability,
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
    assert_eq!(context.as_v1().lineage_root_id().as_str(), capability.id);
    let request = current_process.tool_request(
        "current-root",
        "guarded-current-denial",
        "server-a",
        "send",
        fixture.seed.arguments.clone(),
    )?;
    digest_denial_stage("current-invoke-enter");
    let response = Box::pin(current_process.invoke_known_only(
        "current-root",
        "guarded-current-denial",
        &request,
    ))
    .await?;
    digest_denial_stage("current-invoke-complete");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(response.receipt.kernel_key, current_signer);
    assert!(response.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    assert!(PrivateRecoverySettlementReceiptV1::from_receipt(&response.receipt)?.is_none());
    digest_denial_stage("current-native-lookup-enter");
    let store = fixture.authority.admission_operation_store();
    let (fresh, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine current native digest denial absent")?;
    retained.validate_request_material(&request)?;
    retained.validate_native_security_context(
        &fixture.kernel.refresh_native_security_context(&context)?,
    )?;
    assert_ne!(fresh.binding().operation_id(), id);
    assert_eq!(
        fresh.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(fresh.dispatch_commit().is_none());
    assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    assert_eq!(original_process_charge(&path)?, 2);
    assert_eq!(
        original_process_charge(&path)?
            + i64::try_from(current_process.process("current-root")?.tree_calls)?,
        3
    );
    assert_eq!(external_count(&path)?, 1);
    digest_denial_stage("after-current-call-reconcile-enter");
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            require_private_digest_terminal(
                &fixture,
                &original,
                &current_signer,
                retained_hold.as_ref().map(|value| &value.0),
                &inspect
            )?,
            frozen
        );
        require_retained_signer_hold_audit(&path, &original.workflow, retained_hold.as_ref())?;
        assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    }
    digest_denial_stage("after-current-call-reconcile-complete");
    digest_denial_stage("store-drop-enter");
    drop(store);
    digest_denial_stage("store-drop-complete");
    digest_denial_stage("current-process-drop-enter");
    drop(current_process);
    digest_denial_stage("current-process-drop-complete");
    digest_denial_stage("fixture-drop-enter");
    drop(fixture);
    digest_denial_stage("fixture-drop-complete");
    digest_denial_stage("second-serving-open-enter");
    let reopened = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    digest_denial_stage("second-serving-open-complete");
    assert_eq!(
        reopened.authority.mutation_fence().store_uuid,
        first_fence.store_uuid
    );
    assert!(reopened.authority.mutation_fence().owner_epoch > first_fence.owner_epoch);
    let inspect = reopened.kernel.issue_capability(
        &reopened.control.subject,
        reopened.control.scope.clone(),
        600,
    )?;
    for _ in 0..2 {
        reopened.kernel.reconcile_durable_admission_startup()?;
        reopened.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            require_private_digest_terminal(
                &reopened,
                &original,
                &current_signer,
                retained_hold.as_ref().map(|value| &value.0),
                &inspect
            )?,
            frozen
        );
        require_retained_signer_hold_audit(&path, &original.workflow, retained_hold.as_ref())?;
    }
    digest_denial_stage("second-serving-reconcile-complete");
    let current_journal = read_only(&current_process_path)?;
    assert_eq!(
        current_journal.query_row(
            "SELECT tree_calls FROM processes WHERE id='current-root'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(original_process_charge(&path)?, 2);
    assert_eq!(external_count(&path)?, 1);
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
#[ignore = "consumes one independently reviewed genuine recorded digest-mismatch root"]
async fn recovery_genuine_recorded_digest_denial_settles_with_a_current_signer() -> TestResult {
    Box::pin(consume_genuine_digest_capture(false)).await
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
#[ignore = "consumes a separate genuine recorded digest-mismatch root with an owning signer hold"]
async fn recovery_genuine_held_recorded_digest_denial_settles_with_a_current_signer() -> TestResult
{
    Box::pin(consume_genuine_digest_capture(true)).await
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_current_signer_fixture_releases_its_owner_without_capture() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_path_buf();
    std::fs::write(path.join("current-recovery-receipt-signer"), b"1")?;
    digest_denial_stage("fresh-owner-open-enter");
    let fixture = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    digest_denial_stage("fresh-owner-open-complete");
    let first_fence = fixture.authority.mutation_fence();
    assert_eq!(
        fixture.kernel.receipt_signing_public_key().algorithm(),
        chio_core::SigningAlgorithm::Hybrid
    );
    let store = fixture.authority.admission_operation_store();
    assert_eq!(external_count(&path)?, 0);
    {
        let db = read_only(&path.join("admission.db"))?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM tool_outcome_blobs", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM admission_operation_native_dispatch_ledger",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    digest_denial_stage("fresh-store-drop-enter");
    drop(store);
    digest_denial_stage("fresh-store-drop-complete");
    digest_denial_stage("fresh-fixture-drop-enter");
    drop(fixture);
    digest_denial_stage("fresh-fixture-drop-complete");
    digest_denial_stage("fresh-next-owner-open-enter");
    let reopened =
        SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks"))?;
    digest_denial_stage("fresh-next-owner-open-complete");
    assert_eq!(reopened.mutation_fence().store_uuid, first_fence.store_uuid);
    assert!(reopened.mutation_fence().owner_epoch > first_fence.owner_epoch);
    assert_eq!(external_count(&path)?, 0);
    Ok(())
}

fn require_fresh_denial_zero_capture(path: &Path) -> TestResult {
    let db = read_only(&path.join("admission.db"))?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM tool_outcome_blobs", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM admission_operation_native_dispatch_ledger",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(external_count(path)?, 0);
    assert_eq!(original_process_charge(path)?, 0);
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_current_native_denial_returns_and_releases_its_owner_without_capture(
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_path_buf();
    std::fs::write(path.join("current-recovery-receipt-signer"), b"1")?;
    digest_denial_stage("fresh-denial-fixture-open-enter");
    let fixture = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    digest_denial_stage("fresh-denial-fixture-open-complete");
    let first_fence = fixture.authority.mutation_fence();
    let current_signer = fixture.kernel.receipt_signing_public_key();
    assert_eq!(
        current_signer.algorithm(),
        chio_core::SigningAlgorithm::Hybrid
    );
    require_fresh_denial_zero_capture(&path)?;
    let current_process_path = path.join("fresh-current-digest-denial-process.db");
    assert!(!current_process_path.exists());
    let capability = fixture.kernel.issue_capability(
        &fixture.seed.capability.subject,
        fixture.seed.capability.scope.clone(),
        600,
    )?;
    let current_process = ProcessRuntime::open(&current_process_path, fixture.kernel.clone())?
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: "native-tenant".into(),
            isolation_epoch_id: "native-epoch".into(),
            generation: 1,
        })?;
    current_process.create_root(
        "current-root",
        &capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 32,
            state: Default::default(),
        },
    )?;
    assert_eq!(current_process.process("current-root")?.tree_calls, 0);
    let context = current_process.recovery_security_context("current-root")?;
    assert_eq!(
        context.as_v1().session_id().as_str(),
        current_process.runtime_id()
    );
    assert_eq!(context.as_v1().lineage_root_id().as_str(), capability.id);
    let request = current_process.tool_request(
        "current-root",
        "fresh-current-native-denial",
        "server-a",
        "send",
        fixture.seed.arguments.clone(),
    )?;
    digest_denial_stage("fresh-current-invoke-enter");
    let response = Box::pin(current_process.invoke_known_only(
        "current-root",
        "fresh-current-native-denial",
        &request,
    ))
    .await?;
    digest_denial_stage("fresh-current-invoke-complete");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(response.receipt.kernel_key, current_signer);
    assert!(response.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    assert!(PrivateRecoverySettlementReceiptV1::from_receipt(&response.receipt)?.is_none());
    digest_denial_stage("fresh-current-native-custody-enter");
    let store = fixture.authority.admission_operation_store();
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("fresh current native denial absent")?;
    retained.validate_request_material(&request)?;
    retained.validate_native_security_context(
        &fixture.kernel.refresh_native_security_context(&context)?,
    )?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    require_fresh_denial_zero_capture(&path)?;
    let operation_id = operation.binding().operation_id().clone();
    let terminal_bytes = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let request_bytes = retained.canonical_bytes().to_vec();
    digest_denial_stage("fresh-current-native-custody-complete");
    digest_denial_stage("fresh-after-invoke-reconcile-enter");
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
        let observed = store
            .load_by_operation_id(&operation_id)?
            .ok_or("fresh denied terminal lost after startup")?;
        assert_eq!(
            chio_core::canonical_json_bytes(&observed.to_persisted())?,
            terminal_bytes
        );
        assert_eq!(current_process.process("current-root")?.tree_calls, 1);
        require_fresh_denial_zero_capture(&path)?;
    }
    digest_denial_stage("fresh-after-invoke-reconcile-complete");
    digest_denial_stage("fresh-invoked-store-drop-enter");
    drop(store);
    digest_denial_stage("fresh-invoked-store-drop-complete");
    digest_denial_stage("fresh-invoked-process-drop-enter");
    drop(current_process);
    digest_denial_stage("fresh-invoked-process-drop-complete");
    digest_denial_stage("fresh-invoked-fixture-drop-enter");
    drop(fixture);
    digest_denial_stage("fresh-invoked-fixture-drop-complete");
    digest_denial_stage("fresh-invoked-next-owner-open-enter");
    let reopened = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    digest_denial_stage("fresh-invoked-next-owner-open-complete");
    assert_eq!(
        reopened.authority.mutation_fence().store_uuid,
        first_fence.store_uuid
    );
    assert!(reopened.authority.mutation_fence().owner_epoch > first_fence.owner_epoch);
    assert_eq!(reopened.kernel.receipt_signing_public_key(), current_signer);
    let reopened_store = reopened.authority.admission_operation_store();
    for _ in 0..2 {
        reopened.kernel.reconcile_durable_admission_startup()?;
        reopened.kernel.reconcile_recoverable_admissions()?;
        let observed = reopened_store
            .load_by_operation_id(&operation_id)?
            .ok_or("fresh denied terminal lost after new owner")?;
        assert_eq!(
            chio_core::canonical_json_bytes(&observed.to_persisted())?,
            terminal_bytes
        );
        let (_, retained) = reopened_store
            .load_retained_tool_request(
                &operation_id,
                &reopened.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("fresh denied request lost after new owner")?;
        assert_eq!(retained.canonical_bytes(), request_bytes.as_slice());
        require_fresh_denial_zero_capture(&path)?;
    }
    let current_journal = read_only(&current_process_path)?;
    assert_eq!(
        current_journal.query_row(
            "SELECT tree_calls FROM processes WHERE id='current-root'",
            [],
            |row| { row.get::<_, i64>(0) }
        )?,
        1
    );
    digest_denial_stage("fresh-invoked-next-owner-reconcile-complete");
    Ok(())
}
