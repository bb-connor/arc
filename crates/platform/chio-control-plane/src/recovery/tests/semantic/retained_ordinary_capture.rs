//! Restore an actual predecessor ordinary capture without a recovery workflow.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationV1, AdmissionTerminalReplay,
};
use chio_kernel::tool_outcome::{
    PostReturnEvaluationStateV1, RawInvocationOutcomeV1, ResolvedToolOutcomeV1, ToolOutcomeStore,
};
use chio_kernel::ReceiptStore;
use std::path::Path;

const ORIGINAL_OPERATION: &str = "81d5920b46925dc605ccfdcb2c6ee651ef062aa1737dd398ed7a67a3daa0a1f4";
const ORIGINAL_RAW: &str = "11d383723c85b5add24bb28b8a94d6b93df80db7f89dc4377825ae08ae35aa0f";
const ORIGINAL_SIGNER: &str = "fcbe38632417bb5b875d49a3c02270633917c6093fd01ebb59ff6416e37afe0c";

struct OriginalOrdinaryCapture {
    operation: AdmissionOperationV1,
    retained: Vec<u8>,
    raw: Vec<u8>,
    ledger: Vec<u8>,
    installation: Vec<u8>,
    protected_records: Vec<(String, i64, Vec<u8>)>,
}

fn read_only_database(path: &Path) -> TestResult<rusqlite::Connection> {
    let database =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    database.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    Ok(database)
}

fn original_process_calls(path: &Path) -> TestResult<i64> {
    let database = read_only_database(&path.join("process.db"))?;
    Ok(database.query_row(
        "SELECT tree_calls FROM processes WHERE id='root'",
        [],
        |row| row.get(0),
    )?)
}

fn effect_counts(path: &Path) -> TestResult<(i64, i64)> {
    let semantic = read_only_database(&path.join("semantic-effects.db"))?;
    let ordinary = read_only_database(&path.join("effects.db"))?;
    Ok((
        semantic.query_row("SELECT count(*) FROM semantic_submissions", [], |row| {
            row.get(0)
        })?,
        ordinary.query_row("SELECT count(*) FROM effects", [], |row| row.get(0))?,
    ))
}

fn read_original_capture(path: &Path) -> TestResult<OriginalOrdinaryCapture> {
    let database = read_only_database(&path.join("admission.db"))?;
    let schema: i64 = database.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        schema, 40,
        "this is the real ordinary predecessor schema, not old35"
    );
    let operation_bytes: Vec<u8> = database.query_row(
        "SELECT operation_json FROM admission_operations WHERE operation_id=?1",
        [ORIGINAL_OPERATION],
        |row| row.get(0),
    )?;
    let operation =
        AdmissionOperationV1::from_persisted(serde_json::from_slice(&operation_bytes)?)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&operation.to_persisted())?,
        operation_bytes
    );
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    assert_eq!(operation.version(), 7);
    assert_eq!(
        operation.binding().operation_id().as_str(),
        ORIGINAL_OPERATION
    );
    assert_eq!(
        operation.binding().request_id().as_str(),
        "process:4b204d925f76d2ed675cb29af389911749cfd4a0670da15bafe84a4babac83f5"
    );
    assert_eq!(
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(
            &operation.binding().to_persisted()
        )?),
        "982fc8fb4c03adf01b5cf2e80c3162a74fd9d4babebc272775d3defc7ce3e863"
    );
    assert!(operation.dispatch_commit().is_some());
    let retained: Vec<u8> = database.query_row(
        "SELECT request_json FROM admission_operation_tool_requests WHERE operation_id=?1",
        [ORIGINAL_OPERATION],
        |row| row.get(0),
    )?;
    assert_eq!(retained.len(), 5538);
    assert_eq!(
        chio_core::sha256_hex(&retained),
        "8b4db3be4a45ea457e1aa471219162e34260071d9dc3831e75dd20d8b39a6ae3"
    );
    let raw: Vec<u8> = database.query_row(
        "SELECT canonical_bytes FROM tool_outcome_blobs WHERE digest=?1",
        [ORIGINAL_RAW],
        |row| row.get(0),
    )?;
    assert_eq!(raw.len(), 6842);
    assert_eq!(chio_core::sha256_hex(&raw), ORIGINAL_RAW);
    let parsed = RawInvocationOutcomeV1::from_canonical_bytes(&raw)?;
    assert_eq!(parsed.canonical_blob()?.bytes(), raw.as_slice());
    let identity = serde_json::to_value(parsed.to_persisted())?;
    assert_eq!(
        identity["receipt_signing_identity"],
        serde_json::json!({
            "public_key": ORIGINAL_SIGNER,
            "crypto_floor": "allow_classical",
        })
    );
    let ledger: Vec<u8> = database.query_row(
        "SELECT canonical_record FROM admission_operation_native_dispatch_ledger WHERE operation_id=?1",
        [ORIGINAL_OPERATION], |row| row.get(0),
    )?;
    assert_eq!(ledger.len(), 7332);
    assert_eq!(
        chio_core::sha256_hex(&ledger),
        "3c5478c71a97b5b02b1a8a33a67a402c6fb7672afdd6bfb9ecb4a107fc39e429"
    );
    let ledger_body: Value = serde_json::from_slice(&ledger)?;
    assert_eq!(chio_core::canonical_json_bytes(&ledger_body)?, ledger);
    let policy = chio_core::canonical_json_bytes(&ledger_body["policy"])?;
    assert_eq!(policy.len(), 4281);
    assert_eq!(
        chio_core::sha256_hex(&policy),
        "84f7d1940f052d260325c8f75359d7615dc2cc256f3fcd479909a66249def206"
    );
    let workflows: i64 = database.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        workflows, 0,
        "ordinary captured ownership cannot borrow a recovery workflow"
    );
    let releases: i64 = database.query_row(
        "SELECT count(*) FROM tool_outcome_security_releases",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        releases, 0,
        "consumer entry must be the genuine unresolved release cut"
    );
    let installation: Vec<u8> = database.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key LIKE 'semantic-deployment:%'",
        [], |row| row.get(0),
    )?;
    let mut statement = database.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let protected_records = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(protected_records.len(), 12);
    assert_eq!(original_process_calls(path)?, 1);
    assert_eq!(effect_counts(path)?, (1, 0));
    Ok(OriginalOrdinaryCapture {
        operation,
        retained,
        raw,
        ledger,
        installation,
        protected_records,
    })
}

fn assert_original_physical_custody(path: &Path, original: &OriginalOrdinaryCapture) -> TestResult {
    let database = read_only_database(&path.join("admission.db"))?;
    for (key, version, payload) in &original.protected_records {
        let stored: (i64, Vec<u8>) = database.query_row(
            "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            stored.0, *version,
            "original retained record version changed: {key}"
        );
        assert_eq!(
            &stored.1, payload,
            "original retained record payload changed: {key}"
        );
    }
    assert_eq!(
        database.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    assert_eq!(original_process_calls(path)?, 1);
    assert_eq!(effect_counts(path)?, (1, 0));
    Ok(())
}

#[derive(PartialEq, Eq, Debug)]
struct CompletedOrdinaryCustody {
    operation: Vec<u8>,
    outcome: Vec<u8>,
    evaluation: Vec<u8>,
    release: Vec<u8>,
    receipt: Vec<u8>,
}

fn completed_ordinary_custody(
    fixture: &RecoveryFixture,
    original: &OriginalOrdinaryCapture,
    request: &ToolCallRequest,
    scope: &RecoveryScopeV1,
) -> TestResult<CompletedOrdinaryCustody> {
    let store = fixture.authority.admission_operation_store();
    let outcomes = fixture.authority.tool_outcome_store();
    let operation_id = original.operation.binding().operation_id();
    let operation = store
        .load_by_operation_id(operation_id)?
        .ok_or("original ordinary native operation absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::Completed,
        "known captured ordinary return must privately finalize"
    );
    assert_eq!(operation.version(), 8);
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
        .load_retained_tool_request(operation_id, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("ordinary original retained request absent")?;
    retained.validate_request_material(request)?;
    retained.validate_binding(operation.binding())?;
    assert_eq!(retained.canonical_bytes(), original.retained.as_slice());
    let ledger = store
        .load_native_dispatch_ledger(operation_id, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("ordinary original dispatch ledger absent")?;
    assert_eq!(ledger.canonical_record, original.ledger);
    assert_eq!(
        Some(&ledger.record_digest),
        operation.native_dispatch_ledger_digest()
    );
    assert_eq!(
        ledger.record_digest.as_str(),
        chio_core::sha256_hex(&ledger.canonical_record)
    );
    let capture = store
        .load_native_dispatch_capture(operation_id, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("ordinary original physical native budget capture absent")?;
    assert_eq!(capture.operation, operation);
    assert!(matches!(
        capture.decision,
        chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(_)
    ));
    assert_eq!(
        chio_core::canonical_json_bytes(&store.read_semantic_installation(
            scope,
            &fixture.authority.mutation_fence(),
            now_ms()?
        )?)?,
        original.installation
    );
    let outcome = outcomes
        .lookup_by_operation(operation_id)?
        .ok_or("original ordinary completed outcome absent")?;
    let raw = outcomes
        .load_raw_invocation_by_operation(operation_id)?
        .ok_or("original ordinary raw custody absent")?;
    let blob = raw.canonical_blob()?;
    outcome.validate_canonical_blob(&operation, &blob)?;
    assert_eq!(blob.bytes(), original.raw.as_slice());
    assert!(matches!(
        outcome.disposition(),
        ResolvedToolOutcomeV1::Resolved { .. }
    ));
    let evaluation = outcomes
        .lookup_post_return_evaluation(operation_id)?
        .ok_or("original ordinary evaluation absent")?;
    evaluation.validate_against(&operation, &outcome)?;
    assert!(matches!(
        evaluation.state(),
        PostReturnEvaluationStateV1::Resolved { .. }
    ));
    let release = outcomes
        .lookup_security_release(operation_id)?
        .ok_or("original ordinary security release absent")?;
    release.validate_against(&operation, &raw, &outcome, &evaluation)?;
    assert_eq!(
        release.store_fence().store_uuid,
        fixture.authority.mutation_fence().store_uuid
    );
    assert!(release.store_fence().owner_epoch <= fixture.authority.mutation_fence().owner_epoch);
    let receipt_id = match operation.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("original ordinary terminal receipt absent".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("original ordinary signed receipt absent")?;
    assert_eq!(
        receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert_eq!(
        receipt.kernel_key,
        chio_core::PublicKey::from_hex(ORIGINAL_SIGNER)?
    );
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical
    )?);
    assert!(matches!(
        receipt.decision,
        Some(chio_core_types::receipt::decision::Decision::Allow)
    ));
    assert_original_physical_custody(&fixture.path, original)?;
    Ok(CompletedOrdinaryCustody {
        operation: chio_core::canonical_json_bytes(&operation.to_persisted())?,
        outcome: chio_core::canonical_json_bytes(&outcome.to_persisted())?,
        evaluation: chio_core::canonical_json_bytes(&evaluation.to_persisted())?,
        release: release.canonical_bytes()?,
        receipt: chio_core::canonical_json_bytes(&receipt)?,
    })
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires the sealed genuine predecessor ordinary return-recorded root"]
async fn ordinary_predecessor_recorded_return_retains_custody_and_reopens_its_release_owner(
) -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_ORDINARY_CAPTURE_ROOT")
            .ok_or("reviewed genuine ordinary predecessor capture root absent")?,
    );
    assert_eq!(
        std::fs::read_to_string(path.join("semantic-kind"))?,
        "read-weak-manifest"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("public-original-profile"))?,
        "selected"
    );
    assert!(!path.join("legacy-near-capacity").exists());
    assert!(!path.join("current-recovery-receipt-signer").exists());
    assert!(!path.join("original-recovery-receipt-signer").exists());
    let request_bytes = std::fs::read(path.join("known-semantic-recorded-return-request.json"))?;
    assert_eq!(request_bytes.len(), 4238);
    assert_eq!(
        chio_core::sha256_hex(&request_bytes),
        "9eb45ade77e4b0dba157ab85742119357f1cb4cd0a91b041c1a70e14abba9143"
    );
    let request: ToolCallRequest = serde_json::from_slice(&request_bytes)?;
    let invocation: SemanticInvocationV1 = serde_json::from_value(request.arguments.clone())?;
    let scope = invocation.action.scope.clone();
    let original = read_original_capture(&path)?;
    let original_id = AdmissionOperationId::from_persisted(ORIGINAL_OPERATION)?;
    assert_eq!(original.operation.binding().operation_id(), &original_id);
    let current_process_path = path.join("ordinary-current-process.db");
    assert!(
        !current_process_path.exists(),
        "current journal must be genuinely fresh"
    );

    // The unchanged bootstrap runs the actual native release recovery under
    // a new ServingOwner. It receives no reconstructed workflow or permit.
    let fixture = RecoveryFixture::open(path.clone(), None, false)?;
    let first_fence = fixture.authority.mutation_fence();
    let frozen = completed_ordinary_custody(&fixture, &original, &request, &scope)?;
    let release = fixture
        .authority
        .tool_outcome_store()
        .lookup_security_release(&original_id)?
        .ok_or("ordinary first current release absent")?;
    assert_eq!(
        release.store_fence(),
        &first_fence,
        "the first private release must be owned by this current serving fence"
    );
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            completed_ordinary_custody(&fixture, &original, &request, &scope)?,
            frozen
        );
    }

    // Captured private finality does not renew the original public capability.
    // The sealed predecessor token has expired before this continuation.
    assert!(now_ms()? / 1000 >= request.capability.expires_at);
    let runtime = NativeSemanticRuntime::new(
        fixture.kernel.clone(),
        Arc::new(fixture.authority.admission_operation_store()),
        scope.clone(),
        fixture.authority.mutation_fence(),
    );
    let delivery = runtime
        .execute_step(
            &fixture.process,
            "root",
            "stopped-recorded-semantic-return",
            &request,
        )
        .await;
    if let Ok(response) = delivery {
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
    }
    assert_eq!(
        completed_ordinary_custody(&fixture, &original, &request, &scope)?,
        frozen
    );
    drop(runtime);

    // A current token uses a real new Process session and persisted lineage.
    // Its current pre-dispatch refusal cannot alter the original captured fate.
    let capability = fixture.kernel.issue_capability(
        &fixture.seed.capability.subject,
        fixture.seed.capability.scope.clone(),
        600,
    )?;
    assert_eq!(capability.issuer, fixture.kernel.public_key());
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
    let current_request = current_process.tool_request(
        "current-root",
        "guarded-current-denial",
        "server-a",
        "send",
        fixture.seed.arguments.clone(),
    )?;
    let response = Box::pin(current_process.invoke_known_only(
        "current-root",
        "guarded-current-denial",
        &current_request,
    ))
    .await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical
    )?);
    assert_eq!(
        response.receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    let store = fixture.authority.admission_operation_store();
    let (current_operation, current_retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &current_request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine current native compensated refusal absent")?;
    current_retained.validate_request_material(&current_request)?;
    current_retained.validate_native_security_context(
        &fixture.kernel.refresh_native_security_context(&context)?,
    )?;
    assert_ne!(current_operation.binding().operation_id(), &original_id);
    assert_eq!(
        current_operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(current_operation.dispatch_commit().is_none());
    assert_eq!(current_process.process("current-root")?.tree_calls, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 1);
    assert_eq!(
        original_process_calls(&path)?
            + i64::from(current_process.process("current-root")?.tree_calls),
        2
    );
    assert_eq!(
        completed_ordinary_custody(&fixture, &original, &request, &scope)?,
        frozen
    );
    for _ in 0..2 {
        fixture.kernel.reconcile_durable_admission_startup()?;
        fixture.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            completed_ordinary_custody(&fixture, &original, &request, &scope)?,
            frozen
        );
    }
    drop(store);
    drop(current_process);
    drop(fixture);

    // Every handle holding the first serving lease is gone. This is a second
    // actual serving open of the same original ordinary capture.
    let reopened = RecoveryFixture::open(path.clone(), None, false)?;
    assert_eq!(
        reopened.authority.mutation_fence().store_uuid,
        first_fence.store_uuid
    );
    assert!(reopened.authority.mutation_fence().owner_epoch > first_fence.owner_epoch);
    for _ in 0..2 {
        reopened.kernel.reconcile_durable_admission_startup()?;
        reopened.kernel.reconcile_recoverable_admissions()?;
        assert_eq!(
            completed_ordinary_custody(&reopened, &original, &request, &scope)?,
            frozen
        );
    }
    let current_journal = read_only_database(&current_process_path)?;
    assert_eq!(
        current_journal.query_row(
            "SELECT tree_calls FROM processes WHERE id='current-root'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(reopened.process.process("root")?.tree_calls, 1);
    assert_eq!(
        std::fs::read(path.join("known-semantic-recorded-return-request.json"))?,
        request_bytes
    );
    Ok(())
}
