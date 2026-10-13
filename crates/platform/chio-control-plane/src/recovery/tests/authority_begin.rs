//! Native begin conflicts retain every protected recovery allocation.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionOperationBindingV1, AdmissionOperationV1,
};
use rusqlite::{Connection, OpenFlags};

#[derive(Eq, PartialEq)]
struct ProtectedNativeBeginSnapshot {
    recovery_rows: Vec<u8>,
    recovery_events: i64,
    global_commits: i64,
    global_head: String,
    existing_operation: Option<Vec<u8>>,
}

#[derive(Eq, PartialEq)]
struct NativeBeginSnapshot {
    protected: ProtectedNativeBeginSnapshot,
    charges: u32,
    effects: usize,
}

fn protected_snapshot(
    fixture: &RecoveryFixture,
    existing: Option<&AdmissionOperationV1>,
) -> TestResult<ProtectedNativeBeginSnapshot> {
    let database = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = database.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    type Row = (
        String,
        String,
        String,
        i64,
        Vec<u8>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    let recovery_rows = chio_core::canonical_json_bytes(&rows)?;
    let (recovery_events, global_commits): (i64, i64) = database.query_row(
        "SELECT
         (SELECT count(*) FROM admission_operation_recovery_events),
         (SELECT count(*) FROM authority_global_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let global_head: String = database.query_row(
        "SELECT chain_digest FROM authority_global_commits ORDER BY commit_sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let existing_operation = existing
        .map(|operation| {
            database.query_row(
                "SELECT operation_json FROM admission_operations WHERE operation_id=?1",
                [operation.binding().operation_id().as_str()],
                |row| row.get(0),
            )
        })
        .transpose()?;
    Ok(ProtectedNativeBeginSnapshot {
        recovery_rows,
        recovery_events,
        global_commits,
        global_head,
        existing_operation,
    })
}

fn snapshot(
    fixture: &RecoveryFixture,
    existing: Option<&AdmissionOperationV1>,
) -> TestResult<NativeBeginSnapshot> {
    Ok(NativeBeginSnapshot {
        protected: protected_snapshot(fixture, existing)?,
        charges: fixture.process.process("root")?.tree_calls,
        effects: external_count(&fixture.path)?,
    })
}

fn assert_protected_unchanged(
    before: &ProtectedNativeBeginSnapshot,
    after: &ProtectedNativeBeginSnapshot,
) {
    assert!(
        before == after,
        "native conflict changed protected rows/events/custody: rows {} -> {}; recovery events {} -> {}; global commits {} -> {}",
        chio_core::sha256_hex(&before.recovery_rows),
        chio_core::sha256_hex(&after.recovery_rows),
        before.recovery_events, after.recovery_events,
        before.global_commits, after.global_commits,
    );
}

fn assert_unchanged(before: &NativeBeginSnapshot, after: &NativeBeginSnapshot) {
    assert_protected_unchanged(&before.protected, &after.protected);
    assert!(
        before == after,
        "native conflict changed charges/effects: charges {} -> {}; effects {} -> {}",
        before.charges,
        after.charges,
        before.effects,
        after.effects,
    );
}

fn finalized_operation(
    fixture: &RecoveryFixture,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<AdmissionOperationV1> {
    let binding = AdmissionOperationBindingV1::from_persisted(
        record
            .admission
            .as_ref()
            .ok_or("native recovery intent")?
            .native_binding
            .clone(),
    )?;
    Ok(AdmissionOperationV1::prepare(
        binding,
        fixture.authority.mutation_fence().owner_epoch,
    )?)
}

#[tokio::test]
async fn recovery_native_begin_conflict_preserves_workflow_and_allowances() -> TestResult {
    let fixture = RecoveryFixture::new(false)
        .map_err(|error| format!("native conflict phase=fixture open: {error}"))?;
    let scope = fixture.runtime.scope();
    let creation_key = CreationKey::new("ticket-1")?;
    let expected_workflow = WorkflowId::new(&format!(
        "workflow:{}",
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&(scope, &creation_key))?),
    ))?;
    let continuation = ContinuationId::new(&format!(
        "continuation:{}",
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&(
            scope,
            &expected_workflow
        ))?),
    ))?;
    let expected_request = fixture.process.request_id(
        scope.process_id.as_str(),
        &format!("recovery:{}", continuation.as_str()),
    )?;
    let mut ordinary = fixture.seed.clone();
    ordinary.request_id = expected_request.clone();
    ordinary.arguments =
        serde_json::json!({"title":"ordinary prepared collision", "body":"never dispatched"});
    let context = fixture
        .process
        .recovery_security_context("root")
        .map_err(|error| format!("native conflict phase=process context: {error}"))?;
    let identity = fixture
        .kernel
        .recovery_native_identity(&ordinary, &context)
        .map_err(|error| format!("native conflict phase=ordinary native identity: {error}"))?;
    let fence = fixture.authority.mutation_fence();
    let existing = AdmissionOperationV1::prepare(identity.binding().clone(), fence.owner_epoch)?;
    let store = fixture.authority.admission_operation_store();
    assert!(matches!(
        store
            .begin(&existing, &fence, now_ms()?)
            .map_err(|error| format!("native conflict phase=ordinary prepared begin: {error}"))?,
        AdmissionBeginResult::Created(_)
    ));
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(
        fixture
            .process
            .process("root")
            .map_err(|error| format!("native conflict phase=ordinary charge read: {error}"))?
            .tree_calls,
        0
    );

    let workflow = fixture.ready().await.map_err(|error| {
        format!("native conflict phase=original denial and workflow approval: {error}")
    })?;
    assert_eq!(workflow, expected_workflow);
    let actor = fixture.kernel.authenticate_recovery_actor(
        scope,
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    fixture
        .runtime
        .prepare_original(&actor, &workflow)
        .map_err(|error| format!("native conflict phase=original finalization: {error}"))?;
    let record = fixture.record(&workflow)?;
    assert_eq!(record.seed.request_id, expected_request);
    assert!(record.native_link.is_none());
    assert!(!record.captured);
    let candidate = finalized_operation(&fixture, &record)?;
    assert_eq!(
        candidate.binding().request_namespace_digest(),
        existing.binding().request_namespace_digest()
    );
    assert_eq!(
        candidate.binding().request_id(),
        existing.binding().request_id()
    );
    assert_ne!(
        candidate.binding().operation_id(),
        existing.binding().operation_id()
    );
    assert_ne!(
        candidate.binding().request_binding_hash(),
        existing.binding().request_binding_hash()
    );
    let before = snapshot(&fixture, Some(&existing))
        .map_err(|error| format!("native conflict phase=before snapshot: {error}"))?;
    for _ in 0..2 {
        assert!(matches!(
            store.begin(&candidate, &fence, now_ms()?)
                .map_err(|error| format!("native conflict phase=owning candidate begin: {error}"))?,
            AdmissionBeginResult::Conflict { existing_operation_id }
                if existing_operation_id == *existing.binding().operation_id()
        ));
        // Verify the owning physical preservation condition before a public
        // process read can refuse a damaged authority anchor and mask it.
        assert_protected_unchanged(
            &before.protected,
            &protected_snapshot(&fixture, Some(&existing)).map_err(|error| {
                format!("native conflict phase=after Conflict physical snapshot: {error}")
            })?,
        );
        assert_unchanged(
            &before,
            &snapshot(&fixture, Some(&existing)).map_err(|error| {
                format!("native conflict phase=after Conflict public metrics: {error}")
            })?,
        );
        assert!(store
            .load_by_operation_id(candidate.binding().operation_id())?
            .is_none());
        assert_eq!(
            store.load_by_operation_id(existing.binding().operation_id())?,
            Some(existing.clone())
        );
        assert!(fixture.record(&workflow)?.native_link.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn recovery_native_begin_created_and_replay_attach_one_exact_link() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = fixture.ready().await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    fixture.runtime.prepare_original(&actor, &workflow)?;
    let before = fixture.record(&workflow)?;
    assert!(before.native_link.is_none());
    let candidate = finalized_operation(&fixture, &before)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    assert!(matches!(
        store.begin(&candidate, &fence, now_ms()?)?,
        AdmissionBeginResult::Created(_)
    ));
    let linked = fixture.record(&workflow)?;
    assert_eq!(
        linked.native_link.as_ref().map(OperationId::as_str),
        Some(candidate.binding().operation_id().as_str())
    );
    assert_eq!(linked.revision.get(), before.revision.get() + 1);
    assert!(!linked.captured);
    let snapshot_before = snapshot(&fixture, Some(&candidate))?;
    assert!(
        matches!(store.begin(&candidate, &fence, now_ms()?)?, AdmissionBeginResult::ExactReplay { operation, .. } if operation == candidate)
    );
    assert_unchanged(&snapshot_before, &snapshot(&fixture, Some(&candidate))?);
    Ok(())
}

fn native_units(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<i64> {
    let database = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?);
    Ok(database.query_row(
        "SELECT json_extract(payload,'$.native') FROM admission_operation_recovery_records
         WHERE record_key=?1",
        [format!("workflow-quota:{scope}:{}", workflow.as_str())],
        |row| row.get(0),
    )?)
}

#[tokio::test]
async fn recovery_native_begin_missing_link_replay_owns_one_anchored_debit() -> TestResult {
    // A typed initial writer models an omitted legacy publication. It creates
    // the actual native operation and its authenticated core begin history.
    let fixture = RecoveryFixture::new(false)?;
    let workflow = fixture.ready().await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    fixture.runtime.prepare_original(&actor, &workflow)?;
    let original = fixture.record(&workflow)?;
    assert!(original.native_link.is_none() && !original.captured);
    let candidate = finalized_operation(&fixture, &original)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let before = snapshot(&fixture, None)?;
    let initial_native_units = native_units(&fixture, &workflow)?;
    store.retain_recovery_begin_without_link_for_test(&candidate, &fence, now_ms()?)?;
    let missing_link = fixture.record(&workflow)?;
    let original_bytes = chio_core::canonical_json_bytes(&original)?;
    let missing_bytes = chio_core::canonical_json_bytes(&missing_link)?;
    assert!(
        missing_bytes == original_bytes,
        "modeled initial begin rewrote workflow: {} -> {}",
        chio_core::sha256_hex(&original_bytes),
        chio_core::sha256_hex(&missing_bytes),
    );
    let prepared = snapshot(&fixture, Some(&candidate))?;
    assert!(
        prepared.protected.recovery_rows == before.protected.recovery_rows,
        "modeled initial begin changed protected rows: {} -> {}",
        chio_core::sha256_hex(&before.protected.recovery_rows),
        chio_core::sha256_hex(&prepared.protected.recovery_rows),
    );
    assert_eq!(
        prepared.protected.recovery_events,
        before.protected.recovery_events
    );
    assert_eq!(prepared.charges, before.charges);
    assert_eq!(prepared.effects, before.effects);
    assert_eq!(native_units(&fixture, &workflow)?, initial_native_units);
    assert_eq!(
        store.load_by_operation_id(candidate.binding().operation_id())?,
        Some(candidate.clone())
    );

    assert!(matches!(
        store.begin(&candidate, &fence, now_ms()?)?,
        AdmissionBeginResult::ExactReplay { operation, .. } if operation == candidate
    ));
    let linked = fixture.record(&workflow)?;
    assert_eq!(
        linked.native_link.as_ref().map(OperationId::as_str),
        Some(candidate.binding().operation_id().as_str())
    );
    assert_eq!(linked.revision.get(), original.revision.get() + 1);
    assert!(!linked.captured);
    assert_eq!(native_units(&fixture, &workflow)?, initial_native_units + 1);
    // This public read authenticates the newly synchronized native anchor.
    assert_eq!(fixture.process.process("root")?.tree_calls, before.charges);
    assert_eq!(external_count(&fixture.path)?, 0);
    let published = snapshot(&fixture, Some(&candidate))?;
    assert!(matches!(
        store.begin(&candidate, &fence, now_ms()?)?,
        AdmissionBeginResult::ExactReplay { operation, .. } if operation == candidate
    ));
    assert_unchanged(&published, &snapshot(&fixture, Some(&candidate))?);
    assert_eq!(native_units(&fixture, &workflow)?, initial_native_units + 1);
    Ok(())
}
