//! Protected recovery writers treat a missing live projection with retained
//! events or global commit references as corruption, never as a fresh key.
//! Damage exists only inside a rolled-back savepoint of the real writer
//! transaction; committed custody is never rewritten. The planning fixture
//! holds a real workflow family: an immutable origin claim, cancelled
//! effect-free predecessors with committed retirements, and the owner head and
//! successor bindings exactly as the production transfer writer retains them.
use super::*;
use crate::admission_operation_store::recovery::origins;
use crate::admission_operation_store::recovery::storage::{
    encode, save, save_workflow, scope_key, successor_binding, WorkflowWriteClass,
};
use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_kernel::recovery::RecoveryWorkflowRecordV1;
use chio_kernel::ToolCallRequest;
use chio_security_types::recovery::{
    AuthorityDomainId, ContinuationId, DeploymentDigest, EffectObservationV1, EvidenceRef,
    NativeAdmissionDigest, OperationId, OperationRef, ProcessId, ProtectedText, RecoveryOriginV1,
    RecoveryScopeV1, RecoveryTenantId, ReleaseDispositionV1, RequestId, SafeInteger, StepId,
    WorkflowControlV1, WorkflowId,
};
use serde::Serialize;

/// Every custody table the writers may touch, in a stable order.
type Custody = Vec<Vec<Vec<Value>>>;

#[derive(Clone, Copy)]
enum Damage {
    /// The live row is gone; its events and global commit references remain.
    LiveProjection,
    /// The live row and its events are gone; only global references remain.
    LiveProjectionAndEvents,
}

fn table_rows(connection: &Connection, sql: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    let mut statement = connection.prepare(sql)?;
    let columns = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn custody(connection: &Connection) -> AnchoredTestResult<Custody> {
    Ok(vec![
        table_rows(
            connection,
            "SELECT * FROM admission_operation_recovery_records ORDER BY record_key",
        )?,
        table_rows(
            connection,
            "SELECT * FROM admission_operation_recovery_events ORDER BY sequence",
        )?,
        table_rows(
            connection,
            "SELECT * FROM authority_global_commits ORDER BY commit_sequence",
        )?,
    ])
}

fn scope(fixture: &Fixture) -> AnchoredTestResult<RecoveryScopeV1> {
    Ok(RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new(&fixture.fence.store_uuid)?,
        tenant_id: RecoveryTenantId::new("retained-absence-tenant")?,
        process_id: ProcessId::new("retained-absence-process")?,
    })
}

fn origin() -> AnchoredTestResult<RecoveryOriginV1> {
    Ok(RecoveryOriginV1 {
        operation: OperationRef::new(
            OperationId::new("retained-absence-operation")?,
            NativeAdmissionDigest::from_bytes([5; 32]),
            SafeInteger::new(1)?,
        )?,
        request_id: RequestId::new("retained-absence-request")?,
        closure: EvidenceRef::new("retained-absence-closure")?,
    })
}

/// The retained-custody seed contract of the planning fixture. Only retained
/// canonical recovery verifiers consume it; it acquires no native admission
/// or public command acceptance authority.
fn seed() -> AnchoredTestResult<ToolCallRequest> {
    let signer = Keypair::from_seed(&[41; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "retained-absence-capability".to_owned(),
            issuer: signer.public_key(),
            subject: signer.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: 100,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &signer,
    )?;
    Ok(serde_json::from_value(serde_json::json!({
        "request_id": "retained-absence-original",
        "capability": capability,
        "tool_name": "retained-absence-tool",
        "server_id": "retained-absence-server",
        "agent_id": signer.public_key().to_hex(),
        "arguments": {}
    }))?)
}

/// A pristine creation generation in the exact shape the production command
/// writer retains: no action, reservation, admission, capture or effect.
fn new_record(
    scope: &RecoveryScopeV1,
    origin: &RecoveryOriginV1,
    principal: &chio_security_types::PrincipalId,
    seed: &ToolCallRequest,
    creation_seed: &ProtectedText<32768>,
    workflow: &WorkflowId,
    continuation: &ContinuationId,
) -> AnchoredTestResult<RecoveryWorkflowRecordV1> {
    let suffix = sha256_hex(&encode(&(scope, workflow))?);
    Ok(RecoveryWorkflowRecordV1 {
        scope: scope.clone(),
        origin: Some(origin.clone()),
        workflow_id: workflow.clone(),
        step_id: StepId::new(&format!("step:{suffix}"))?,
        continuation_id: continuation.clone(),
        revision: SafeInteger::new(1)?,
        control: WorkflowControlV1::Active,
        seed: seed.clone(),
        creation_seed: creation_seed.clone(),
        deployment_digest: DeploymentDigest::from_bytes([7; 32]),
        created_by: principal.clone(),
        effect_cardinality: SafeInteger::new(1)?,
        action: None,
        process_reservation: None,
        selected: false,
        review: None,
        approval: None,
        issuance: None,
        signed_grant: None,
        envelope: None,
        admission: None,
        admission_closed: false,
        native_link: None,
        captured: false,
        captured_deployment: None,
        historical_hold: None,
        effect: EffectObservationV1::NeverAdmitted,
        release: ReleaseDispositionV1::NotAvailable,
        original_flow: None,
        reported_decision: None,
        provider_finality: None,
        provider_lookups: SafeInteger::ZERO,
    })
}

/// The canonical retained successor-binding image of one owner transfer,
/// encoded by this fixture exactly as the production writer retains it.
#[derive(Serialize)]
struct RetainedSuccessorBinding {
    schema: &'static str,
    scope: RecoveryScopeV1,
    origin: RecoveryOriginV1,
    principal: chio_security_types::PrincipalId,
    predecessor_workflow_id: WorkflowId,
    predecessor_continuation_id: ContinuationId,
    predecessor_generation: SafeInteger,
    successor_workflow_id: WorkflowId,
    successor_continuation_id: ContinuationId,
    successor_generation: SafeInteger,
}

fn binding_record(
    scope: &RecoveryScopeV1,
    origin: &RecoveryOriginV1,
    principal: &chio_security_types::PrincipalId,
    predecessor: (&WorkflowId, &ContinuationId, u64),
    successor: (&WorkflowId, &ContinuationId, u64),
) -> AnchoredTestResult<(String, Vec<u8>)> {
    let binding = RetainedSuccessorBinding {
        schema: "chio.recovery.successor-binding.v1",
        scope: scope.clone(),
        origin: origin.clone(),
        principal: principal.clone(),
        predecessor_workflow_id: predecessor.0.clone(),
        predecessor_continuation_id: predecessor.1.clone(),
        predecessor_generation: SafeInteger::new(predecessor.2)?,
        successor_workflow_id: successor.0.clone(),
        successor_continuation_id: successor.1.clone(),
        successor_generation: SafeInteger::new(successor.2)?,
    };
    Ok((
        format!(
            "recovery-successor:{}:{}",
            scope_key(scope)?,
            successor.0.as_str()
        ),
        encode(&binding)?,
    ))
}

/// Commit one protected write through the production writer and real owner.
fn commit_save(
    fixture: &Fixture,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    save(
        &tx,
        &fixture.store.serving_owner,
        key,
        scope,
        "command",
        payload,
        None,
    )?;
    fixture.store.commit_write(tx)?;
    fixture.store.sync_after_write(&connection)
}

/// Commit one multi-write planning transaction through the production
/// writers and the real owner, exactly as the store's own flows do.
fn commit_planning(
    fixture: &Fixture,
    apply: impl FnOnce(&rusqlite::Transaction<'_>) -> AnchoredTestResult,
) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    apply(&tx)?;
    crate::serving_owner::verify_authenticated_recovery_history(&tx)?;
    fixture.store.commit_write(tx)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

fn committed_version(fixture: &Fixture, key: &str) -> AnchoredTestResult<(i64, i64, i64)> {
    let connection = fixture.store.connection()?;
    Ok(connection.query_row(
        "SELECT
            (SELECT version FROM admission_operation_recovery_records WHERE record_key=?1),
            (SELECT count(*) FROM admission_operation_recovery_events WHERE record_key=?1),
            (SELECT count(*) FROM authority_global_commits
              WHERE projection_kind='recovery' AND projection_key=?1)",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

/// Run the same production writer against a deliberately lost live projection.
/// The writer must refuse without touching any record, event or global commit,
/// and rolling the savepoint back must restore the exact authentic custody.
fn assert_lost_projection_refused(
    fixture: &Fixture,
    key: &str,
    scope: &str,
    payload: &[u8],
    damage: Damage,
) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let authentic = custody(&tx)?;
    tx.execute_batch(
        "SAVEPOINT lost_projection_probe;
         PRAGMA defer_foreign_keys = ON;
         DROP TRIGGER admission_operation_recovery_no_delete;",
    )?;
    tx.execute(
        "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
        [key],
    )?;
    if matches!(damage, Damage::LiveProjectionAndEvents) {
        tx.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_delete")?;
        tx.execute(
            "DELETE FROM admission_operation_recovery_events WHERE record_key=?1",
            [key],
        )?;
    }
    let damaged = custody(&tx)?;
    assert_ne!(damaged, authentic, "the probe must remove retained custody");
    let result = save(
        &tx,
        &fixture.store.serving_owner,
        key,
        scope,
        "command",
        payload,
        None,
    );
    assert!(
        matches!(
            &result,
            Err(AdmissionOperationStoreError::Invariant(detail))
                if detail.contains("disappeared with retained history")
        ),
        "a lost live projection was not refused as retained history: {result:?}"
    );
    assert_eq!(
        custody(&tx)?,
        damaged,
        "the refused writer changed records, events or global commits"
    );
    tx.execute_batch("ROLLBACK TO lost_projection_probe; RELEASE lost_projection_probe")?;
    assert_eq!(
        custody(&tx)?,
        authentic,
        "the probe did not restore the authentic custody"
    );
    tx.rollback()?;
    Ok(())
}

#[test]
fn generic_writer_creates_updates_and_refuses_a_lost_live_projection() -> AnchoredTestResult {
    let fixture = fixture();
    let scope = scope_key(&scope(&fixture)?)?;
    let key = format!("knowledge-pin:{scope}:retained-absence");
    let unrelated = format!("knowledge-pin:{scope}:retained-absence-unrelated");
    let payload =
        |value: u64| -> AnchoredTestResult<Vec<u8>> { Ok(encode(&SafeInteger::new(value)?)?) };

    commit_save(&fixture, &key, &scope, &payload(1)?)?;
    assert_eq!(committed_version(&fixture, &key)?, (1, 1, 1));
    // Unrelated retained history never blocks a pristine key.
    commit_save(&fixture, &unrelated, &scope, &payload(1)?)?;
    assert_eq!(committed_version(&fixture, &unrelated)?, (1, 1, 1));
    commit_save(&fixture, &key, &scope, &payload(2)?)?;
    assert_eq!(committed_version(&fixture, &key)?, (2, 2, 2));

    for damage in [Damage::LiveProjection, Damage::LiveProjectionAndEvents] {
        assert_lost_projection_refused(&fixture, &key, &scope, &payload(3)?, damage)?;
        assert_eq!(committed_version(&fixture, &key)?, (2, 2, 2));
    }
    assert_eq!(committed_version(&fixture, &unrelated)?, (1, 1, 1));
    // The refused probes left the store serving ordinary updates.
    commit_save(&fixture, &key, &scope, &payload(3)?)?;
    assert_eq!(committed_version(&fixture, &key)?, (3, 3, 3));
    Ok(())
}

#[test]
fn planning_writer_creates_updates_and_refuses_lost_claim_and_owner_head() -> AnchoredTestResult {
    let fixture = fixture();
    let scope = scope(&fixture)?;
    let scope_hash = scope_key(&scope)?;
    let origin = origin()?;
    let principal = chio_security_types::PrincipalId::new("retained-absence-principal")?;
    let seed = seed()?;
    let creation_seed = ProtectedText::new(std::str::from_utf8(&encode(&seed)?)?)?;
    let generation = |index: u64| -> AnchoredTestResult<(WorkflowId, ContinuationId)> {
        Ok((
            WorkflowId::new(&format!("retained-absence-workflow-{index}"))?,
            ContinuationId::new(&format!("retained-absence-continuation-{index}"))?,
        ))
    };
    let (first_workflow, first_continuation) = generation(1)?;
    let (second_workflow, second_continuation) = generation(2)?;
    let (third_workflow, third_continuation) = generation(3)?;
    let (fourth_workflow, fourth_continuation) = generation(4)?;
    let (claim_key, claim) =
        origins::claim_record_for_test(&scope, &first_workflow, &first_continuation, &origin)?;
    let head = |owner: &WorkflowId, continuation: &ContinuationId, generation: u64| {
        successor_binding::owner_head_record_for_test(
            &scope,
            &origin,
            &principal,
            owner,
            continuation,
            generation,
        )
    };
    let record = |workflow: &WorkflowId, continuation: &ContinuationId| {
        new_record(
            &scope,
            &origin,
            &principal,
            &seed,
            &creation_seed,
            workflow,
            continuation,
        )
    };
    let (head_key, _) = head(&first_workflow, &first_continuation, 1)?;
    let owner = &fixture.store.serving_owner;

    // Pristine planning creation: the immutable claim and its first workflow
    // generation land in one production transaction.
    commit_planning(&fixture, |tx| {
        save(tx, owner, &claim_key, &scope_hash, "command", &claim, None)?;
        let mut first = record(&first_workflow, &first_continuation)?;
        save_workflow(tx, owner, &mut first, WorkflowWriteClass::Planning)?;
        Ok(())
    })?;
    assert_eq!(committed_version(&fixture, &claim_key)?, (1, 1, 1));

    // The closed first generation spends its one control purpose and commits
    // its live-allocation retirement, the effect-free closure a genuine
    // transfer requires of its predecessor.
    commit_planning(&fixture, |tx| {
        let mut closed = record(&first_workflow, &first_continuation)?;
        closed.control = WorkflowControlV1::Cancelled;
        closed.admission_closed = true;
        save_workflow(tx, owner, &mut closed, WorkflowWriteClass::Control)?;
        Ok(())
    })?;

    // The first genuine transfer opens the head with the closed first
    // generation, retains the immutable successor binding and advances the
    // head to the second generation in the same transaction.
    commit_planning(&fixture, |tx| {
        let (_, opening) = head(&first_workflow, &first_continuation, 1)?;
        let (binding_key, binding) = binding_record(
            &scope,
            &origin,
            &principal,
            (&first_workflow, &first_continuation, 1),
            (&second_workflow, &second_continuation, 2),
        )?;
        let (_, advanced) = head(&second_workflow, &second_continuation, 2)?;
        save(tx, owner, &head_key, &scope_hash, "command", &opening, None)?;
        save(
            tx,
            owner,
            &binding_key,
            &scope_hash,
            "command",
            &binding,
            None,
        )?;
        save(
            tx,
            owner,
            &head_key,
            &scope_hash,
            "command",
            &advanced,
            None,
        )?;
        let mut second = record(&second_workflow, &second_continuation)?;
        save_workflow(tx, owner, &mut second, WorkflowWriteClass::Planning)?;
        Ok(())
    })?;
    assert_eq!(committed_version(&fixture, &head_key)?, (2, 2, 2));

    // Legitimate head update: one further closed generation transfers to the
    // third generation, advancing the retained head in one transaction.
    commit_planning(&fixture, |tx| {
        let mut closed = record(&second_workflow, &second_continuation)?;
        closed.control = WorkflowControlV1::Cancelled;
        closed.admission_closed = true;
        save_workflow(tx, owner, &mut closed, WorkflowWriteClass::Control)?;
        Ok(())
    })?;
    commit_planning(&fixture, |tx| {
        let (binding_key, binding) = binding_record(
            &scope,
            &origin,
            &principal,
            (&second_workflow, &second_continuation, 2),
            (&third_workflow, &third_continuation, 3),
        )?;
        let (_, advanced) = head(&third_workflow, &third_continuation, 3)?;
        save(
            tx,
            owner,
            &binding_key,
            &scope_hash,
            "command",
            &binding,
            None,
        )?;
        save(
            tx,
            owner,
            &head_key,
            &scope_hash,
            "command",
            &advanced,
            None,
        )?;
        let mut third = record(&third_workflow, &third_continuation)?;
        save_workflow(tx, owner, &mut third, WorkflowWriteClass::Planning)?;
        Ok(())
    })?;
    assert_eq!(committed_version(&fixture, &head_key)?, (3, 3, 3));

    // The refused attempts carry the exact payload of the next legitimate
    // head advancement, and the immutable claim's own replay bytes.
    let (_, fourth_head) = head(&fourth_workflow, &fourth_continuation, 4)?;
    for damage in [Damage::LiveProjection, Damage::LiveProjectionAndEvents] {
        assert_lost_projection_refused(&fixture, &head_key, &scope_hash, &fourth_head, damage)?;
        assert_lost_projection_refused(&fixture, &claim_key, &scope_hash, &claim, damage)?;
    }
    assert_eq!(committed_version(&fixture, &head_key)?, (3, 3, 3));
    assert_eq!(committed_version(&fixture, &claim_key)?, (1, 1, 1));

    // The refused probes left the planning allocation serving the next
    // legitimate owner transition.
    commit_planning(&fixture, |tx| {
        let mut closed = record(&third_workflow, &third_continuation)?;
        closed.control = WorkflowControlV1::Cancelled;
        closed.admission_closed = true;
        save_workflow(tx, owner, &mut closed, WorkflowWriteClass::Control)?;
        Ok(())
    })?;
    commit_planning(&fixture, |tx| {
        let (binding_key, binding) = binding_record(
            &scope,
            &origin,
            &principal,
            (&third_workflow, &third_continuation, 3),
            (&fourth_workflow, &fourth_continuation, 4),
        )?;
        let (_, advanced) = head(&fourth_workflow, &fourth_continuation, 4)?;
        save(
            tx,
            owner,
            &binding_key,
            &scope_hash,
            "command",
            &binding,
            None,
        )?;
        save(
            tx,
            owner,
            &head_key,
            &scope_hash,
            "command",
            &advanced,
            None,
        )?;
        let mut fourth = record(&fourth_workflow, &fourth_continuation)?;
        save_workflow(tx, owner, &mut fourth, WorkflowWriteClass::Planning)?;
        Ok(())
    })?;
    assert_eq!(committed_version(&fixture, &head_key)?, (4, 4, 4));
    assert_eq!(committed_version(&fixture, &claim_key)?, (1, 1, 1));
    Ok(())
}
