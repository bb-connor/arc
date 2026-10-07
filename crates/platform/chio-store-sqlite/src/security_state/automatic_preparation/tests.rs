use super::*;
use chio_security_types::ports::{LeaseOwnerId, ResponseDispatchStore, SessionId};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseEffectKind, ResponseEffectSpec, ResponseExecutionBinding,
    ResponseExecutionMode, ResponsePlanInput, ResponseTarget,
};
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn id(value: &str) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(value)?)
}

fn fixture() -> Result<AutomaticResponsePreparationClaimRequest, Box<dyn std::error::Error>> {
    let contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())?;
    let plan = chio_quarantine::build_response_plan(ResponsePlanInput {
        execution: ResponseExecutionBinding::new(ResponseExecutionMode::Live),
        tenant_id: TenantId::new("canonical-preparation-tenant")?,
        action_id: ActionId::new("canonical-preparation-action")?,
        trigger_finding_id: id("canonical-preparation-finding")?,
        trigger_finding_hash: Digest32::new([31; 32]),
        trigger_finding_receipt_id: chio_security_types::ports::OpaqueReceiptRef::new(
            "finding-receipt",
        )?,
        policy_version: id("canonical-preparation-policy")?,
        policy_hash: Digest32::new([32; 32]),
        affected_ids: vec![id("canonical-preparation-session")?],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("canonical-preparation-session")?,
            },
            contribution_hash: Digest32::new(*sha256(contribution.as_bytes()).as_bytes()),
            canonical_contribution: contribution,
            observed_base_version_hash: Digest32::new([20; 32]),
        }],
        ttl_ms: 20_000,
        created_at_unix_ms: 40_000,
        operator_capability: OperatorCapabilityBinding {
            capability_id: id("canonical-preparation-capability")?,
            capability_digest: Digest32::new([30; 32]),
            expires_at_unix_ms: 70_000,
            executor_subject: id("canonical-preparation-executor")?,
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: id("canonical-preparation-submitter")?,
        reason_hash: Digest32::new([31; 32]),
    })?;
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        dispatch_id: id("canonical-preparation-dispatch")?,
        executor_authority_id: id("canonical-preparation-authority")?,
        executor_authority_generation: 1,
        authorized_at_unix_ms: 40_001,
        authorization_capability_hash: plan.operator_capability.capability_digest,
        governed_intent_hash: Digest32::new([32; 32]),
        policy_decision_hash: Digest32::new([33; 32]),
        admission_artifact_fingerprint: Some(Digest32::new([35; 32])),
        approval: ResponseDispatchApproval::Automatic,
    };
    Ok(AutomaticResponsePreparationClaimRequest {
        response_plan: plan,
        prepared_dispatch_binding: binding,
    })
}

fn open(path: &std::path::Path) -> PortResult<SqliteSecurityStateStore> {
    SqliteSecurityStateStore::open_with_trusted_clock(
        path,
        Arc::new(chio_security_types::clock::FixedClock::from_millis(42_000)),
    )
}

fn claimed(
    outcome: AutomaticResponsePreparationClaimOutcome,
) -> PreparedActiveResponseDispatchBinding {
    match outcome {
        AutomaticResponsePreparationClaimOutcome::Created(binding)
        | AutomaticResponsePreparationClaimOutcome::Existing(binding) => *binding,
    }
}

fn dispatch(
    request: &AutomaticResponsePreparationClaimRequest,
) -> Result<ResponseDispatchCommitRequest, Box<dyn std::error::Error>> {
    let binding = &request.prepared_dispatch_binding;
    Ok(chio_kernel::prepare_response_dispatch(
        chio_kernel::ResponseDispatchPreparationRequest {
            plan: chio_security_types::FreshLiveAdmission::new(request.response_plan.clone())?,
            dispatch_id: binding.dispatch_id.clone(),
            authorization_capability_hash: binding.authorization_capability_hash,
            governed_intent_hash: binding.governed_intent_hash,
            policy_decision_hash: binding.policy_decision_hash,
            admission_artifact_fingerprint: binding.admission_artifact_fingerprint,
            executor_authority_id: binding.executor_authority_id.clone(),
            executor_authority_generation: binding.executor_authority_generation,
            approval: binding.approval.clone(),
            authorized_at_unix_ms: binding.authorized_at_unix_ms,
            initial_lease: ResponseDispatchLease {
                lease_owner_id: LeaseOwnerId::new("canonical-preparation-worker")?,
                lease_expires_at_unix_ms: 50_000,
            },
        },
    )?)
}

fn counts(connection: &Connection) -> rusqlite::Result<Vec<i64>> {
    [
        "security_response_automatic_preparations",
        "security_response_dispatches",
        "security_response_dispatch_fences",
        "security_response_plans",
        "security_response_effects",
        "security_scheduler_leases",
        "security_scheduler_fence_sequences",
    ]
    .into_iter()
    .map(|table| {
        connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
    })
    .collect()
}

#[test]
fn automatic_claim_reuses_the_first_descriptor_across_reopen() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("pin.db");
    let request = fixture()?;
    let store = open(&path)?;
    assert!(matches!(
        store.claim_automatic_preparation(&request)?,
        AutomaticResponsePreparationClaimOutcome::Created(_)
    ));
    let observer = Connection::open(&path)?;
    let original_body: Vec<u8> = observer.query_row(
        "SELECT prepared_binding_body FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )?;
    drop(store);
    let store = open(&path)?;
    let mut retry = request.clone();
    retry.prepared_dispatch_binding.authorized_at_unix_ms += 1_000;
    retry.prepared_dispatch_binding.dispatch_id = id("later-candidate-dispatch")?;
    assert_eq!(
        claimed(store.claim_automatic_preparation(&retry)?),
        request.prepared_dispatch_binding
    );
    let after_body: Vec<u8> = observer.query_row(
        "SELECT prepared_binding_body FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(after_body, original_body);
    assert_eq!(counts(&observer)?, vec![1, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

#[test]
fn concurrent_claims_choose_one_original_artifact_without_effects() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("race.db");
    let first = fixture()?;
    let mut other = first.clone();
    other
        .prepared_dispatch_binding
        .admission_artifact_fingerprint = Some(Digest32::new([36; 32]));
    other.prepared_dispatch_binding.dispatch_id = id("other-artifact-dispatch")?;
    let a = open(&path)?;
    let b = open(&path)?;
    let barrier = Arc::new(Barrier::new(2));
    let start = Arc::clone(&barrier);
    let ar = first.clone();
    let thread = std::thread::spawn(move || {
        start.wait();
        a.claim_automatic_preparation(&ar)
    });
    barrier.wait();
    let second_result = b.claim_automatic_preparation(&other);
    let first_result = thread.join().map_err(|_| "preparation thread panicked")?;
    let winner = match (first_result, second_result) {
        (Ok(AutomaticResponsePreparationClaimOutcome::Created(binding)), Err(error))
        | (Err(error), Ok(AutomaticResponsePreparationClaimOutcome::Created(binding))) => {
            assert_eq!(
                error.kind(),
                chio_security_types::ports::PortErrorKind::Conflict
            );
            *binding
        }
        unexpected => return Err(format!("invalid claim race: {unexpected:?}").into()),
    };
    let observer = Connection::open(&path)?;
    assert_eq!(
        load_preparation(&observer, &first.prepared_dispatch_binding)?,
        Some(winner)
    );
    assert_eq!(counts(&observer)?, vec![1, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

#[test]
fn mismatched_claim_cannot_commit_or_fence_the_original_action() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("mismatch.db");
    let store = open(&path)?;
    let request = fixture()?;
    store.claim_automatic_preparation(&request)?;
    let mut other = request.clone();
    other
        .prepared_dispatch_binding
        .admission_artifact_fingerprint = Some(Digest32::new([36; 32]));
    other.prepared_dispatch_binding.dispatch_id = id("other-artifact-dispatch")?;
    let observer = Connection::open(&path)?;
    let before = counts(&observer)?;
    let canonical_before = canonical_prepared_dispatch_binding(&request.prepared_dispatch_binding)?;
    let raw_before: Vec<u8> = observer.query_row(
        "SELECT prepared_binding_body FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )?;
    let fence = AutomaticResponseDispatchFenceRequest {
        response_plan: other.response_plan.clone(),
        prepared_dispatch_binding: other.prepared_dispatch_binding.clone(),
    };
    let fence_error = match store.fence_uncommitted_automatic_dispatch(&fence) {
        Err(error) => error,
        Ok(_) => return Err("mismatched fence was accepted".into()),
    };
    assert_eq!(
        fence_error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    let commit_error = match store.commit_dispatch(&dispatch(&other)?) {
        Err(error) => error,
        Ok(_) => return Err("mismatched commit was accepted".into()),
    };
    assert_eq!(
        commit_error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    assert_eq!(counts(&observer)?, before);
    let raw_after: Vec<u8> = observer.query_row(
        "SELECT prepared_binding_body FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(raw_after, raw_before);
    let original = load_preparation(&observer, &request.prepared_dispatch_binding)?
        .ok_or("original pin lost")?;
    assert_eq!(
        canonical_prepared_dispatch_binding(&original)?,
        canonical_before
    );
    assert!(matches!(
        store.commit_dispatch(&dispatch(&request)?)?,
        ResponseDispatchCommitOutcome::Committed(_)
    ));
    assert_eq!(counts(&observer)?, vec![1, 1, 0, 1, 0, 1, 1]);
    Ok(())
}

#[test]
fn foreign_automatic_preparation_schema_is_rejected_before_migration() -> TestResult {
    for foreign in [
        "CREATE TABLE security_response_automatic_preparations (tenant_id TEXT, action_id TEXT PRIMARY KEY)",
        "CREATE TABLE security_response_automatic_preparations (tenant_id TEXT NOT NULL, action_id TEXT NOT NULL, dispatch_id TEXT NOT NULL, prepared_binding_body BLOB NOT NULL, prepared_binding_hash BLOB NOT NULL, claimed_at INTEGER NOT NULL, PRIMARY KEY(action_id, tenant_id))",
        "CREATE VIEW security_response_automatic_preparations AS SELECT 1 AS tenant_id",
    ] {
        let directory = chio_test_support::private_tempdir()?; let path = directory.path().join("foreign.db");
        let observer = Connection::open(&path)?; observer.execute_batch(foreign)?;
        let before: Vec<(String, String)> = observer.prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")?.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<_,_>>()?;
        let error = match open(&path) { Err(error) => error, Ok(_) => return Err("foreign table admitted".into()) };
        assert_eq!(error.kind(), chio_security_types::ports::PortErrorKind::IntegrityFailure);
        let after: Vec<(String, String)> = observer.prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")?.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<_,_>>()?;
        assert_eq!(after, before);
    }
    Ok(())
}

#[test]
fn readiness_refuses_missing_immutability_trigger_and_foreign_index() -> TestResult {
    for corruption in ["DROP TRIGGER security_response_automatic_preparations_immutable", "CREATE INDEX rogue_preparation_index ON security_response_automatic_preparations(action_id)"] {
        let directory = chio_test_support::private_tempdir()?; let path = directory.path().join("corrupt.db");
        let store = open(&path)?; let observer = Connection::open(&path)?;
        observer.execute_batch(corruption)?; let before = counts(&observer)?;
        let error = match store.ensure_dispatch_ready() { Err(error) => error, Ok(_) => return Err("corrupt preparation schema reported ready".into()) };
        assert_eq!(error.kind(), chio_security_types::ports::PortErrorKind::IntegrityFailure);
        let error = match store.claim_automatic_preparation(&fixture()?) { Err(error) => error, Ok(_) => return Err("corrupt preparation schema claimed".into()) };
        assert_eq!(error.kind(), chio_security_types::ports::PortErrorKind::IntegrityFailure);
        assert_eq!(counts(&observer)?, before);
    }
    Ok(())
}

#[test]
fn legacy_action_fence_remains_lossless_and_blocks_bound_preparation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("legacy.db");
    let store = open(&path)?;
    let request = fixture()?;
    let observer = Connection::open(&path)?;
    let mut legacy = request.prepared_dispatch_binding.clone();
    legacy.schema_version = 1;
    legacy.admission_artifact_fingerprint = None;
    let (body, hash) = canonical_prepared_dispatch_binding(&legacy)?;
    assert!(!std::str::from_utf8(&body)?.contains("admission_artifact_fingerprint"));
    observer.execute("INSERT INTO security_response_dispatch_fences (dispatch_id, tenant_id, action_id, prepared_binding_body, prepared_binding_hash, fenced_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![legacy.dispatch_id.as_str(), legacy.tenant_id.as_str(), legacy.action_id.as_str(), body, hash.as_bytes().as_slice(), 42_000])?;
    drop(store);
    let store = open(&path)?;
    store.ensure_dispatch_ready()?;
    let fence = AutomaticResponseDispatchFenceRequest {
        response_plan: request.response_plan.clone(),
        prepared_dispatch_binding: legacy.clone(),
    };
    let outcome = store.fence_uncommitted_automatic_dispatch(&fence)?;
    let AutomaticResponseDispatchFenceOutcome::ExistingFence(record) = outcome else {
        return Err("legacy fence was not retained".into());
    };
    assert_eq!(record.prepared_dispatch_binding, legacy);
    assert_eq!(record.binding_hash, hash);
    let error = match store.claim_automatic_preparation(&request) {
        Err(error) => error,
        Ok(_) => return Err("bound claim bypassed legacy fence".into()),
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    let error = match store.commit_dispatch(&dispatch(&request)?) {
        Err(error) => error,
        Ok(_) => return Err("bound dispatch bypassed legacy fence".into()),
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    let retained: Vec<u8> = observer.query_row(
        "SELECT prepared_binding_body FROM security_response_dispatch_fences",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained, body);
    assert_eq!(counts(&observer)?, vec![0, 0, 1, 0, 0, 0, 0]);
    Ok(())
}

fn recanonicalize_legacy_dispatch(request: &mut ResponseDispatchCommitRequest) -> TestResult {
    let mut snapshot = chio_quarantine::decode_response_record(&request.response_plan)?;
    let binding = snapshot
        .execution_dispatch
        .as_mut()
        .ok_or("dispatch binding missing")?;
    binding.schema_version = 1;
    binding.admission_artifact_fingerprint = None;
    binding.policy_decision_hash = request.authorization.body.policy_decision_hash;
    snapshot.dispatch_authorization_hash = None;
    request.authorization.body.schema_version = 1;
    request.authorization.body.admission_artifact_fingerprint = None;
    request.authorization.body.response_body_hash =
        Digest32::new(*sha256(&canonical_json_bytes(&snapshot)?).as_bytes());
    let authorization = canonical_json_bytes(&request.authorization.body)?;
    request.authorization.body_hash = Digest32::new(*sha256(&authorization).as_bytes());
    request.authorization.canonical_body = CanonicalBody::new(authorization)?;
    snapshot.dispatch_authorization_hash = Some(request.authorization.body_hash);
    let response = canonical_json_bytes(&snapshot)?;
    request.response_plan.body_hash = Digest32::new(*sha256(&response).as_bytes());
    request.response_plan.canonical_body = CanonicalBody::new(response)?;
    Ok(())
}

#[test]
fn raw_legacy_fresh_dispatch_only_replays_its_exact_existing_payload() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("legacy-fresh.db");
    let store = open(&path)?;
    let mut legacy = dispatch(&fixture()?)?;
    recanonicalize_legacy_dispatch(&mut legacy)?;
    assert!(
        !std::str::from_utf8(legacy.authorization.canonical_body.as_bytes())?
            .contains("admission_artifact_fingerprint")
    );
    assert!(
        !std::str::from_utf8(legacy.response_plan.canonical_body.as_bytes())?
            .contains("admission_artifact_fingerprint")
    );
    let observer = Connection::open(&path)?;
    let authorization = &legacy.authorization.body;
    let response = &legacy.response_plan;
    observer.execute("INSERT INTO security_response_plans (action_id, tenant_id, generation, state, body, body_hash, due_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![response.action_id.as_str(), response.tenant_id.as_str(), to_i64(response.generation)?, response.state.as_str(), response.canonical_body.as_bytes(), response.body_hash.as_bytes().as_slice(), response.due_at_unix_ms.map(to_i64).transpose()?])?;
    let lease_hash = scheduler_lease_body_hash(
        response.tenant_id.as_str(),
        response.action_id.as_str(),
        authorization.key.dispatch_id.as_str(),
        0,
        legacy.initial_lease.lease_owner_id.as_str(),
        legacy.initial_lease.lease_expires_at_unix_ms,
        1,
    )?;
    observer.execute("INSERT INTO security_scheduler_leases (action_id, tenant_id, claim_id, claim_ordinal, lease_owner_id, lease_expires_at, fencing_token, lease_body_hash) VALUES (?1, ?2, ?3, 0, ?4, ?5, 1, ?6)", params![response.action_id.as_str(), response.tenant_id.as_str(), authorization.key.dispatch_id.as_str(), legacy.initial_lease.lease_owner_id.as_str(), to_i64(legacy.initial_lease.lease_expires_at_unix_ms)?, lease_hash.as_slice()])?;
    observer.execute("INSERT INTO security_response_dispatches (dispatch_id, tenant_id, action_id, commit_mode, authorization_body, authorization_body_hash, response_generation, response_state, response_body, response_body_hash, response_due_at, initial_lease_owner_id, initial_lease_expires_at, initial_fencing_token) VALUES (?1, ?2, ?3, 'fresh', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)", params![authorization.key.dispatch_id.as_str(), response.tenant_id.as_str(), response.action_id.as_str(), legacy.authorization.canonical_body.as_bytes(), legacy.authorization.body_hash.as_bytes().as_slice(), to_i64(response.generation)?, response.state.as_str(), response.canonical_body.as_bytes(), response.body_hash.as_bytes().as_slice(), response.due_at_unix_ms.map(to_i64).transpose()?, legacy.initial_lease.lease_owner_id.as_str(), to_i64(legacy.initial_lease.lease_expires_at_unix_ms)?])?;
    let before = counts(&observer)?;
    drop(store);
    let store = open(&path)?;
    store.ensure_dispatch_ready()?;
    let ResponseDispatchCommitOutcome::Existing(record) = store.commit_dispatch(&legacy)? else {
        return Err("legacy fresh row was not replayed exactly".into());
    };
    assert_eq!(record.authorization, legacy.authorization);
    assert_eq!(record.response_plan, legacy.response_plan);
    let mut different = legacy.clone();
    different.authorization.body.policy_decision_hash = Digest32::new([37; 32]);
    recanonicalize_legacy_dispatch(&mut different)?;
    let error = match store.commit_dispatch(&different) {
        Err(error) => error,
        Ok(_) => return Err("legacy existing row accepted another payload".into()),
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    assert_eq!(counts(&observer)?, before);
    assert_eq!(
        load_response_dispatch(&observer, &authorization.key)?
            .ok_or("legacy row lost")?
            .authorization,
        legacy.authorization
    );
    assert_eq!(
        before[0], 0,
        "legacy row was backfilled as fresh preparation authority"
    );
    let empty_path = directory.path().join("unbound-new.db");
    let empty = open(&empty_path)?;
    let error = match empty.commit_dispatch(&legacy) {
        Err(error) => error,
        Ok(_) => return Err("unbound legacy data minted a fresh row".into()),
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::InvalidData
    );
    assert_eq!(counts(&Connection::open(&empty_path)?)?, vec![0; 7]);
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct PreparationPinSnapshot {
    tenant_id: String,
    action_id: String,
    dispatch_id: String,
    canonical_body: Vec<u8>,
    body_hash: Vec<u8>,
    claimed_at: i64,
}

fn raw_preparation_pin(
    connection: &Connection,
    request: &AutomaticResponsePreparationClaimRequest,
) -> rusqlite::Result<PreparationPinSnapshot> {
    connection.query_row(
        "SELECT tenant_id, action_id, dispatch_id, prepared_binding_body, prepared_binding_hash, claimed_at FROM security_response_automatic_preparations WHERE tenant_id = ?1 AND action_id = ?2",
        params![
            request.prepared_dispatch_binding.tenant_id.as_str(),
            request.prepared_dispatch_binding.action_id.as_str()
        ],
        |row| Ok(PreparationPinSnapshot {
            tenant_id: row.get(0)?,
            action_id: row.get(1)?,
            dispatch_id: row.get(2)?,
            canonical_body: row.get(3)?,
            body_hash: row.get(4)?,
            claimed_at: row.get(5)?,
        }),
    )
}

fn recanonicalize_execution_binding_only(
    request: &mut ResponseDispatchCommitRequest,
    schema_version: u8,
    fingerprint: Option<Digest32>,
) -> TestResult {
    let authorization_schema = request.authorization.body.schema_version;
    let authorization_fingerprint = request.authorization.body.admission_artifact_fingerprint;
    let mut snapshot = chio_quarantine::decode_response_record(&request.response_plan)?;
    let binding = snapshot
        .execution_dispatch
        .as_mut()
        .ok_or("execution binding missing")?;
    binding.schema_version = schema_version;
    binding.admission_artifact_fingerprint = fingerprint;
    binding.validate_for_plan(&snapshot.plan)?;
    snapshot.dispatch_authorization_hash = None;
    request.authorization.body.response_body_hash =
        Digest32::new(*sha256(&canonical_json_bytes(&snapshot)?).as_bytes());
    let authorization = canonical_json_bytes(&request.authorization.body)?;
    request.authorization.body_hash = Digest32::new(*sha256(&authorization).as_bytes());
    request.authorization.canonical_body = CanonicalBody::new(authorization)?;
    snapshot.dispatch_authorization_hash = Some(request.authorization.body_hash);
    let response = canonical_json_bytes(&snapshot)?;
    request.response_plan.body_hash = Digest32::new(*sha256(&response).as_bytes());
    request.response_plan.canonical_body = CanonicalBody::new(response)?;
    assert_eq!(
        request.authorization.body.schema_version,
        authorization_schema
    );
    assert_eq!(
        request.authorization.body.admission_artifact_fingerprint,
        authorization_fingerprint
    );
    Ok(())
}

fn execution_binding_mismatch_preserves_pin(
    label: &str,
    execution_schema: u8,
    execution_fingerprint: Option<Digest32>,
) -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join(format!("{label}.db"));
    let store = open(&path)?;
    let request = fixture()?;
    assert!(matches!(
        store.claim_automatic_preparation(&request)?,
        AutomaticResponsePreparationClaimOutcome::Created(_)
    ));
    let observer = Connection::open(&path)?;
    let before = counts(&observer)?;
    assert_eq!(before, vec![1, 0, 0, 0, 0, 0, 0]);
    let raw_before = raw_preparation_pin(&observer, &request)?;
    let healthy = dispatch(&request)?;
    assert_eq!(healthy.authorization.body.schema_version, 2);
    assert_eq!(
        healthy.authorization.body.admission_artifact_fingerprint,
        Some(Digest32::new([35; 32]))
    );
    let mut mismatch = healthy.clone();
    recanonicalize_execution_binding_only(&mut mismatch, execution_schema, execution_fingerprint)?;
    let decoded = chio_quarantine::decode_response_record(&mismatch.response_plan)?;
    let execution = decoded
        .execution_dispatch
        .as_ref()
        .ok_or("mutated execution binding missing")?;
    assert_eq!(execution.schema_version, execution_schema);
    assert_eq!(
        execution.admission_artifact_fingerprint,
        execution_fingerprint
    );
    assert_eq!(
        mismatch.authorization.body.schema_version,
        healthy.authorization.body.schema_version
    );
    assert_eq!(
        mismatch.authorization.body.admission_artifact_fingerprint,
        healthy.authorization.body.admission_artifact_fingerprint
    );
    let refused = store.commit_dispatch(&mismatch);
    let after = counts(&observer)?;
    let raw_after = raw_preparation_pin(&observer, &request)?;
    assert_eq!(
        after, before,
        "mismatched execution binding changed the seven table counts"
    );
    assert_eq!(
        raw_after, raw_before,
        "mismatched execution binding changed the raw canonical pin"
    );
    let error = match refused {
        Err(error) => error,
        Ok(_) => return Err("inconsistent execution binding was committed".into()),
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::InvalidData
    );
    store.ensure_dispatch_ready()?;
    let ResponseDispatchCommitOutcome::Committed(committed) = store.commit_dispatch(&healthy)?
    else {
        return Err("healthy original dispatch did not commit after mismatch refusal".into());
    };
    assert_eq!(committed.authorization, healthy.authorization);
    assert_eq!(committed.response_plan, healthy.response_plan);
    assert_eq!(counts(&observer)?, vec![1, 1, 0, 1, 0, 1, 1]);
    assert_eq!(raw_preparation_pin(&observer, &request)?, raw_before);
    Ok(())
}

#[test]
fn fresh_dispatch_rejects_execution_fingerprint_different_from_authorization_and_pin() -> TestResult
{
    execution_binding_mismatch_preserves_pin(
        "execution-fingerprint-mismatch",
        2,
        Some(Digest32::new([36; 32])),
    )
}

#[test]
fn fresh_dispatch_rejects_legacy_execution_binding_beside_v2_authorization_and_pin() -> TestResult {
    execution_binding_mismatch_preserves_pin("execution-schema-mismatch", 1, None)
}

type SchemaCatalogObject = (String, String, String, i64, Option<String>);

#[derive(Debug, Eq, PartialEq)]
struct ForeignSchemaSnapshot {
    catalog: Vec<SchemaCatalogObject>,
    schema_version: i64,
    user_version: i64,
    application_id: i64,
    journal_mode: String,
}

fn foreign_catalog_snapshot(
    path: &std::path::Path,
) -> Result<ForeignSchemaSnapshot, Box<dyn std::error::Error>> {
    let observer = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let catalog = observer
        .prepare(
            "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY type, name",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ForeignSchemaSnapshot {
        catalog,
        schema_version: observer.query_row("PRAGMA schema_version", [], |row| row.get(0))?,
        user_version: observer.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        application_id: observer.query_row("PRAGMA application_id", [], |row| row.get(0))?,
        journal_mode: observer.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
    })
}

#[test]
fn mixed_case_foreign_preparation_objects_are_refused_without_opening_side_effects() -> TestResult {
    for foreign in [
        "CREATE TABLE SeCuRiTy_ReSpOnSe_AuToMaTiC_PrEpArAtIoNs (tenant_id TEXT, action_id TEXT PRIMARY KEY)",
        "CREATE TABLE unrelated_foreign_owner (id INTEGER PRIMARY KEY); CREATE TRIGGER SeCuRiTy_ReSpOnSe_AuToMaTiC_PrEpArAtIoNs_ImMuTaBlE BEFORE UPDATE ON unrelated_foreign_owner BEGIN SELECT RAISE(ABORT, 'foreign sentinel'); END",
    ] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("mixed-case-foreign.db");
        {
            let creator = Connection::open(&path)?;
            creator.execute_batch(foreign)?;
            let journal: String = creator.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            assert_eq!(journal, "delete");
        }
        let before = foreign_catalog_snapshot(&path)?;
        let bytes_before = std::fs::read(&path)?;
        let opened = open(&path);
        let error = match opened {
            Err(error) => error,
            Ok(store) => {
                drop(store);
                return Err("mixed-case foreign preparation object was admitted".into());
            }
        };
        let after = foreign_catalog_snapshot(&path)?;
        let bytes_after = std::fs::read(&path)?;
        assert_eq!(error.kind(), chio_security_types::ports::PortErrorKind::IntegrityFailure);
        assert_eq!(after, before, "refused public opener changed catalog or schema/database pragmas");
        assert_eq!(bytes_after, bytes_before, "refused public opener changed the stable DELETE-mode database bytes");
    }
    let directory = chio_test_support::private_tempdir()?;
    let healthy_path = directory.path().join("healthy-open.db");
    let healthy = open(&healthy_path)?;
    healthy.ensure_dispatch_ready()?;
    assert_eq!(counts(&Connection::open(&healthy_path)?)?, vec![0; 7]);
    Ok(())
}
