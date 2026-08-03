use std::sync::Arc;

use chio_quarantine::{
    build_response_plan, decode_response_record, EffectMutation, EffectMutationRequest,
    ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    ActionId, CanonicalBody, Digest32, OpaqueReceiptRef, PortErrorKind, RecordId,
    ResponseCasRequest, ResponsePlanKey, ResponsePlanRecord, ResponseStore, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponseMutationLog, ResponsePlan, ResponsePlanInput, ResponseSnapshot, ResponseState,
    ResponseTarget,
};
use chio_store_sqlite::SqliteSecurityStateStore;

const CREATED_AT_UNIX_MS: u64 = 10_000;
const EXPIRES_AT_UNIX_MS: u64 = 30_000;

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn record_id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn rejected<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn response_plan(action: &str, approval_requirement: ResponseApprovalRequirement) -> ResponsePlan {
    let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
        .unwrap_or_else(|error| panic!("invalid contribution body: {error}"));
    let contribution_hash =
        Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
    build_response_plan(ResponsePlanInput {
        action_id: ActionId::new(action)
            .unwrap_or_else(|error| panic!("invalid action id: {error}")),
        trigger_finding_id: record_id("legacy-cas-finding"),
        trigger_finding_hash: digest(1),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("legacy-cas-finding-receipt")
            .unwrap_or_else(|error| panic!("invalid finding receipt id: {error}")),
        tenant_id: TenantId::new("legacy-cas-tenant")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        policy_version: record_id("legacy-cas-policy"),
        policy_hash: digest(2),
        affected_ids: vec![record_id("legacy-cas-affected")],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("legacy-cas-session")
                    .unwrap_or_else(|error| panic!("invalid session id: {error}")),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: digest(3),
        }],
        ttl_ms: EXPIRES_AT_UNIX_MS - CREATED_AT_UNIX_MS,
        created_at_unix_ms: CREATED_AT_UNIX_MS,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record_id("legacy-cas-capability"),
            capability_digest: digest(4),
            expires_at_unix_ms: 40_000,
            executor_subject: record_id("legacy-cas-executor"),
        },
        approval_requirement,
        submitter: record_id("legacy-cas-submitter"),
        reason_hash: digest(5),
    })
    .unwrap_or_else(|error| panic!("response plan build failed: {error}"))
}

fn open_store(path: &std::path::Path) -> Arc<SqliteSecurityStateStore> {
    Arc::new(
        SqliteSecurityStateStore::open(path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    )
}

fn create_plan(store: &Arc<SqliteSecurityStateStore>, plan: ResponsePlan) -> ResponsePlanRecord {
    ResponseStateMachine::new(Arc::clone(store))
        .create(plan)
        .unwrap_or_else(|error| panic!("response plan create failed: {error}"))
}

fn enter_applying(
    store: &Arc<SqliteSecurityStateStore>,
    current: &ResponsePlanRecord,
    occurred_at_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
) -> ResponsePlanRecord {
    ResponseStateMachine::new(Arc::clone(store))
        .transition(
            current,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms,
                applying_lease_expires_at_unix_ms: Some(lease_expires_at_unix_ms),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("enter applying failed: {error}"))
}

fn request_effect(
    store: &Arc<SqliteSecurityStateStore>,
    current: &ResponsePlanRecord,
    occurred_at_unix_ms: u64,
) -> ResponsePlanRecord {
    let snapshot = decode_response_record(current)
        .unwrap_or_else(|error| panic!("applying response decode failed: {error}"));
    ResponseStateMachine::new(Arc::clone(store))
        .record_effect(
            current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: snapshot.plan.effects.as_slice()[0].effect_id.clone(),
                occurred_at_unix_ms,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|error| panic!("effect request failed: {error}"))
}

fn cancel_plan(
    store: &Arc<SqliteSecurityStateStore>,
    current: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    ResponseStateMachine::new(Arc::clone(store))
        .transition(
            current,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::Cancelled,
                occurred_at_unix_ms: CREATED_AT_UNIX_MS + 1,
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("response cancellation failed: {error}"))
}

fn transition_id(record: &ResponsePlanRecord) -> RecordId {
    decode_response_record(record)
        .unwrap_or_else(|error| panic!("response decode failed: {error}"))
        .mutations
        .as_slice()
        .last()
        .unwrap_or_else(|| panic!("response mutation log is empty"))
        .transition_id()
        .clone()
}

fn encode_snapshot(snapshot: &ResponseSnapshot) -> ResponsePlanRecord {
    let bytes = chio_core::canonical_json_bytes(snapshot)
        .unwrap_or_else(|error| panic!("response canonicalization failed: {error}"));
    let canonical_body = CanonicalBody::new(bytes)
        .unwrap_or_else(|error| panic!("response canonical body failed: {error}"));
    let body_hash = Digest32::new(*chio_core::sha256(canonical_body.as_bytes()).as_bytes());
    ResponsePlanRecord {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
        generation: snapshot.generation,
        state: record_id(snapshot.state.as_str()),
        canonical_body,
        body_hash,
        due_at_unix_ms: snapshot.due_at_unix_ms,
    }
}

fn cas_request(current: &ResponsePlanRecord, candidate: ResponsePlanRecord) -> ResponseCasRequest {
    ResponseCasRequest {
        transition_id: transition_id(&candidate),
        expected_generation: current.generation,
        record: candidate,
    }
}

fn assert_stored_plan(store: &SqliteSecurityStateStore, expected: &ResponsePlanRecord) {
    let loaded = store
        .load_plan(&ResponsePlanKey {
            tenant_id: expected.tenant_id.clone(),
            action_id: expected.action_id.clone(),
        })
        .unwrap_or_else(|error| panic!("response plan load failed: {error}"));
    assert_eq!(loaded.as_ref(), Some(expected));
}

#[test]
fn legacy_response_cas_accepts_one_exact_append_and_replays_idempotently() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let plan = response_plan(
        "legacy-cas-exact-append",
        ResponseApprovalRequirement::Automatic,
    );
    let target = open_store(&directory.path().join("target.db"));
    let current = create_plan(&target, plan.clone());
    let source = open_store(&directory.path().join("source.db"));
    let source_current = create_plan(&source, plan);
    let candidate = cancel_plan(&source, &source_current);
    let request = cas_request(&current, candidate.clone());

    assert_eq!(
        target
            .compare_and_swap(&request)
            .unwrap_or_else(|error| panic!("exact append failed: {error}")),
        candidate
    );
    assert_eq!(
        target
            .compare_and_swap(&request)
            .unwrap_or_else(|error| panic!("exact append retry failed: {error}")),
        candidate
    );
    assert_stored_plan(target.as_ref(), &candidate);
}

#[test]
fn legacy_response_cas_rejects_valid_substituted_history_and_plan() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let plan = response_plan("legacy-cas-history", ResponseApprovalRequirement::Automatic);
    let target = open_store(&directory.path().join("history-target.db"));
    let target_planned = create_plan(&target, plan.clone());
    let current = enter_applying(&target, &target_planned, 10_001, 20_000);
    let source = open_store(&directory.path().join("history-source.db"));
    let source_planned = create_plan(&source, plan);
    let alternate = enter_applying(&source, &source_planned, 10_002, 21_000);
    let substituted_history = request_effect(&source, &alternate, 10_003);
    let error = rejected(
        target.compare_and_swap(&cas_request(&current, substituted_history)),
        "separately valid substituted history must be rejected",
    );
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_stored_plan(target.as_ref(), &current);

    let plan_target = open_store(&directory.path().join("plan-target.db"));
    let target_current = create_plan(
        &plan_target,
        response_plan("legacy-cas-plan", ResponseApprovalRequirement::Automatic),
    );
    let plan_source = open_store(&directory.path().join("plan-source.db"));
    let source_current = create_plan(
        &plan_source,
        response_plan(
            "legacy-cas-plan",
            ResponseApprovalRequirement::Governed {
                policy_id: record_id("legacy-cas-approval-policy"),
            },
        ),
    );
    let substituted_plan = cancel_plan(&plan_source, &source_current);
    let error = rejected(
        plan_target.compare_and_swap(&cas_request(&target_current, substituted_plan)),
        "valid substituted plan must be rejected",
    );
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_stored_plan(plan_target.as_ref(), &target_current);
}

#[test]
fn legacy_response_cas_rejects_dropped_reordered_and_multiple_appends() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let plan = response_plan(
        "legacy-cas-malformed-history",
        ResponseApprovalRequirement::Automatic,
    );
    let target = open_store(&directory.path().join("malformed-target.db"));
    let target_planned = create_plan(&target, plan.clone());
    let current = enter_applying(&target, &target_planned, 10_001, 20_000);
    let source = open_store(&directory.path().join("malformed-source.db"));
    let source_planned = create_plan(&source, plan.clone());
    let source_applying = enter_applying(&source, &source_planned, 10_001, 20_000);
    let valid_candidate = request_effect(&source, &source_applying, 10_002);

    let mut dropped_snapshot = decode_response_record(&valid_candidate)
        .unwrap_or_else(|error| panic!("valid candidate decode failed: {error}"));
    let mut dropped_mutations = dropped_snapshot.mutations.into_vec();
    dropped_mutations.remove(0);
    dropped_snapshot.mutations = ResponseMutationLog::new(dropped_mutations)
        .unwrap_or_else(|error| panic!("dropped mutation log failed: {error}"));
    let dropped = encode_snapshot(&dropped_snapshot);
    let error = rejected(
        target.compare_and_swap(&ResponseCasRequest {
            transition_id: transition_id(&valid_candidate),
            expected_generation: current.generation,
            record: dropped,
        }),
        "dropped prior mutation must be rejected",
    );
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_stored_plan(target.as_ref(), &current);

    let mut reordered_snapshot = decode_response_record(&valid_candidate)
        .unwrap_or_else(|error| panic!("valid candidate decode failed: {error}"));
    let mut reordered_mutations = reordered_snapshot.mutations.into_vec();
    reordered_mutations.swap(0, 1);
    reordered_snapshot.mutations = ResponseMutationLog::new(reordered_mutations)
        .unwrap_or_else(|error| panic!("reordered mutation log failed: {error}"));
    let reordered = encode_snapshot(&reordered_snapshot);
    let error = rejected(
        target.compare_and_swap(&ResponseCasRequest {
            transition_id: transition_id(&valid_candidate),
            expected_generation: current.generation,
            record: reordered,
        }),
        "reordered prior mutations must be rejected",
    );
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_stored_plan(target.as_ref(), &current);

    let multi_target = open_store(&directory.path().join("multiple-target.db"));
    let multi_current = create_plan(&multi_target, plan);
    let error = rejected(
        multi_target.compare_and_swap(&cas_request(&multi_current, valid_candidate)),
        "multiple appended mutations must be rejected",
    );
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_stored_plan(multi_target.as_ref(), &multi_current);
}

#[test]
fn legacy_response_cas_maps_stored_canonical_and_decode_corruption_to_integrity_failure() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let plan = response_plan(
        "legacy-cas-corruption",
        ResponseApprovalRequirement::Automatic,
    );
    let source = open_store(&directory.path().join("corruption-source.db"));
    let source_current = create_plan(&source, plan.clone());
    let candidate = cancel_plan(&source, &source_current);

    for (name, canonical_body, body_hash) in [
        ("canonical", b"{}".to_vec(), vec![0_u8; 32]),
        (
            "decode",
            b"{}".to_vec(),
            chio_core::sha256(b"{}").as_bytes().to_vec(),
        ),
    ] {
        let path = directory.path().join(format!("{name}-target.db"));
        let target = open_store(&path);
        let current = create_plan(&target, plan.clone());
        rusqlite::Connection::open(&path)
            .and_then(|connection| {
                connection.execute(
                    "UPDATE security_response_plans SET body = ?1, body_hash = ?2 WHERE tenant_id = ?3 AND action_id = ?4",
                    rusqlite::params![
                        canonical_body,
                        body_hash,
                        current.tenant_id.as_str(),
                        current.action_id.as_str(),
                    ],
                )?;
                Ok(())
            })
            .unwrap_or_else(|error| panic!("stored response corruption failed: {error}"));
        let error = rejected(
            target.compare_and_swap(&cas_request(&current, candidate.clone())),
            "stored response corruption must fail closed",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
        let generation = rusqlite::Connection::open(&path)
            .and_then(|connection| {
                connection.query_row(
                    "SELECT generation FROM security_response_plans WHERE tenant_id = ?1 AND action_id = ?2",
                    rusqlite::params![current.tenant_id.as_str(), current.action_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap_or_else(|error| panic!("stored response generation read failed: {error}"));
        assert_eq!(generation, 0);
    }
}
