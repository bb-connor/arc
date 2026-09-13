//! Real operation leases and anchored native writes, not scope-only fixtures.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{
    FlowJoinRequest, FlowStateKey, IsolationEpochId, LineageId, RecordId, SessionId, TenantId,
};
use chio_security_types::{InformationLabel, PrincipalId};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
#[path = "mutations/authority_binding.rs"]
mod authority_binding;
#[path = "mutations/faults.rs"]
mod faults;
#[path = "mutations/history_integrity.rs"]
mod history_integrity;
#[path = "mutations/input.rs"]
mod input;
#[path = "mutations/monotonicity.rs"]
mod monotonicity;
#[path = "mutations/nonce_preflight.rs"]
mod nonce_preflight;
pub(in crate::admission_operation_store::tests) use nonce_preflight::prepare_issuance_fixture;
#[path = "mutations/shared.rs"]
mod shared;

pub(super) fn request(name: &str) -> TestResult<(SecurityInvocationContext, FlowJoinRequest)> {
    let key = FlowStateKey {
        tenant_id: TenantId::new("native-tenant")?,
        principal_id: PrincipalId::new("native-principal")?,
        lineage_id: LineageId::new("native-lineage")?,
        session_id: SessionId::new("native-session")?,
        isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
    };
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        1,
    ));
    Ok((
        context,
        FlowJoinRequest {
            key,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: RecordId::new(name)?,
        },
    ))
}

pub(super) fn setup(
    fixture: &Fixture,
    name: &str,
    context: &SecurityInvocationContext,
) -> TestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    let (operation, lease, _) = setup_with_stale_lease(fixture, name, context)?;
    Ok((operation, lease))
}

fn setup_with_stale_lease(
    fixture: &Fixture,
    name: &str,
    context: &SecurityInvocationContext,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    AdmissionRecoveryLease,
)> {
    setup_at(fixture, name, context, now_ms())
}

fn setup_at(
    fixture: &Fixture,
    name: &str,
    context: &SecurityInvocationContext,
    decision_at: u64,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    AdmissionRecoveryLease,
)> {
    let initialized = fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            decision_at,
        )?
        .ok_or("source initialization absent")?;
    setup_selected_at(
        fixture,
        name,
        context,
        decision_at,
        Some(initialized.admission_binding()?),
    )
}

fn setup_selected_at(
    fixture: &Fixture,
    name: &str,
    context: &SecurityInvocationContext,
    decision_at: u64,
    selected: Option<chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1>,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    AdmissionRecoveryLease,
)> {
    setup_selected_phase(fixture, name, context, decision_at, selected, false)
}

fn setup_selected_phase(
    fixture: &Fixture,
    name: &str,
    context: &SecurityInvocationContext,
    decision_at: u64,
    selected: Option<chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1>,
    nonce_preflight: bool,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    AdmissionRecoveryLease,
)> {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        execution_nonce: nonce_preflight,
        ..AdmissionParticipantRequirements::NONE
    };
    let (unbound, original) = super::super::retained_request::original_with_requirements(
        &fixture.fence,
        name,
        requirements,
    )?;
    let ctx = context.as_v1();
    let mut binding = serde_json::json!({
        "schema": "chio.admission-security-binding.v1", "context": {
            "tenant_id": ctx.tenant_id(), "session_id": ctx.session_id(), "principal_id": ctx.principal_id(),
            "isolation_epoch_id": ctx.isolation_epoch_id(), "lineage_root_id": ctx.lineage_root_id(),
            "context_generation": ctx.context_generation()
        }, "pre_dispatch_required": true, "pre_dispatch_hook_installed": true
    });
    let (hash_schema, retained_schema) = if let Some(selected) = selected {
        binding["schema"] = "chio.admission-security-binding.v2".into();
        binding["native_authority"] = serde_json::to_value(selected)?;
        (
            "chio.tool-admission-request.v3",
            "chio.retained-tool-admission-request.v3",
        )
    } else {
        (
            "chio.tool-admission-request.v2",
            "chio.retained-tool-admission-request.v2",
        )
    };
    let immutable = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": hash_schema,
        "unbound_request_hash": unbound.binding().immutable_request_hash(), "security_binding": binding
    }))?);
    let mut retained: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
    retained["schema"] = retained_schema.into();
    retained["security_binding"] = binding;
    let retained =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&retained)?)?;
    let old = unbound.to_persisted().binding;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: old.kind,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "authority",
            &fixture.fence.store_uuid,
        ))?,
        request_id: old.request_id,
        capability_id: old.capability_id,
        authorization_capability_hash: old.authorization_capability_hash,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            AdmissionDigest::try_new("immutable", immutable)?,
            unbound.binding().action_parameter_hash().clone(),
            requirements,
        )?,
        policy_hash: old.policy_hash,
        effect_class: old.effect_class,
    })?;
    let operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    let profile = super::super::retained_request::authority_profile::selection(None, None, None)?;
    let (operation, retained) =
        super::super::retained_request::authority_profile::prepare_with_profile(
            operation, retained, profile,
        )?;
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &retained,
        &fixture.fence,
        decision_at,
    )?;
    let lease = claim(fixture, &operation, name, decision_at);
    let stale_lease = lease.clone();
    if nonce_preflight {
        return Ok((operation, lease, stale_lease));
    }
    let operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation, name,
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            decision_at,
        )?
        .into_operation();
    let lease = claim(fixture, &operation, name, decision_at);
    Ok((operation, lease, stale_lease))
}

fn count(fixture: &Fixture) -> TestResult<i64> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn operation_owned_join_is_anchored_idempotent_and_keeps_other_authorities_unchanged() -> TestResult
{
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let other = imported(&fixture, "other")?;
    let initialized = hydrate(&fixture, &source)?;
    let other_initialization = hydrate(&fixture, &other)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let result = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    assert_eq!(result.key, request.key);
    assert!(result.context_generation > 0);
    let before = global_count(&*fixture.store.connection()?)?;
    assert_eq!(
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms()
        )?,
        result
    );
    assert_eq!(count(&fixture)?, 1);
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert_eq!(hydrate(&fixture, &source)?, initialized);
    assert_eq!(hydrate(&fixture, &other)?, other_initialization);
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &other_initialization,
            &context,
            &request,
            now_ms()
        )
        .is_err());
    let connection = fixture.store.connection()?;
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM security_participant_state_flow_contexts WHERE security_authority_id = 'other' AND tenant_id = 'native-tenant'", [], |row| row.get::<_, i64>(0))?, 0);
    assert!(connection.execute("UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1 WHERE security_authority_id = 'source'", []).is_err());
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn wrong_identity_lease_observation_and_command_substitution_fail_before_writing() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let (_, stale) = setup(&fixture, "different-operation", &context)?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &stale,
            &initialized,
            &context,
            &request,
            now_ms()
        )
        .is_err());
    let wrong_observation =
        SecurityInvocationContext::v1(context.as_v1().clone().with_flow_state_generation(1));
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &wrong_observation,
            &request,
            now_ms()
        )
        .is_err());
    let mut wrong_key = request.clone();
    wrong_key.key.session_id = SessionId::new("different-session")?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &wrong_key,
            now_ms()
        )
        .is_err());
    let mut wrong_identity = serde_json::to_value(&context)?;
    // Change a genuinely trusted-context field, not agent metadata.
    let object = wrong_identity.get_mut("context").ok_or("context variant")?;
    object["contextGeneration"] = 2.into();
    let wrong_identity = serde_json::from_value(wrong_identity)?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &wrong_identity,
            &request,
            now_ms()
        )
        .is_err());
    assert_eq!(count(&fixture)?, 0);
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let mut different = request.clone();
    different.transition_id = RecordId::new("different-command")?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &different,
            now_ms()
        )
        .is_err());
    assert_eq!(count(&fixture)?, 1);
    Ok(())
}

#[test]
fn native_join_errors_rollback_or_recover_exactly_one_committed_record() -> TestResult {
    let _reset = ResetCutpoint;
    for stage in 7..=11 {
        let fixture = fixture();
        let source = imported(&fixture, "source")?;
        let initialized = hydrate(&fixture, &source)?;
        let (context, request) = request("native-join")?;
        let (operation, lease) = setup(&fixture, "native-operation", &context)?;
        FAIL_AFTER.set(stage);
        let result = fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        );
        FAIL_AFTER.set(0);
        assert!(result.is_err(), "stage {stage}");
        assert_eq!(count(&fixture)?, i64::from(stage >= 10));
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            _temp,
            database,
            lock_root,
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
        };
        let operation = fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("operation")?;
        let lease = claim(&fixture, &operation, "new-owner", now_ms());
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        )?;
        assert_eq!(count(&fixture)?, 1);
        native::verify_coverage(&*fixture.store.connection()?)?;
    }
    Ok(())
}

#[test]
fn owner_takeover_preserves_join_history_without_reacquiring_old_authority() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let result = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert_eq!(
        store.load_security_participant_state(
            initialized.security_authority_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(initialized.clone())
    );
    assert!(store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms()
        )
        .is_err());
    let operation = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation")?;
    let now = now_ms();
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "new-owner"),
        now,
        now + 10000,
        &authority.mutation_fence(),
    )?;
    assert_eq!(
        store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms()
        )?,
        result
    );
    Ok(())
}
