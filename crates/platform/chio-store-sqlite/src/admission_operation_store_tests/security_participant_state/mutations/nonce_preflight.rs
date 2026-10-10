//! Actual Prepared leases cannot be borrowed by the dispatch journal.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityInputJoinRequestV1, NativeSecurityNoncePreflightJoinRequestV1,
};

pub(in crate::admission_operation_store::tests) fn prepare_issuance_fixture(
    fixture: &Fixture,
    issuer: &Keypair,
    join: bool,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    let initialized = hydrate(fixture, &imported(fixture, "source")?)?;
    let (context, raw) = request("unused")?;
    let binding = initialized.admission_binding()?;
    let (operation, lease, _) = setup_selected_phase(
        fixture,
        &format!("kernel:{}", issuer.public_key().to_hex()),
        &context,
        now_ms(),
        Some(binding.clone()),
        true,
    )?;
    if join {
        let input = NativeSecurityNoncePreflightJoinRequestV1::new(
            operation.binding().operation_id().clone(),
            raw.key,
            input::label()?,
        )?;
        fixture.store.join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms(),
        )?;
    }
    let (_, original) = fixture
        .store
        .load_retained_tool_request(operation.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("native nonce original request")?;
    Ok((operation, original))
}

fn prepare(
    fixture: &Fixture,
    context: &SecurityInvocationContext,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    NativeSecurityNoncePreflightJoinRequestV1,
)> {
    let initialized = fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("initialization")?;
    let (operation, lease, _) = setup_selected_phase(
        fixture,
        "nonce-preflight",
        context,
        now_ms(),
        Some(initialized.admission_binding()?),
        true,
    )?;
    let (_, raw) = request("unused")?;
    let input = NativeSecurityNoncePreflightJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key,
        input::label()?,
    )?;
    Ok((operation, lease, input))
}

#[test]
fn native_journal_checkpoint_preserves_nonce_preflight_and_current_label() -> TestResult {
    let _fixture_clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, _) = request("checkpoint-nonce")?;
    let (operation, lease, input) = prepare(&fixture, &context)?;
    let binding = initialized.admission_binding()?;
    let before = fixture.store.join_native_security_nonce_preflight(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let (_, after) = fixture
        .store
        .load_native_security_nonce_preflight_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("nonce history absent")?;
    assert_eq!(after, Some(before.clone()));
    let observation = fixture.store.observe_security_participant_flow(
        &binding,
        input.key(),
        &fixture.fence,
        now_ms(),
    )?;
    assert_eq!(
        observation
            .snapshot()
            .ok_or("current nonce label absent")?
            .principal_label,
        input::label()?
    );
    let (_, dispatch) = fixture
        .store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("operation absent")?;
    assert!(dispatch.is_none());
    assert_eq!(
        fixture.store.join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms()
        )?,
        before
    );
    Ok(())
}

#[test]
fn preflight_is_anchored_once_and_never_satisfies_dispatch_input_custody() -> TestResult {
    let _fixture_clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, _) = request("unused")?;
    let (operation, lease, input) = prepare(&fixture, &context)?;
    let binding = initialized.admission_binding()?;
    let result = fixture.store.join_native_security_nonce_preflight(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    result.validate()?;
    assert_eq!(result.input, input);
    assert_eq!(result.join.snapshot.principal_label, input::label()?);
    let (_, history) = fixture
        .store
        .load_native_security_nonce_preflight_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("preflight operation")?;
    assert_eq!(history, Some(result.clone()));
    let (_, dispatch) = fixture
        .store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("dispatch operation")?;
    assert!(dispatch.is_none());
    let before = global_count(&*fixture.store.connection()?)?;
    assert_eq!(
        fixture.store.join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms(),
        )?,
        result
    );
    let dispatch = NativeSecurityInputJoinRequestV1::new(
        input.operation_id().clone(),
        input.key().clone(),
        input.input_label().clone(),
    )?;
    assert!(fixture
        .store
        .join_native_security_input(&operation, &lease, &binding, &context, &dispatch, now_ms(),)
        .is_err());
    let changed = NativeSecurityNoncePreflightJoinRequestV1::new(
        input.operation_id().clone(),
        input.key().clone(),
        InformationLabel::bottom(),
    )?;
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &changed,
            now_ms(),
        )
        .is_err());
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert_eq!(count(&fixture)?, 0);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn preflight_rejects_wrong_phase_lease_identity_and_observation_before_writing() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, _) = request("unused")?;
    let binding = initialized.admission_binding()?;
    let (operation, lease, input) = prepare(&fixture, &context)?;
    let (dispatch, other_lease) = setup(&fixture, "dispatch-only", &context)?;
    let before = global_count(&*fixture.store.connection()?)?;
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &operation,
            &other_lease,
            &binding,
            &context,
            &input,
            now_ms(),
        )
        .is_err());
    let wrong_observation =
        SecurityInvocationContext::v1(context.as_v1().clone().with_flow_state_generation(1));
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &wrong_observation,
            &input,
            now_ms(),
        )
        .is_err());
    let mut wrong_key = input.key().clone();
    wrong_key.session_id = SessionId::new("wrong-session")?;
    let wrong = NativeSecurityNoncePreflightJoinRequestV1::new(
        input.operation_id().clone(),
        wrong_key,
        InformationLabel::bottom(),
    )?;
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &wrong,
            now_ms(),
        )
        .is_err());
    let wrong_phase = NativeSecurityNoncePreflightJoinRequestV1::new(
        dispatch.binding().operation_id().clone(),
        input.key().clone(),
        InformationLabel::bottom(),
    )?;
    let mut foreign_key = input.key().clone();
    foreign_key.tenant_id = TenantId::new("foreign-tenant")?;
    let foreign = NativeSecurityNoncePreflightJoinRequestV1::new(
        input.operation_id().clone(),
        foreign_key,
        input.input_label().clone(),
    )?;
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &foreign,
            now_ms(),
        )
        .is_err());
    assert!(fixture
        .store
        .join_native_security_nonce_preflight(
            &dispatch,
            &other_lease,
            &binding,
            &context,
            &wrong_phase,
            now_ms(),
        )
        .is_err());
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert_eq!(
        fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM security_participant_nonce_preflight_events",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn preflight_cutpoints_preserve_only_committed_monotone_history_on_reopen() -> TestResult {
    for stage in 22..=26 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let binding = initialized.admission_binding()?;
        let (context, _) = request("unused")?;
        let (operation, lease, input) = prepare(&fixture, &context)?;
        let _reset = ResetCutpoint;
        FAIL_AFTER.set(stage);
        assert!(fixture
            .store
            .join_native_security_nonce_preflight(
                &operation,
                &lease,
                &binding,
                &context,
                &input,
                now_ms(),
            )
            .is_err());
        FAIL_AFTER.set(0);
        let Fixture {
            _temp,
            database,
            lock_root,
            store,
            authority,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let authority = crate::test_authority::open_serving(&database, &lock_root)?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let (_, history) = store
            .load_native_security_nonce_preflight_join(
                operation.binding().operation_id(),
                &fence,
                now_ms(),
            )?
            .ok_or("operation after reopen")?;
        assert_eq!(history.is_some(), stage >= 25, "cutpoint {stage}");
        let observed =
            store.observe_native_security_flow(&binding, input.key(), &fence, now_ms())?;
        assert_eq!(observed.stored_context_generation().is_some(), stage >= 25);
        assert!(
            store
                .join_native_security_nonce_preflight(
                    &operation,
                    &lease,
                    &binding,
                    &context,
                    &input,
                    now_ms(),
                )
                .is_err(),
            "historical owner cannot mutate after restart"
        );
        native::verify_coverage(&*store.connection()?)?;
    }
    Ok(())
}

#[test]
fn compacted_preflight_transition_stays_refused_to_another_join_family() -> TestResult {
    let _fixture_clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, _) = request("compacted-preflight")?;
    let (operation, lease, input) = prepare(&fixture, &context)?;
    let binding = initialized.admission_binding()?;
    let recorded = fixture.store.join_native_security_nonce_preflight(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let current = |fixture: &Fixture| -> TestResult<bool> {
        Ok(fixture.store.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_transitions
             WHERE tenant_id = ?1 AND transition_id = ?2)",
            params![
                input.key().tenant_id.as_str(),
                input.transition_id().as_str()
            ],
            |row| row.get(0),
        )?)
    };
    assert!(
        !current(&fixture)?,
        "finished preflight transition stayed current"
    );
    assert_eq!(
        fixture.store.join_native_security_nonce_preflight(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms(),
        )?,
        recorded
    );
    // A flow join of another operation cannot claim the preflight identifier.
    let (_, mut join) = request("unused")?;
    join.transition_id = input.transition_id().clone();
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(recorded.join.snapshot.context_generation),
    );
    let (other, other_lease) = setup(&fixture, "compacted-preflight-reuse", &context)?;
    let before = global_count(&*fixture.store.connection()?)?;
    let refused = fixture.store.join_security_participant_flow(
        &other,
        &other_lease,
        &initialized,
        &context,
        &join,
        now_ms(),
    );
    assert!(
        refused.as_ref().is_err_and(|error| error
            .to_string()
            .contains("native transition belongs to another operation or imported history")),
        "a compacted preflight identifier was claimed by a flow join"
    );
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert!(!current(&fixture)?);
    Ok(())
}
