// Real native capture plus physical output journal. The returned payload and
// pure evaluation are fixtures, not evidence of native connector activation.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationV1, AdmissionRecoveryLease, NativeSecurityOutputJoinRecordV1,
    NativeSecurityOutputJoinRequestV1, QualifiedAdmissionOperationStoreExt,
};
use chio_kernel::tool_outcome::{
    test_support, PostReturnEvaluationRecordV1, SettlementDispositionV1, ToolOutcomeRecordV1,
    ToolOutcomeStore,
};
use chio_store_sqlite::admission_operation_store::SecurityParticipantStateInitialization;

mod faults {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_output_fault_tests.rs"
    ));
}

struct Finalizing {
    operation: AdmissionOperationV1,
    lease: AdmissionRecoveryLease,
    stale_lease: AdmissionRecoveryLease,
    initialized: SecurityParticipantStateInitialization,
    observation: chio_kernel::admission_operation::NativeSecurityFlowObservationV1,
    outcome: ToolOutcomeRecordV1,
    evaluation: PostReturnEvaluationRecordV1,
}

impl Finalizing {
    fn intent(&self, label: InformationLabel) -> TestResult<NativeSecurityOutputJoinRequestV1> {
        Ok(NativeSecurityOutputJoinRequestV1::new(
            &self.operation,
            &self.observation,
            label,
            &self.outcome,
            &self.evaluation,
        )?)
    }

    fn join(
        &self,
        fixture: &Fixture,
        intent: &NativeSecurityOutputJoinRequestV1,
    ) -> TestResult<NativeSecurityOutputJoinRecordV1> {
        let store = fixture.authority.admission_operation_store();
        let port: &dyn AdmissionOperationStore = &store;
        Ok(port.join_native_security_output(
            &self.operation,
            &self.lease,
            &fixture.binding,
            intent,
            now_ms()?,
        )?)
    }
}

fn finalizing(fixture: &mut Fixture, egress: bool) -> TestResult<Finalizing> {
    finalizing_with_clearance(fixture, egress, InformationLabel::bottom())
}

fn finalizing_with_clearance(
    fixture: &mut Fixture,
    egress: bool,
    clearance: InformationLabel,
) -> TestResult<Finalizing> {
    let captured = run_capture_through_with_clearance(fixture, egress, clearance, |fixture| {
        Ok(fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?)
    })?;
    let store = fixture.authority.admission_operation_store();
    let outcomes = fixture.authority.tool_outcome_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_retained_tool_request(&captured.operation_id, &fence, now_ms()?)?
        .ok_or("captured operation missing")?;
    let initialized = store
        .load_security_participant_state(
            fixture.binding.security_authority_id(),
            &fence,
            now_ms()?,
        )?
        .ok_or("native initialization missing")?;
    let key = crate::security::adapters::flow_key(fixture.context.as_v1());
    let observation =
        store.observe_security_participant_flow(&fixture.binding, &key, &fence, now_ms()?)?;
    // Test the physical writer with the same claimant through the store's real
    // lease verifier. Reading its identifier does not construct a lease or
    // recreate the kernel's consumed live release owner.
    let claimant: String =
        rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?.query_row(
            "SELECT recovery_claimant_id FROM admission_operations WHERE operation_id = ?1",
            [captured.operation_id.as_str()],
            |row| row.get(0),
        )?;
    let claimant = AdmissionIdentifier::try_new("claimant", claimant)?;
    let now = now_ms()?;
    let stale_lease = store.claim_recovery(
        &captured.operation_id,
        operation.version(),
        &claimant,
        now,
        now + 60_000,
        &fence,
    )?;
    let context = SecurityInvocationContext::v1(
        fixture.context.as_v1().clone().with_flow_state_generation(
            observation
                .stored_context_generation()
                .ok_or("joined context absent")?,
        ),
    );
    let (blob, outcome) = test_support::native_returned_value(
        &operation,
        fence.clone(),
        now_ms()?,
        &fixture.request,
        &context,
        serde_json::json!({"private": "returned secret"}),
    )?;
    let (outcome, operation) = outcomes
        .record_tool_returned(&operation, &stale_lease, &blob, &outcome, &fence, now_ms()?)?
        .into_parts();
    let now = now_ms()?;
    let lease = store.claim_recovery(
        &captured.operation_id,
        operation.version(),
        &claimant,
        now,
        now + 60_000,
        &fence,
    )?;
    let prepared = test_support::prepared_evaluation(&operation, &outcome, now_ms()?)?;
    outcomes.begin_post_return_evaluation(&lease, &prepared, &fence, now_ms()?)?;
    let pure = test_support::record_pure_step(&prepared)?;
    outcomes.stage_post_return_evaluation(
        &captured.operation_id,
        prepared.version(),
        &lease,
        &pure,
        &fence,
        now_ms()?,
    )?;
    let external = test_support::record_external_step(&pure, now_ms()?)?;
    outcomes.stage_post_return_evaluation(
        &captured.operation_id,
        pure.version(),
        &lease,
        &external,
        &fence,
        now_ms()?,
    )?;
    let (evaluation, resolved, blob) = test_support::resolve_with_blob(
        &outcome,
        &external,
        SettlementDispositionV1::NotApplicable,
    )?;
    outcomes.finalize_post_return(
        &captured.operation_id,
        external.version(),
        &lease,
        &evaluation,
        outcome.version(),
        &resolved,
        Some(&blob),
        &fence,
        now_ms()?,
    )?;
    Ok(Finalizing {
        operation,
        lease,
        stale_lease,
        initialized,
        observation,
        outcome: resolved,
        evaluation,
    })
}

fn counts(fixture: &Fixture) -> TestResult<(i64, i64, i64)> {
    let connection = rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?;
    Ok(connection.query_row("SELECT (SELECT COUNT(*) FROM security_participant_output_events),
        (SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'security_participant_output'),
        (SELECT COUNT(*) FROM tool_outcome_security_releases)", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?)
}

fn input_history(fixture: &Fixture) -> TestResult<Vec<Vec<u8>>> {
    let connection = rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?;
    let mut statement = connection.prepare(
        "SELECT canonical_record FROM security_participant_state_mutations ORDER BY sequence",
    )?;
    let records = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(records)
}

fn reopen(fixture: Fixture, expected: &NativeSecurityOutputJoinRecordV1) -> TestResult {
    let Fixture {
        kernel,
        authority,
        _directory,
        ..
    } = fixture;
    drop(kernel);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(
        _directory.path().join("admission.db"),
        _directory.path().join("locks"),
    )?;
    let store = authority.admission_operation_store();
    let port: &dyn AdmissionOperationStore = &store;
    let (current, history) = port
        .load_native_security_output_join(
            &expected.join.operation_id,
            &authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("reopened output operation absent")?;
    assert_eq!(current.state(), AdmissionOperationState::Finalizing);
    assert_eq!(history.as_ref(), Some(expected));
    assert_eq!(
        store.load_security_participant_output(
            &expected.join.operation_id,
            &authority.mutation_fence(),
            now_ms()?
        )?,
        Some(expected.clone())
    );
    assert_eq!(
        store
            .load_by_operation_id(&expected.join.operation_id)?
            .ok_or("reopened operation")?
            .state(),
        AdmissionOperationState::Finalizing
    );
    Ok(())
}

#[test]
fn native_output_journal_propagates_taint_once_without_releasing_or_rewriting_input() -> TestResult
{
    for egress in [false, true] {
        let mut fixture = super::super::super::public_fixture()?;
        let finalizing = finalizing(&mut fixture, egress)?;
        let before = input_history(&fixture)?;
        let label = super::super::super::restricted_label();
        let intent = finalizing.intent(label.clone())?;
        let output = finalizing.join(&fixture, &intent)?;
        intent.validate_resolution(&output.join.command, &output.join.snapshot)?;
        for current in [
            &output.join.snapshot.principal_label,
            &output.join.snapshot.lineage_label,
            &output.join.snapshot.session_label,
        ] {
            assert_eq!(current, &label);
        }
        assert_eq!(finalizing.join(&fixture, &intent)?, output);
        assert!(finalizing
            .join(&fixture, &finalizing.intent(InformationLabel::bottom())?)
            .is_err());
        assert_eq!(counts(&fixture)?, (1, 1, 0));
        let connection =
            rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?;
        connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
        for sql in [
            "UPDATE security_participant_output_events SET sequence = sequence",
            "DELETE FROM security_participant_output_events",
            "INSERT OR REPLACE INTO security_participant_output_events SELECT * FROM security_participant_output_events",
        ] {
            assert!(connection.execute_batch(sql).is_err(), "{sql}");
        }
        drop(connection);
        assert_eq!(input_history(&fixture)?, before);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        reopen(fixture, &output)?;
    }
    Ok(())
}

#[test]
fn native_output_journal_rejects_stale_lease_generation_and_substituted_artifacts() -> TestResult {
    let mut fixture = super::super::super::public_fixture()?;
    let finalizing = finalizing(&mut fixture, true)?;
    let intent = finalizing.intent(InformationLabel::bottom())?;
    let store = fixture.authority.admission_operation_store();
    let port: &dyn AdmissionOperationStore = &store;
    let fence = fixture.authority.mutation_fence();
    assert!(port
        .load_native_security_output_join(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                chio_core::sha256_hex(b"absent-native-output")
            )?,
            &fence,
            now_ms()?,
        )?
        .is_none());
    assert_eq!(
        port.load_native_security_output_join(intent.operation_id(), &fence, now_ms()?,)?,
        Some((finalizing.operation.clone(), None))
    );
    for field in [
        "store_uuid",
        "security_authority_id",
        "initialization_digest",
    ] {
        let mut changed = serde_json::to_value(&fixture.binding)?;
        changed[field] = "b".repeat(64).into();
        let changed = serde_json::from_value(changed)?;
        assert!(
            port.join_native_security_output(
                &finalizing.operation,
                &finalizing.lease,
                &changed,
                &intent,
                now_ms()?,
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(store
        .join_security_participant_output(
            &finalizing.operation,
            &finalizing.stale_lease,
            &finalizing.initialized,
            &intent,
            now_ms()?
        )
        .is_err());
    for field in ["operation_id", "outcome_digest", "evaluation_digest"] {
        let mut changed = serde_json::to_value(&intent)?;
        changed[field] = "a".repeat(64).into();
        let changed = serde_json::from_value(changed)?;
        assert!(finalizing.join(&fixture, &changed).is_err(), "{field}");
    }
    let mut snapshot = finalizing
        .observation
        .snapshot()
        .ok_or("current snapshot")?
        .clone();
    snapshot.context_generation += 1;
    let observation = chio_kernel::admission_operation::NativeSecurityFlowObservationV1::new(
        fixture.binding.clone(),
        snapshot.key.clone(),
        Some(snapshot.clone()),
        Some(snapshot.context_generation),
        now_ms()?,
    )?;
    let stale = NativeSecurityOutputJoinRequestV1::new(
        &finalizing.operation,
        &observation,
        InformationLabel::bottom(),
        &finalizing.outcome,
        &finalizing.evaluation,
    )?;
    assert!(finalizing.join(&fixture, &stale).is_err());
    assert_eq!(counts(&fixture)?, (0, 0, 0));
    let output = finalizing.join(&fixture, &intent)?;
    assert_eq!(counts(&fixture)?, (1, 1, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(store);
    reopen(fixture, &output)
}

#[test]
fn native_output_journal_inherits_all_current_labels_when_output_is_public() -> TestResult {
    let label = super::super::super::restricted_label();
    let mut fixture =
        Fixture::new_with_seed(std::array::from_fn(|_| InformationLabel::bottom()), |key| {
            Ok(Some(FlowJoinRequest {
                key: key.clone(),
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: label.clone(),
                transition_id: RecordId::new("output-inherited-session")?,
            }))
        })?;
    let finalizing = finalizing_with_clearance(&mut fixture, false, label.clone())?;
    let before = finalizing
        .observation
        .snapshot()
        .ok_or("inherited input snapshot")?;
    assert_eq!(before.principal_label, label);
    assert_eq!(before.lineage_label, label);
    assert_eq!(before.session_label, label);
    let intent = finalizing.intent(InformationLabel::bottom())?;
    let output = finalizing.join(&fixture, &intent)?;
    assert_eq!(output.join.snapshot.principal_label, label);
    assert_eq!(output.join.snapshot.lineage_label, label);
    assert_eq!(output.join.snapshot.session_label, label);
    assert_eq!(counts(&fixture)?, (1, 1, 0));
    reopen(fixture, &output)
}
