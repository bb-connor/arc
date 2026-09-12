use super::*;
use rusqlite::types::Value;

#[test]
fn missing_native_schema_does_not_fall_back_to_legacy_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
    let connection = store.connection()?;
    let query = evidence_query(
        &consumption("tenant", "grant")?,
        DeclassificationEvidencePhase::Consumption,
    );
    assert!(records::load_evidence(ScopedReader::native(&connection, A), &query).is_err());
    assert!(records::load_evidence(ScopedReader::legacy(&connection), &query)?.is_none());
    assert!(verify_native_declassification_state(&connection, A).is_err());
    Ok(())
}

pub(super) fn all_rows(
    connection: &Connection,
    authority: Option<&str>,
) -> TestResult<Vec<Vec<Vec<Value>>>> {
    [
        "declassification_lifecycle",
        "declassification_uses",
        "declassification_receipt_outbox",
        "declassification_evidence_identity",
        "declassification_tombstones",
    ]
    .into_iter()
    .map(|suffix| {
        let source = format!("security_{suffix}");
        let fields = retained_security_columns(&source)?;
        let columns = fields.join(",");
        let (table, predicate) = match authority {
            Some(_) => (
                format!("security_participant_state_{suffix}"),
                " WHERE security_authority_id = ?1",
            ),
            None => (source, ""),
        };
        let mut statement = connection.prepare(&format!(
            "SELECT {columns} FROM {table}{predicate} ORDER BY {columns}"
        ))?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(authority), |row| {
                (0..fields.len())
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .collect()
}

#[test]
fn native_and_legacy_declassification_mutations_preserve_identical_retained_cells() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let directory = tempfile::tempdir()?;
        let legacy = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
        let mut legacy_connection = legacy.connection()?;
        let owner = SecurityStateWriteTransaction::new(
            legacy_connection.transaction_with_behavior(TransactionBehavior::Immediate)?,
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        let native = ScopedMutation::native_for_test(&tx, A);
        let legacy = ScopedMutation::legacy(owner.transaction());
        for state in [&native, &legacy] {
            state.begin_declassification_reconciliation()?;
            state.end_declassification_reconciliation()?;
            state.seal_declassification_live_dispatch()?;
        }
        for grant in ["pending", "terminal", "compacted"] {
            let consumed = consumption("tenant", grant)?;
            for state in [&native, &legacy] {
                state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
                state.record_declassification_evidence_retry(&retry(&consumed)?)?;
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
            if grant == "pending" {
                continue;
            }
            let outcome = release(&consumed)?;
            for state in [&native, &legacy] {
                state.commit_declassification_outcome_evidence(&outcome)?;
                for (phase, receipt) in [
                    (
                        DeclassificationEvidencePhase::Consumption,
                        &consumed.receipt,
                    ),
                    (DeclassificationEvidencePhase::Outcome, &outcome.receipt),
                ] {
                    state.acknowledge_declassification_evidence(&ack(
                        &consumed.consumption.grant_id,
                        receipt,
                        phase,
                    ))?;
                }
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
            if grant == "compacted" {
                let request = compaction_request(&consumed, &outcome)?;
                assert_eq!(
                    native.compact_declassification_evidence(&request)?,
                    legacy.compact_declassification_evidence(&request)?
                );
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
        }
        assert!(all_rows(&tx, Some(B))?.iter().all(Vec::is_empty));
        integrity::verify(native.reader())?;
        integrity::verify(legacy.reader())?;
        owner.into_transaction().rollback()?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn native_declassification_row_commands_match_shared_semantics_and_reject_substitution(
) -> TestResult {
    use crate::security_state::native_declassification::{
        consumption_changes, NativeDeclassificationOutcome,
    };
    use rusqlite::types::ValueRef;
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        let state = ScopedMutation::native_for_test(&tx, A);
        state.seal_declassification_live_dispatch()?;
        let consumed = consumption("tenant", "owned-grant")?;
        state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
        let assert_physical = |changes: &[crate::security_state::NativeRowChange]| -> TestResult {
            let rows = all_rows(&tx, Some(A))?;
            for change in changes {
                let index = match change.table.as_str() {
                    "security_declassification_uses" => 1,
                    "security_declassification_receipt_outbox" => 2,
                    "security_declassification_evidence_identity" => 3,
                    _ => return Err("unexpected native use table".into()),
                };
                let encoded = rows[index]
                    .iter()
                    .map(|row| {
                        let values = row.iter().map(ValueRef::from).collect::<Vec<_>>();
                        encode_retained_security_values(&change.table, &values)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                assert_eq!(
                    encoded
                        .iter()
                        .filter(|row| change
                            .after
                            .as_ref()
                            .is_some_and(|after| after.as_bytes() == row.as_slice()))
                        .count(),
                    1
                );
            }
            Ok(())
        };
        let pending = consumption_changes(&consumed)?;
        assert_physical(&pending)?;
        let command = NativeDeclassificationOutcome {
            consumption: consumed.clone(),
            outcome: release(&consumed)?,
        };
        state.commit_declassification_outcome_evidence(&command.outcome)?;
        let changes = command.changes()?;
        assert_eq!(changes[0].before, pending[0].after);
        assert_physical(&changes)?;
        command.validate_changes(&changes)?;
        let other_consumption = consumption("tenant", "another-owned-grant")?;
        let other_changes = NativeDeclassificationOutcome {
            outcome: release(&other_consumption)?,
            consumption: other_consumption,
        }
        .changes()?;
        for index in 0..changes.len() {
            let mut missing = changes.clone();
            missing.remove(index);
            assert!(command.validate_changes(&missing).is_err());
            let mut substituted = changes[index].clone();
            // A well-formed canonical row from another grant is not this use.
            substituted.after = other_changes[index].after.clone();
            assert!(command.validate_change(&substituted).is_err());
            if changes[index].before.is_some() {
                let mut substituted = changes[index].clone();
                substituted.before = other_changes[index].before.clone();
                assert!(command.validate_change(&substituted).is_err());
            }
        }
        let mut duplicate = changes.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(command.validate_changes(&duplicate).is_err());
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn native_declassification_egress_observation_enforces_both_issuer_time_bounds() -> TestResult {
    use chio_core::{DeclassificationPurpose, Keypair, SignedDeclassificationGrant};
    use chio_security_types::ports::{DestinationId, IsolationEpochId, LineageId, SessionId};
    use chio_security_types::{
        DeclassificationGrantBody, DeclassificationGrantClaims, PrincipalId,
    };
    let mut consumed = consumption("tenant", "time-bound-grant")?;
    let key = FlowStateKey {
        tenant_id: consumed.consumption.tenant_id.clone(),
        principal_id: PrincipalId::new("principal")?,
        lineage_id: LineageId::new("lineage")?,
        session_id: SessionId::new("session")?,
        isolation_epoch_id: IsolationEpochId::new("epoch")?,
    };
    let signed = SignedDeclassificationGrant::sign(
        DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: consumed.consumption.grant_id.clone(),
            capability_id: RecordId::new("capability")?,
            tenant_id: key.tenant_id.clone(),
            subject_id: key.principal_id.clone(),
            agent_id: RecordId::new("agent")?,
            session_id: key.session_id.clone(),
            source_label_hash: Digest32::new([2; 32]),
            target_label: InformationLabel::bottom(),
            destination_id: DestinationId::new("destination")?,
            tool_name: RecordId::new("tool")?,
            purpose: DeclassificationPurpose::new("purpose")?,
            request_hash: consumed.consumption.request_hash,
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 2,
            authority_key_id: RecordId::new("authority-key")?,
        })?,
        &Keypair::generate(),
    )?;
    let ActiveDefenseReceiptBody::DeclassificationConsumption(mut body) =
        decode_declassification_receipt(&consumed.receipt).map_err(|()| "fixture receipt")?
    else {
        return Err("fixture is not consumption".into());
    };
    body.grant_hash = Digest32::new(
        *chio_core::hashing::sha256(&chio_core::canonical_json_bytes(&signed)?).as_bytes(),
    );
    consumed.receipt = receipt(&ActiveDefenseReceiptBody::DeclassificationConsumption(body))?;
    let DeclassificationTransitionBinding::Consumption { request_id, .. } =
        &consumed.transition_binding
    else {
        return Err("fixture binding is not consumption".into());
    };
    let fence =
        crate::security_state::flow_state::planned_native_egress_fence(&EgressFenceRequest {
            key,
            request_id: request_id.clone(),
            request_hash: consumed.consumption.request_hash,
            expected_context_generation: 1,
            expires_at_unix_ms: 3_000,
        })?;
    let command = crate::security_state::NativeEgressCommand::declassified(
        EgressFenceCommit {
            fence,
            dispatch_commitment_id: RecordId::new("dispatch")?,
            committed_at_unix_ms: 1_000,
        },
        consumed,
        &signed,
    )?;
    // The consumption and commitment timestamps are otherwise within allowed
    // clock skew. Neither may pull the issuer's start time into the future.
    assert!(command.validate_observation(999).is_err());
    command.validate_observation(1_000)?;
    command.validate_observation(1_999)?;
    assert!(command.validate_observation(2_000).is_err());
    Ok(())
}

#[test]
fn native_flow_use_and_evidence_rollback_together_after_each_late_write_failure() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        for failing_phase in ["consumption", "outcome", "cancel"] {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            seed_lifecycle(&tx, A)?;
            let state = ScopedMutation::native_for_test(&tx, A);
            state.seal_declassification_live_dispatch()?;
            let consumed = consumption("tenant", "grant")?;
            // The trigger and all test-only native mutations share the rollback.
            tx.execute_batch(&format!("CREATE TRIGGER fail_native_outbox BEFORE INSERT ON security_participant_state_declassification_receipt_outbox WHEN NEW.phase = '{failing_phase}' BEGIN SELECT RAISE(ABORT, 'late evidence failure'); END;"))?;
            let join = FlowJoinRequest {
                key: FlowStateKey {
                    tenant_id: TenantId::new("tenant")?,
                    principal_id: chio_security_types::PrincipalId::new("principal")?,
                    lineage_id: chio_security_types::ports::LineageId::new("lineage")?,
                    session_id: chio_security_types::ports::SessionId::new("session")?,
                    isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch")?,
                },
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("join")?,
            };
            state.join(&join)?;
            let result =
                state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000));
            if failing_phase == "consumption" {
                assert!(result.is_err());
            } else {
                result?;
                if failing_phase == "outcome" {
                    assert!(state
                        .commit_declassification_outcome_evidence(&release(&consumed)?)
                        .is_err());
                }
            }
            drop(tx);
            assert!(connection.is_autocommit());
            assert!(all_rows(connection, Some(A))?.iter().all(Vec::is_empty));
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM security_participant_state_flow_contexts",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0);
        }
        Ok(())
    })
}
