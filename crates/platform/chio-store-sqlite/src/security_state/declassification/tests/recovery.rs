use super::*;

#[test]
fn recovery_requires_its_own_lifecycle_and_unknown_outcomes_are_never_compacted() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = consumption("tenant", "grant")?;
        for authority in [A, B] {
            seed_lifecycle(&tx, authority)?;
            let state = ScopedMutation::native_for_test(&tx, authority);
            state.seal_declassification_live_dispatch()?;
            state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
        }
        let a = ScopedMutation::native_for_test(&tx, A);
        let b = ScopedMutation::native_for_test(&tx, B);
        let recovery = rebind_outcome(
            release(&consumed)?,
            DeclassificationTransitionBinding::RecoveryOutcomeUnknown {
                tenant_id: consumed.consumption.tenant_id.clone(),
                grant_id: consumed.consumption.grant_id.clone(),
                request_hash: consumed.consumption.request_hash,
                predecessor_evidence_id: consumed.receipt.evidence_id.clone(),
                predecessor_transition_id: consumed.receipt.transition_id.clone(),
            },
        )?;
        assert!(a.begin_declassification_reconciliation().is_err());
        a.reset_declassification_lifecycle()?;
        a.begin_declassification_reconciliation()?;
        assert!(a.begin_declassification_reconciliation().is_err());
        assert!(a.seal_declassification_live_dispatch().is_err());
        assert!(b
            .commit_declassification_outcome_evidence(&recovery)
            .is_err());
        assert!(a
            .commit_declassification_outcome_evidence(&release(&consumed)?)
            .is_err());
        a.commit_declassification_outcome_evidence(&recovery)?;
        a.commit_declassification_outcome_evidence(&recovery)?;
        a.end_declassification_reconciliation()?;
        assert!(a.end_declassification_reconciliation().is_err());
        a.seal_declassification_live_dispatch()?;
        for (phase, receipt) in [
            (
                DeclassificationEvidencePhase::Consumption,
                &consumed.receipt,
            ),
            (DeclassificationEvidencePhase::Outcome, &recovery.receipt),
        ] {
            a.acknowledge_declassification_evidence(&ack(
                &consumed.consumption.grant_id,
                receipt,
                phase,
            ))?;
        }
        let request = compaction_request(&consumed, &recovery)?;
        assert_eq!(
            a.compact_declassification_evidence(&request),
            Err(PortError::invalid_data())
        );
        assert!(super::super::compaction::candidates(
            a.reader(),
            &DeclassificationCompactionQuery {
                readiness_cursor: request.readiness_cursor,
                now_unix_ms: request.compacted_at_unix_ms,
                after_tenant_id: None,
                after_grant_id: None,
                max_records: 10
            }
        )?
        .is_empty());
        assert_eq!(outbox::count_stranded(a.reader())?, 0);
        assert_eq!(outbox::count_stranded(b.reader())?, 1);
        for authority in [A, B] {
            verify_native_declassification_state(&tx, authority)?;
        }
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn initialized_native_state_rejects_mutations_without_changing_retained_history() -> TestResult {
    with_flow_sql_fixture(true, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = ScopedMutation::native_for_test(&tx, A);
        let before = equivalence::all_rows(&tx, Some(A))?;
        assert_eq!(
            state.begin_declassification_reconciliation(),
            Err(PortError::conflict())
        );
        // Exact lifecycle replay is a no-write result, not serving activation.
        state.seal_declassification_live_dispatch()?;
        assert_eq!(
            state.reset_declassification_lifecycle(),
            Err(PortError::conflict())
        );
        assert!(state.end_declassification_reconciliation().is_err());
        let consumed = participant_source::declassification_consumption_fixture("pending")?;
        let evidence = records::load_evidence(
            state.reader(),
            &evidence_query(&consumed, DeclassificationEvidencePhase::Consumption),
        )?
        .ok_or("missing imported consumption")?;
        assert!(!evidence.acknowledged);
        assert_eq!(
            state.acknowledge_declassification_evidence(&ack(
                &consumed.consumption.grant_id,
                &consumed.receipt,
                DeclassificationEvidencePhase::Consumption
            )),
            Err(PortError::conflict())
        );
        assert_eq!(
            state.record_declassification_evidence_retry(&retry(&consumed)?),
            Err(PortError::conflict())
        );
        assert!(matches!(
            state.commit_declassification_consumption_evidence(&consumed, || panic!(
                "history must not read clock"
            ))?,
            DeclassificationConsume::AlreadyConsumed { .. }
        ));
        assert_eq!(
            state.commit_declassification_consumption_evidence(
                &consumption("tenant", "new-grant")?,
                || Ok(1_000)
            ),
            Err(PortError::conflict())
        );
        assert!(state
            .commit_declassification_outcome_evidence(&release(&consumed)?)
            .is_err());
        assert_eq!(equivalence::all_rows(&tx, Some(A))?, before);
        verify_native_declassification_state(&tx, A)?;
        verify_native_declassification_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}
