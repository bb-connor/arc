use super::*;

#[test]
fn fresh_native_consumption_and_retry_bounds_fail_without_partial_writes() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        let state = ScopedMutation::native_for_test(&tx, A);
        state.seal_declassification_live_dispatch()?;
        let consumed = consumption("tenant", "grant")?;
        let before = equivalence::all_rows(&tx, Some(A))?;
        for observed in [Ok(2_000), Ok(u64::MAX), Err(PortError::unavailable())] {
            assert!(state
                .commit_declassification_consumption_evidence(&consumed, || observed)
                .is_err());
            assert_eq!(equivalence::all_rows(&tx, Some(A))?, before);
        }
        state.commit_declassification_consumption_evidence(&consumed, || Ok(1_999))?;
        let mut failed = retry(&consumed)?;
        let used = equivalence::all_rows(&tx, Some(A))?;
        failed.failed_at_unix_ms = u64::MAX;
        assert!(state
            .record_declassification_evidence_retry(&failed)
            .is_err());
        assert_eq!(equivalence::all_rows(&tx, Some(A))?, used);
        tx.execute("UPDATE security_participant_state_declassification_receipt_outbox SET attempts = ?1 WHERE security_authority_id = ?2", params![i64::from(u32::MAX), A])?;
        let exhausted = equivalence::all_rows(&tx, Some(A))?;
        assert_eq!(
            state.record_declassification_evidence_retry(&retry(&consumed)?),
            Err(PortError::integrity_failure())
        );
        assert_eq!(equivalence::all_rows(&tx, Some(A))?, exhausted);
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn colliding_use_evidence_and_transition_ids_are_independent_between_authorities() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        seed_lifecycle(&tx, B)?;
        let a = ScopedMutation::native_for_test(&tx, A);
        let b = ScopedMutation::native_for_test(&tx, B);
        let consumed = consumption("tenant", "shared")?;
        assert!(a
            .commit_declassification_consumption_evidence(&consumed, || Ok(1_000))
            .is_err());
        a.seal_declassification_live_dispatch()?;
        a.seal_declassification_live_dispatch()?;
        assert!(b
            .commit_declassification_consumption_evidence(&consumed, || Ok(1_000))
            .is_err());
        b.seal_declassification_live_dispatch()?;
        for state in [&a, &b] {
            assert_eq!(
                state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?,
                DeclassificationConsume::Consumed
            );
            assert_eq!(
                state.commit_declassification_consumption_evidence(&consumed, || panic!(
                    "exact replay must not read current time"
                ))?,
                DeclassificationConsume::AlreadyConsumed {
                    request_hash: consumed.consumption.request_hash,
                    state: DeclassificationUseState::ConsumedPendingDispatch
                }
            );
        }
        let mut conflict = consumed.clone();
        conflict.consumption.grant_expires_at_unix_ms += 1;
        assert!(a
            .commit_declassification_consumption_evidence(&conflict, || panic!(
                "conflict must not read time"
            ))
            .is_err());
        let outcome = release(&consumed)?;
        a.commit_declassification_outcome_evidence(&outcome)?;
        a.commit_declassification_outcome_evidence(&outcome)?;
        assert_eq!(outbox::count_stranded(a.reader())?, 0);
        assert_eq!(outbox::count_stranded(b.reader())?, 1);
        assert_eq!(outbox::stranded(b.reader(), 1)?.len(), 1);
        assert_eq!(outbox::count_pending(a.reader())?, 2);
        assert_eq!(outbox::count_pending(b.reader())?, 1);
        let missing = ScopedMutation::native_for_test(&tx, "missing");
        assert!(records::load_use(
            missing.reader(),
            &DeclassificationUseQuery {
                tenant_id: consumed.consumption.tenant_id.clone(),
                grant_id: consumed.consumption.grant_id.clone()
            }
        )?
        .is_none());
        assert!(missing
            .commit_declassification_consumption_evidence(&consumed, || panic!(
                "missing lifecycle must fail before clock"
            ))
            .is_err());
        assert!(missing
            .commit_declassification_outcome_evidence(&outcome)
            .is_err());
        for authority in [A, B] {
            verify_native_declassification_state(&tx, authority)?;
        }
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn predecessor_ack_retry_and_pending_selection_never_borrow_another_authority() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = consumption("tenant", "shared")?;
        let outcome = release(&consumed)?;
        for authority in [A, B] {
            seed_lifecycle(&tx, authority)?;
            let state = ScopedMutation::native_for_test(&tx, authority);
            state.seal_declassification_live_dispatch()?;
            state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
            state.commit_declassification_outcome_evidence(&outcome)?;
        }
        let a = ScopedMutation::native_for_test(&tx, A);
        let b = ScopedMutation::native_for_test(&tx, B);
        let consumption_ack = ack(
            &consumed.consumption.grant_id,
            &consumed.receipt,
            DeclassificationEvidencePhase::Consumption,
        );
        let outcome_ack = ack(
            &consumed.consumption.grant_id,
            &outcome.receipt,
            DeclassificationEvidencePhase::Outcome,
        );
        a.acknowledge_declassification_evidence(&consumption_ack)?;
        a.acknowledge_declassification_evidence(&consumption_ack)?;
        assert_eq!(
            b.acknowledge_declassification_evidence(&outcome_ack),
            Err(PortError::conflict())
        );
        let pending_a = records::pending(a.reader(), None, None, u64::MAX, 10)?;
        let pending_b = records::pending(b.reader(), None, None, u64::MAX, 10)?;
        assert_eq!(pending_a.len(), 1);
        assert_eq!(pending_a[0].phase, DeclassificationEvidencePhase::Outcome);
        assert_eq!(pending_b.len(), 1);
        assert_eq!(
            pending_b[0].phase,
            DeclassificationEvidencePhase::Consumption
        );
        let failed = retry(&consumed)?;
        let updated = b.record_declassification_evidence_retry(&failed)?;
        assert_eq!(updated.attempts, 1);
        assert!(updated.next_attempt_at_unix_ms > failed.failed_at_unix_ms);
        assert_eq!(
            b.record_declassification_evidence_retry(&failed),
            Err(PortError::conflict())
        );
        assert!(a.record_declassification_evidence_retry(&failed).is_err());
        assert!(records::pending(
            b.reader(),
            None,
            None,
            updated.next_attempt_at_unix_ms - 1,
            10
        )?
        .is_empty());
        assert_eq!(
            records::pending(
                b.reader(),
                Some(&consumed.consumption.tenant_id),
                Some(&consumed.consumption.grant_id),
                updated.next_attempt_at_unix_ms,
                10
            )?
            .len(),
            2
        );
        let mut invalid_ack = consumption_ack.clone();
        invalid_ack.durable_sink_record_hash = Digest32::new([0; 32]);
        assert!(b
            .acknowledge_declassification_evidence(&invalid_ack)
            .is_err());
        b.acknowledge_declassification_evidence(&consumption_ack)?;
        b.acknowledge_declassification_evidence(&outcome_ack)?;
        assert_eq!(outbox::count_pending(b.reader())?, 0);
        assert_eq!(outbox::count_pending(a.reader())?, 1);
        for authority in [A, B] {
            verify_native_declassification_state(&tx, authority)?;
        }
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn batch_fairness_is_per_tenant_within_only_the_selected_authority() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for authority in [A, B] {
            seed_lifecycle(&tx, authority)?;
            let state = ScopedMutation::native_for_test(&tx, authority);
            state.seal_declassification_live_dispatch()?;
            for (tenant, grant) in [
                ("tenant-a", "one"),
                ("tenant-a", "two"),
                ("tenant-b", "one"),
            ] {
                state.commit_declassification_consumption_evidence(
                    &consumption(tenant, grant)?,
                    || Ok(1_000),
                )?;
            }
            let batch = records::pending(state.reader(), None, None, 1_000, 2)?;
            assert_eq!(batch.len(), 2);
            assert_ne!(batch[0].tenant_id, batch[1].tenant_id);
            assert_eq!(outbox::count_stranded(state.reader())?, 3);
            assert_eq!(outbox::count_pending(state.reader())?, 3);
            assert_eq!(outbox::stranded(state.reader(), 2)?.len(), 2);
            assert!(records::pending(state.reader(), None, None, 1_000, 0).is_err());
            assert!(
                outbox::stranded(state.reader(), MAX_DECLASSIFICATION_EVIDENCE_BATCH + 1).is_err()
            );
        }
        tx.rollback()?;
        Ok(())
    })
}
