use super::*;

#[test]
fn compaction_pages_and_permanent_spent_grants_remain_authority_scoped() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for authority in [A, B] {
            seed_lifecycle(&tx, authority)?;
            let state = ScopedMutation::native_for_test(&tx, authority);
            state.seal_declassification_live_dispatch()?;
            for grant in ["first", "second"] {
                terminal(&state, &consumption("tenant", grant)?)?;
            }
        }
        let a = ScopedMutation::native_for_test(&tx, A);
        let b = ScopedMutation::native_for_test(&tx, B);
        let consumed = consumption("tenant", "first")?;
        let request = compaction_request(&consumed, &release(&consumed)?)?;
        let mut query = DeclassificationCompactionQuery {
            readiness_cursor: request.readiness_cursor.clone(),
            now_unix_ms: request.compacted_at_unix_ms,
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        };
        let first = super::super::compaction::candidates(a.reader(), &query)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].use_record.grant_id.as_str(), "first");
        query.after_tenant_id = Some(consumed.consumption.tenant_id.clone());
        query.after_grant_id = Some(consumed.consumption.grant_id.clone());
        let second = super::super::compaction::candidates(a.reader(), &query)?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].use_record.grant_id.as_str(), "second");
        a.compact_declassification_evidence(&request)?;
        assert_eq!(
            a.commit_declassification_consumption_evidence(&consumed, || panic!(
                "spent grant cannot read time"
            )),
            Err(PortError::conflict())
        );
        assert!(matches!(
            b.commit_declassification_consumption_evidence(&consumed, || panic!(
                "historical retry cannot read time"
            ))?,
            DeclassificationConsume::AlreadyConsumed {
                state: DeclassificationUseState::Released,
                ..
            }
        ));
        assert!(records::load_evidence(
            a.reader(),
            &evidence_query(&consumed, DeclassificationEvidencePhase::Consumption)
        )?
        .is_none());
        assert!(records::load_evidence(
            b.reader(),
            &evidence_query(&consumed, DeclassificationEvidencePhase::Consumption)
        )?
        .is_some());
        for authority in [A, B] {
            verify_native_declassification_state(&tx, authority)?;
        }
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn compaction_refuses_canonical_but_inconsistent_grant_hash_without_deleting_evidence() -> TestResult
{
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        let state = ScopedMutation::native_for_test(&tx, A);
        state.seal_declassification_live_dispatch()?;
        let consumed = consumption("tenant", "grant")?;
        let mut outcome = terminal(&state, &consumed)?;
        let ActiveDefenseReceiptBody::DeclassificationOutcome(mut body) =
            decode_declassification_receipt(&outcome.receipt).map_err(|()| "bad fixture")?
        else {
            return Err("wrong receipt".into());
        };
        body.grant_hash = Digest32::new([99; 32]);
        outcome.receipt = receipt(&ActiveDefenseReceiptBody::DeclassificationOutcome(body))?;
        // Simulate corrupt retained cells, including a consistent identity digest.
        // The individual receipt still decodes and its canonical hash verifies.
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
        tx.execute("UPDATE security_participant_state_declassification_receipt_outbox SET canonical_body = ?1, body_hash = ?2, evidence_id = ?3 WHERE security_authority_id = ?4 AND phase = 'outcome'", params![outcome.receipt.canonical_body.as_bytes(), outcome.receipt.body_hash.as_bytes().as_slice(), outcome.receipt.evidence_id.as_str(), A])?;
        tx.execute("UPDATE security_participant_state_declassification_evidence_identity SET body_hash = ?1, evidence_id = ?2 WHERE security_authority_id = ?3 AND phase = 'outcome'", params![outcome.receipt.body_hash.as_bytes().as_slice(), outcome.receipt.evidence_id.as_str(), A])?;
        assert!(records::load_evidence(
            state.reader(),
            &evidence_query(&consumed, DeclassificationEvidencePhase::Outcome)
        )?
        .is_some());
        assert_eq!(
            integrity::verify(state.reader()),
            Err(PortError::integrity_failure())
        );
        assert_eq!(
            state.compact_declassification_evidence(&compaction_request(&consumed, &outcome)?),
            Err(PortError::conflict())
        );
        assert_eq!(
            state.query_row(sql::COUNT_EVIDENCE, &[], |row| row.get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            state.query_row(sql::COUNT_TOMBSTONES, &[], |row| row.get::<_, i64>(0))?,
            0
        );
        lifecycle::verify(state.reader())?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn identity_and_tombstone_integrity_joins_cannot_hide_missing_local_predecessors() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        for compacted in [false, true] {
            for phase in ["consumption", "outcome"] {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let consumed = consumption("tenant", "grant")?;
                for authority in [A, B] {
                    seed_lifecycle(&tx, authority)?;
                    let state = ScopedMutation::native_for_test(&tx, authority);
                    state.seal_declassification_live_dispatch()?;
                    let outcome = terminal(&state, &consumed)?;
                    if compacted {
                        state.compact_declassification_evidence(&compaction_request(
                            &consumed, &outcome,
                        )?)?;
                    }
                }
                // Wrong local identity must not match the intact colliding B row.
                tx.execute("UPDATE security_participant_state_declassification_evidence_identity SET body_hash = ?1 WHERE security_authority_id = ?2 AND phase = ?3", params![[99_u8; 32].as_slice(), A, phase])?;
                assert_eq!(
                    verify_native_declassification_state(&tx, A),
                    Err(PortError::integrity_failure())
                );
                verify_native_declassification_state(&tx, B)?;
                // Missing local identity exercises LEFT JOIN null detection as well.
                if !compacted {
                    assert_eq!(
                        ScopedMutation::native_for_test(&tx, A).compact_declassification_evidence(
                            &compaction_request(&consumed, &release(&consumed)?)?
                        ),
                        Err(PortError::integrity_failure())
                    );
                }
                // Defer the physical FK only inside this rollback-only corruption
                // fixture so the relational verifier sees the missing parent.
                tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
                tx.execute("DELETE FROM security_participant_state_declassification_evidence_identity WHERE security_authority_id = ?1 AND phase = ?2", params![A, phase])?;
                assert_eq!(
                    verify_native_declassification_state(&tx, A),
                    Err(PortError::integrity_failure())
                );
                verify_native_declassification_state(&tx, B)?;
                tx.rollback()?;
            }
        }
        Ok(())
    })
}
