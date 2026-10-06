use super::*;
use std::sync::Arc;

type Key = (String, String, DeclassificationEvidencePhase);

fn page(after: Option<&Key>, max_records: u32) -> TestResult<DeclassificationRetriedEvidenceQuery> {
    Ok(match after {
        None => DeclassificationRetriedEvidenceQuery {
            after_tenant_id: None,
            after_grant_id: None,
            after_phase: None,
            max_records,
        },
        Some((tenant, grant, phase)) => DeclassificationRetriedEvidenceQuery {
            after_tenant_id: Some(TenantId::new(tenant.as_str())?),
            after_grant_id: Some(GrantId::new(grant.as_str())?),
            after_phase: Some(*phase),
            max_records,
        },
    })
}

fn key(record: &DeclassificationEvidenceRecord) -> Key {
    (
        record.tenant_id.as_str().to_owned(),
        record.grant_id.as_str().to_owned(),
        record.phase,
    )
}

fn failed(
    consumed: &DeclassificationConsumptionEvidenceCommit,
    phase: DeclassificationEvidencePhase,
    receipt: &ReceiptAppendRequest,
) -> TestResult<DeclassificationEvidenceRetryRequest> {
    Ok(DeclassificationEvidenceRetryRequest {
        tenant_id: consumed.consumption.tenant_id.clone(),
        grant_id: consumed.consumption.grant_id.clone(),
        phase,
        evidence_id: receipt.evidence_id.clone(),
        body_hash: receipt.body_hash,
        transition_id: receipt.transition_id.clone(),
        failed_at_unix_ms: 10_000,
        error_code: ErrorCode::new("sink_unavailable")?,
    })
}

fn all_pages(reader: ScopedReader<'_>, max_records: u32) -> TestResult<Vec<Key>> {
    let mut keys: Vec<Key> = Vec::new();
    loop {
        let records = records::retried(reader, &page(keys.last(), max_records)?)?;
        let full = records.len() == usize::try_from(max_records)?;
        for record in &records {
            assert!(!record.acknowledged);
            assert!(record.attempts > 0);
            // Retried rows are selected while still in backoff.
            assert!(record.next_attempt_at_unix_ms > 10_000);
            keys.push(key(record));
        }
        if !full {
            return Ok(keys);
        }
    }
}

#[test]
fn retried_evidence_pages_in_key_order_over_only_failed_unacknowledged_rows() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for authority in [A, B] {
            seed_lifecycle(&tx, authority)?;
            ScopedMutation::native_for_test(&tx, authority)
                .seal_declassification_live_dispatch()?;
        }
        let a = ScopedMutation::native_for_test(&tx, A);
        let b = ScopedMutation::native_for_test(&tx, B);
        for (tenant, grant) in [
            ("tenant-b", "one"),
            ("tenant-a", "two"),
            ("tenant-a", "one"),
            ("tenant-a", "untried"),
            ("tenant-c", "delivered"),
        ] {
            let consumed = consumption(tenant, grant)?;
            a.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
            b.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
            match grant {
                "one" => {
                    a.record_declassification_evidence_retry(&failed(
                        &consumed,
                        DeclassificationEvidencePhase::Consumption,
                        &consumed.receipt,
                    )?)?;
                }
                "two" => {
                    let outcome = release(&consumed)?;
                    a.commit_declassification_outcome_evidence(&outcome)?;
                    a.acknowledge_declassification_evidence(&ack(
                        &consumed.consumption.grant_id,
                        &consumed.receipt,
                        DeclassificationEvidencePhase::Consumption,
                    ))?;
                    a.record_declassification_evidence_retry(&failed(
                        &consumed,
                        DeclassificationEvidencePhase::Outcome,
                        &outcome.receipt,
                    )?)?;
                }
                "delivered" => {
                    a.record_declassification_evidence_retry(&failed(
                        &consumed,
                        DeclassificationEvidencePhase::Consumption,
                        &consumed.receipt,
                    )?)?;
                    a.acknowledge_declassification_evidence(&ack(
                        &consumed.consumption.grant_id,
                        &consumed.receipt,
                        DeclassificationEvidencePhase::Consumption,
                    ))?;
                }
                _ => {}
            }
        }
        let expected: Vec<Key> = vec![
            (
                "tenant-a".to_owned(),
                "one".to_owned(),
                DeclassificationEvidencePhase::Consumption,
            ),
            (
                "tenant-a".to_owned(),
                "two".to_owned(),
                DeclassificationEvidencePhase::Outcome,
            ),
            (
                "tenant-b".to_owned(),
                "one".to_owned(),
                DeclassificationEvidencePhase::Consumption,
            ),
        ];
        for max_records in [1, 2, MAX_DECLASSIFICATION_EVIDENCE_BATCH] {
            assert_eq!(all_pages(a.reader(), max_records)?, expected);
        }
        let same_grant_consumption = (
            "tenant-a".to_owned(),
            "two".to_owned(),
            DeclassificationEvidencePhase::Consumption,
        );
        assert_eq!(
            records::retried(a.reader(), &page(Some(&same_grant_consumption), 10)?)?
                .iter()
                .map(key)
                .collect::<Vec<_>>(),
            expected[1..].to_vec()
        );
        assert!(records::retried(a.reader(), &page(expected.last(), 10)?)?.is_empty());
        assert!(records::retried(b.reader(), &page(None, 10)?)?.is_empty());
        assert_eq!(outbox::count_pending(b.reader())?, 5);
        for invalid in [
            page(None, 0)?,
            page(None, MAX_DECLASSIFICATION_EVIDENCE_BATCH + 1)?,
            DeclassificationRetriedEvidenceQuery {
                after_phase: None,
                ..page(expected.first(), 10)?
            },
            DeclassificationRetriedEvidenceQuery {
                after_tenant_id: None,
                ..page(expected.first(), 10)?
            },
        ] {
            assert_eq!(
                records::retried(a.reader(), &invalid),
                Err(PortError::invalid_data())
            );
        }
        tx.rollback()?;
        Ok(())
    })?;

    let directory = chio_test_support::private_tempdir()?;
    let store = SqliteSecurityStateStore::open_with_trusted_clock(
        directory.path().join("retried-declassification.sqlite"),
        Arc::new(chio_security_types::clock::FixedClock::from_millis(1_000)),
    )?;
    store.seal_declassification_live_dispatch()?;
    let consumed = consumption("tenant-a", "legacy")?;
    store.commit_declassification_consumption_evidence(&consumed)?;
    assert!(store
        .load_retried_declassification_evidence(&page(None, 10)?)?
        .is_empty());
    store.record_declassification_evidence_retry(&failed(
        &consumed,
        DeclassificationEvidencePhase::Consumption,
        &consumed.receipt,
    )?)?;
    let retried = store.load_retried_declassification_evidence(&page(None, 10)?)?;
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].attempts, 1);
    assert_eq!(
        retried[0].last_error_code.as_ref().map(ErrorCode::as_str),
        Some("sink_unavailable")
    );
    store.acknowledge_declassification_evidence(&ack(
        &consumed.consumption.grant_id,
        &consumed.receipt,
        DeclassificationEvidencePhase::Consumption,
    ))?;
    assert!(store
        .load_retried_declassification_evidence(&page(None, 10)?)?
        .is_empty());
    Ok(())
}
