use super::*;

struct FixedClock;

impl SecurityStateClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(1_000)
    }
}

#[test]
fn flow_use_and_receipt_outbox_share_one_outer_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(FixedClock))?;
    store.seal_declassification_live_dispatch()?;
    let observer = Connection::open(&path)?;
    let consumption = participant_source::declassification_consumption_fixture("grant")?;
    let outcome = participant_source::declassification_outcome_fixture(&consumption)?;
    let use_query = DeclassificationUseQuery {
        tenant_id: consumption.consumption.tenant_id.clone(),
        grant_id: consumption.consumption.grant_id.clone(),
    };
    let join = request("join")?;
    let mut connection = store.connection()?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (owner, snapshot) = SecurityStateWriteTransaction::new(tx)?.join(&join)?;
    let (owner, used) =
        owner.commit_declassification_consumption_evidence(&consumption, &FixedClock)?;
    assert_eq!(used, DeclassificationConsume::Consumed);
    assert!(load_flow_snapshot(&observer, &join.key)?.is_none());
    assert!(load_declassification_use_record(&observer, &use_query)?.is_none());
    let owner = owner.commit_declassification_outcome_evidence(&outcome)?;
    assert!(load_declassification_use_record(&observer, &use_query)?.is_none());
    owner.into_transaction().commit()?;
    assert_eq!(load_flow_snapshot(&observer, &join.key)?, Some(snapshot));
    let used =
        load_declassification_use_record(&observer, &use_query)?.ok_or("committed use absent")?;
    assert_eq!(used.state, DeclassificationUseState::Released);
    for phase in [
        DeclassificationEvidencePhase::Consumption,
        DeclassificationEvidencePhase::Outcome,
    ] {
        assert!(load_declassification_evidence_record(
            &observer,
            &DeclassificationEvidenceQuery {
                tenant_id: use_query.tenant_id.clone(),
                grant_id: use_query.grant_id.clone(),
                phase,
            }
        )?
        .is_some());
    }
    Ok(())
}

#[test]
fn outbox_failure_rolls_back_flow_use_and_any_earlier_evidence() -> TestResult {
    for failing_phase in ["consumption", "outcome"] {
        let directory = tempfile::tempdir()?;
        let store = SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("security.db"),
            Arc::new(FixedClock),
        )?;
        store.seal_declassification_live_dispatch()?;
        let consumption = participant_source::declassification_consumption_fixture("grant")?;
        let outcome = participant_source::declassification_outcome_fixture(&consumption)?;
        let join = request("join")?;
        let mut connection = store.connection()?;
        connection.execute_batch(&format!(
            "CREATE TRIGGER reject_evidence BEFORE INSERT ON security_declassification_receipt_outbox
             WHEN NEW.phase = '{failing_phase}' BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END;"
        ))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (owner, _) = SecurityStateWriteTransaction::new(tx)?.join(&join)?;
        let consumed =
            owner.commit_declassification_consumption_evidence(&consumption, &FixedClock);
        if failing_phase == "consumption" {
            assert!(consumed.is_err());
            drop(consumed);
        } else {
            let (owner, _) = consumed?;
            assert!(owner
                .commit_declassification_outcome_evidence(&outcome)
                .is_err());
        }
        assert!(connection.is_autocommit());
        assert!(load_flow_snapshot(&connection, &join.key)?.is_none());
        let uses: i64 = connection.query_row(
            "SELECT count(*) FROM security_declassification_uses",
            [],
            |row| row.get(0),
        )?;
        let evidence: i64 = connection.query_row(
            "SELECT count(*) FROM security_declassification_receipt_outbox",
            [],
            |row| row.get(0),
        )?;
        assert_eq!((uses, evidence), (0, 0));
    }
    Ok(())
}

#[test]
fn cancellation_after_consumption_rolls_back_flow_and_does_not_spend_grant() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open_with_trusted_clock(
        directory.path().join("security.db"),
        Arc::new(FixedClock),
    )?;
    store.seal_declassification_live_dispatch()?;
    let consumption = participant_source::declassification_consumption_fixture("grant")?;
    let join = request("join")?;
    {
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (owner, _) = SecurityStateWriteTransaction::new(tx)?.join(&join)?;
        let (owner, _) =
            owner.commit_declassification_consumption_evidence(&consumption, &FixedClock)?;
        drop(owner);
        assert!(connection.is_autocommit());
        assert!(load_flow_snapshot(&connection, &join.key)?.is_none());
    }
    assert_eq!(store.count_pending_declassification_evidence()?, 0);
    assert_eq!(
        store.commit_declassification_consumption_evidence(&consumption)?,
        DeclassificationConsume::Consumed
    );
    Ok(())
}

#[test]
fn cancelling_uncommitted_flow_does_not_reverse_committed_taint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("security.db"))?;
    let mut retained_join = request("retained-join")?;
    retained_join.principal_join = InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([chio_security_types::Compartment::new("retained")?]),
    )?;
    let retained = store.join(&retained_join)?;
    let mut pending = request("pending-join")?;
    pending.principal_join = InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([chio_security_types::Compartment::new("pending")?]),
    )?;
    {
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (owner, changed) = SecurityStateWriteTransaction::new(tx)?.join(&pending)?;
        assert_ne!(changed.principal_label, retained.principal_label);
        drop(owner);
    }
    assert_eq!(store.load(&retained.key)?, Some(retained));
    Ok(())
}
