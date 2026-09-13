use super::*;
use rusqlite::types::Value;

struct FixedClock;
impl SecurityStateClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(1_000)
    }
}

fn rows(
    connection: &Connection,
    suffix: &str,
    authority: Option<&str>,
) -> TestResult<Vec<Vec<Value>>> {
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
}

#[test]
fn native_and_legacy_domain_mutations_produce_identical_retained_cells() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let directory = tempfile::tempdir()?;
        let legacy = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
        let mut legacy_connection = legacy.connection()?;
        let mut owner = SecurityStateWriteTransaction::new(
            legacy_connection.transaction_with_behavior(TransactionBehavior::Immediate)?,
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let native = FlowMutation::native_for_test(&tx, A);
        let mut join = request("initial")?;
        join.principal_join = label("principal")?;
        join.lineage_join = label("lineage")?;
        join.session_join = label("session")?;
        for index in 0..3 {
            join.transition_id = RecordId::new(format!("join-{index}"))?;
            if index == 1 {
                join.key.session_id = SessionId::new("new-session")?;
            } else if index == 2 {
                join.key.lineage_id = LineageId::new("extended-lineage")?;
            }
            let native_snapshot = native.join(&join)?;
            let (next, legacy_snapshot) = owner.join(&join)?;
            owner = next;
            assert_eq!(native_snapshot, legacy_snapshot);
        }
        let transition = IsolationEpochTransition {
            tenant_id: join.key.tenant_id.clone(),
            principal_id: join.key.principal_id.clone(),
            lineage_id: join.key.lineage_id.clone(),
            previous_isolation_epoch_id: join.key.isolation_epoch_id.clone(),
            new_isolation_epoch_id: IsolationEpochId::new("new-epoch")?,
            new_session_id: SessionId::new("isolated-session")?,
            verification_evidence_hash: Digest32::new([7; 32]),
            transition_id: RecordId::new("isolation-transition")?,
            effective_at_unix_ms: 1_000,
        };
        let verified = VerifiedIsolationEvidence {
            verifier_id: RecordId::new("verifier")?,
            receipt_ref: OpaqueReceiptRef::new("receipt")?,
        };
        let snapshot = native.open_isolation_epoch(&transition, &verified)?;
        let (next, legacy_snapshot) = owner.open_isolation_epoch(&transition, &verified)?;
        owner = next;
        assert_eq!(snapshot, legacy_snapshot);
        let requested = fences::fence_request(&snapshot)?;
        let fence = native.acquire_egress_fence(&requested, || Ok(1_000))?;
        let (next, legacy_fence) = owner.acquire_egress_fence(&requested, &FixedClock)?;
        owner = next;
        assert_eq!(fence, legacy_fence);
        let commitment = EgressFenceCommit {
            fence,
            dispatch_commitment_id: RecordId::new("dispatch")?,
            committed_at_unix_ms: 1_000,
        };
        let committed = native.commit_egress_fence(&commitment, || Ok(1_000))?;
        let (owner, legacy_committed) = owner.commit_egress_fence(&commitment, &FixedClock)?;
        assert_eq!(committed, legacy_committed);
        for suffix in [
            "principal_flow_state",
            "lineage_flow_state",
            "session_flow_state",
            "session_memberships",
            "flow_contexts",
            "flow_sequences",
            "isolation_epochs",
            "egress_fences",
            "transitions",
        ] {
            assert_eq!(
                rows(&tx, suffix, Some(A))?,
                rows(owner.transaction(), suffix, None)?,
                "{suffix}"
            );
            assert!(rows(&tx, suffix, Some(B))?.is_empty(), "{suffix}");
        }
        owner.into_transaction().rollback()?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn absent_native_schema_never_falls_back_to_populated_legacy_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let legacy = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
    let join = request("initial")?;
    let expected = legacy.join(&join)?;
    let connection = legacy.connection()?;
    assert!(load_scoped_flow_snapshot(FlowReader::native(&connection, A), &join.key).is_err());
    assert_eq!(load_flow_snapshot(&connection, &join.key)?, Some(expected));
    Ok(())
}

#[test]
fn nonpositive_stored_generations_are_integrity_errors_in_both_scopes() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let directory = tempfile::tempdir()?;
        let legacy = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
        let mut legacy_connection = legacy.connection()?;
        for suffix in [
            "principal_flow_state",
            "lineage_flow_state",
            "session_flow_state",
            "flow_contexts",
        ] {
            for generation in [0, -1] {
                let legacy_tx =
                    legacy_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let join = request("initial")?;
                let (owner, _) = SecurityStateWriteTransaction::new(legacy_tx)?.join(&join)?;
                FlowMutation::native_for_test(&tx, A).join(&join)?;
                FlowMutation::native_for_test(&tx, B).join(&join)?;
                tx.execute(
                    &format!("UPDATE security_participant_state_{suffix} SET generation = ?1 WHERE security_authority_id = ?2"),
                    params![generation, A],
                )?;
                owner.transaction().execute(
                    &format!("UPDATE security_{suffix} SET generation = ?1"),
                    [generation],
                )?;
                assert_eq!(
                    load_scoped_flow_snapshot(FlowReader::native(&tx, A), &join.key),
                    Err(PortError::integrity_failure()),
                    "native {suffix}={generation}"
                );
                assert_eq!(
                    load_flow_snapshot(owner.transaction(), &join.key),
                    Err(PortError::integrity_failure()),
                    "legacy {suffix}={generation}"
                );
                verify_native_flow_state(&tx, B)?;
                owner.into_transaction().rollback()?;
                tx.rollback()?;
            }
        }
        Ok(())
    })
}
