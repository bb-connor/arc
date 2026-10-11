use super::*;
use chio_security_types::ports::PortErrorKind;

#[test]
fn new_egress_commit_denies_expiry_during_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let fence = fixture
        .store
        .acquire_egress_fence(&fixture.flow_request()?)?;
    let commitment = EgressFenceCommit {
        fence,
        dispatch_commitment_id: RecordId::new("commit")?,
        committed_at_unix_ms: 1_000,
    };
    assert_kind(
        fixture
            .after_database_wait(false, 1_500, |store| store.commit_egress_fence(&commitment))?,
        PortErrorKind::Conflict,
    );
    let committed: bool = fixture.store.connection()?.query_row(
        "SELECT committed_at IS NOT NULL FROM security_egress_fences",
        [],
        |row| row.get(0),
    )?;
    assert!(!committed);
    Ok(())
}

#[test]
fn exact_committed_egress_replay_survives_expiry_and_unavailable_clock() -> TestResult {
    for now in [1_500, u64::MAX] {
        let fixture = Fixture::new()?;
        let fence = fixture
            .store
            .acquire_egress_fence(&fixture.flow_request()?)?;
        let commitment = EgressFenceCommit {
            fence,
            dispatch_commitment_id: RecordId::new("commit")?,
            committed_at_unix_ms: 1_000,
        };
        let committed = fixture.store.commit_egress_fence(&commitment)?;
        assert_eq!(
            fixture.after_database_wait(false, now, |store| store
                .commit_egress_fence(&commitment))??,
            committed
        );
        let conflicting = EgressFenceCommit {
            dispatch_commitment_id: RecordId::new("different-commit")?,
            ..commitment
        };
        assert_kind(
            fixture.store.commit_egress_fence(&conflicting),
            PortErrorKind::Conflict,
        );
    }
    Ok(())
}

#[test]
fn clock_failure_after_write_wait_leaves_no_new_egress_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.flow_request()?;
    assert_kind(
        fixture.after_database_wait(false, u64::MAX, |store| {
            store.acquire_egress_fence(&request)
        })?,
        PortErrorKind::Unavailable,
    );
    let count: i64 = fixture.store.connection()?.query_row(
        "SELECT count(*) FROM security_egress_fences",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
