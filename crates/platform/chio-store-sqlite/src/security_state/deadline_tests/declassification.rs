use super::*;
use chio_security_types::ports::PortErrorKind;

#[test]
fn fresh_declassification_denies_expiry_during_sqlite_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.store.seal_declassification_live_dispatch()?;
    let consumption = participant_source::declassification_consumption_fixture("grant")?;
    assert_kind(
        fixture.after_database_wait(false, 2_000, |store| {
            store.commit_declassification_consumption_evidence(&consumption)
        })?,
        PortErrorKind::Conflict,
    );
    assert!(fixture
        .store
        .load_declassification_use(&DeclassificationUseQuery {
            tenant_id: consumption.consumption.tenant_id,
            grant_id: consumption.consumption.grant_id,
        })?
        .is_none());
    assert_eq!(fixture.store.count_pending_declassification_evidence()?, 0);
    Ok(())
}

#[test]
fn fresh_declassification_denies_unavailable_clock_after_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.store.seal_declassification_live_dispatch()?;
    let consumption = participant_source::declassification_consumption_fixture("grant")?;
    assert_kind(
        fixture.after_database_wait(false, u64::MAX, |store| {
            store.commit_declassification_consumption_evidence(&consumption)
        })?,
        PortErrorKind::Unavailable,
    );
    assert_eq!(fixture.store.count_pending_declassification_evidence()?, 0);
    Ok(())
}

#[test]
fn exact_declassification_history_survives_expiry_and_unavailable_clock() -> TestResult {
    for now in [2_000, u64::MAX] {
        let fixture = Fixture::new()?;
        fixture.store.seal_declassification_live_dispatch()?;
        let consumption = participant_source::declassification_consumption_fixture("grant")?;
        assert_eq!(
            fixture
                .store
                .commit_declassification_consumption_evidence(&consumption)?,
            DeclassificationConsume::Consumed
        );
        let outcome = participant_source::declassification_outcome_fixture(&consumption)?;
        fixture
            .store
            .commit_declassification_outcome_evidence(&outcome)?;
        assert_eq!(
            fixture.after_database_wait(false, now, |store| store
                .commit_declassification_consumption_evidence(&consumption))??,
            DeclassificationConsume::AlreadyConsumed {
                request_hash: consumption.consumption.request_hash,
                state: DeclassificationUseState::Released
            }
        );
        fixture
            .store
            .commit_declassification_outcome_evidence(&outcome)?;
        assert_eq!(fixture.store.count_pending_declassification_evidence()?, 2);
    }
    Ok(())
}

#[test]
fn live_declassification_can_be_consumed_just_before_expiry() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.store.seal_declassification_live_dispatch()?;
    let consumption = participant_source::declassification_consumption_fixture("grant")?;
    assert_eq!(
        fixture.after_database_wait(false, 1_999, |store| store
            .commit_declassification_consumption_evidence(&consumption))??,
        DeclassificationConsume::Consumed,
    );
    Ok(())
}

#[test]
fn fresh_declassification_bounds_receipt_time_skew_after_write_wait() -> TestResult {
    for now in [6_000, 6_001] {
        let fixture = Fixture::new()?;
        fixture.store.seal_declassification_live_dispatch()?;
        let mut consumption = participant_source::declassification_consumption_fixture("grant")?;
        consumption.consumption.grant_expires_at_unix_ms = 10_000;
        let result = fixture.after_database_wait(false, now, |store| {
            store.commit_declassification_consumption_evidence(&consumption)
        })?;
        if now == 6_000 {
            assert_eq!(result?, DeclassificationConsume::Consumed);
        } else {
            assert_kind(result, PortErrorKind::InvalidData);
            assert_eq!(fixture.store.count_pending_declassification_evidence()?, 0);
        }
    }
    Ok(())
}
