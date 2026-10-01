use super::*;
use chio_security_types::ports::PortErrorKind;

#[test]
fn renewal_cannot_resurrect_lineage_fence_after_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let fence = LineageFenceStore::acquire(&fixture.store, &fixture.lineage_request()?)?;
    let renewal = LineageFenceRenewal {
        tenant_id: fence.tenant_id.clone(),
        action_id: fence.action_id.clone(),
        fencing_token: fence.fencing_token,
        scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: fence.scheduler_fencing_token,
        expected_expires_at_unix_ms: fence.expires_at_unix_ms,
        renewed_expires_at_unix_ms: 2_000,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| {
            LineageFenceStore::renew(store, &renewal)
        })?,
        PortErrorKind::Conflict,
    );
    assert_eq!(
        load_lineage_fence(&*fixture.store.connection()?, "tenant", "action")?,
        Some((fence, true))
    );
    Ok(())
}

#[test]
fn takeover_cannot_resurrect_lineage_fence_after_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let fence = LineageFenceStore::acquire(&fixture.store, &fixture.lineage_request()?)?;
    let takeover = LineageFenceTakeover {
        tenant_id: fence.tenant_id.clone(),
        action_id: fence.action_id.clone(),
        expected_fencing_token: fence.fencing_token,
        expected_scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
        expected_scheduler_fencing_token: fence.scheduler_fencing_token,
        expected_expires_at_unix_ms: fence.expires_at_unix_ms,
        successor_scheduler_lease_owner_id: LeaseOwnerId::new("successor")?,
        successor_scheduler_fencing_token: 2,
        successor_expires_at_unix_ms: 2_000,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| {
            LineageFenceStore::takeover(store, &takeover)
        })?,
        PortErrorKind::Conflict,
    );
    assert_eq!(
        load_lineage_fence(&*fixture.store.connection()?, "tenant", "action")?,
        Some((fence, true))
    );
    Ok(())
}

#[test]
fn stale_lineage_owner_cannot_release_after_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let fence = LineageFenceStore::acquire(&fixture.store, &fixture.lineage_request()?)?;
    let release = LineageFenceRelease {
        tenant_id: fence.tenant_id.clone(),
        action_id: fence.action_id.clone(),
        fencing_token: fence.fencing_token,
        scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: fence.scheduler_fencing_token,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| {
            LineageFenceStore::release(store, &release)
        })?,
        PortErrorKind::Conflict,
    );
    assert_eq!(
        load_lineage_fence(&*fixture.store.connection()?, "tenant", "action")?,
        Some((fence, true))
    );
    Ok(())
}
