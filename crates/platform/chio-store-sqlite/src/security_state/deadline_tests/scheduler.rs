use super::*;
use chio_security_types::ports::PortErrorKind;

#[test]
fn scheduler_identity_denies_expiry_during_read_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let work = fixture
        .store
        .claim_due(&fixture.scheduler_request()?)?
        .remove(0);
    assert_kind(
        fixture.after_database_wait(true, 1_500, |store| {
            store.validate_lease_identity(
                &work.tenant_id,
                &work.action_id,
                &work.lease_owner_id,
                work.fencing_token,
            )
        })?,
        PortErrorKind::Conflict,
    );
    Ok(())
}

#[test]
fn scheduler_claim_retry_denies_expiry_during_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.scheduler_request()?;
    let work = fixture.store.claim_due(&request)?.remove(0);
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.claim_due(&request))?,
        PortErrorKind::Conflict,
    );
    assert_eq!(
        load_scheduler_lease(
            &*fixture.store.connection()?,
            &SchedulerWorkKey {
                tenant_id: work.tenant_id.clone(),
                action_id: work.action_id.clone()
            }
        )?,
        Some(work)
    );
    Ok(())
}

#[test]
fn scheduler_retry_denies_expiry_during_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let work = fixture
        .store
        .claim_due(&fixture.scheduler_request()?)?
        .remove(0);
    let key = SchedulerWorkKey {
        tenant_id: work.tenant_id.clone(),
        action_id: work.action_id.clone(),
    };
    let retry = SchedulerRetryRequest {
        work,
        expected_attempts: 0,
        error_code: chio_security_types::ports::ErrorCode::new("transient")?,
        first_failure_at_unix_ms: 1_000,
        now_unix_ms: 1_000,
        not_before_unix_ms: 2_000,
        health_event_id: None,
        transition_id: RecordId::new("retry")?,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.record_retry(&retry))?,
        PortErrorKind::Conflict,
    );
    assert!(fixture.store.load_retry(&key)?.is_none());
    Ok(())
}

#[test]
fn scheduler_release_denies_expiry_during_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let work = fixture
        .store
        .claim_due(&fixture.scheduler_request()?)?
        .remove(0);
    let release = SchedulerLeaseReleaseRequest {
        work: work.clone(),
        clear_retry_state: true,
        transition_id: RecordId::new("release")?,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.release_lease(&release))?,
        PortErrorKind::Conflict,
    );
    assert_eq!(
        load_scheduler_lease(
            &*fixture.store.connection()?,
            &SchedulerWorkKey {
                tenant_id: work.tenant_id.clone(),
                action_id: work.action_id.clone()
            }
        )?,
        Some(work)
    );
    Ok(())
}

#[test]
fn effect_persistence_denies_expiry_during_write_wait() -> TestResult {
    let fixture = Fixture::new()?;
    let work = fixture
        .store
        .claim_due(&fixture.scheduler_request()?)?
        .remove(0);
    let body = b"{}";
    let mut hash = [0; 32];
    hash.copy_from_slice(sha256(body).as_ref());
    let effect = ResponseEffectRecord {
        tenant_id: work.tenant_id,
        action_id: work.action_id,
        effect_id: EffectId::new("effect")?,
        generation: 0,
        scheduler_lease_owner_id: work.lease_owner_id,
        scheduler_fencing_token: work.fencing_token,
        state: RecordId::new("applied")?,
        canonical_body: CanonicalBody::new(body.to_vec())?,
        body_hash: Digest32::new(hash),
        encrypted_rollback_ref: None,
    };
    assert_kind(
        fixture.after_database_wait(false, 1_500, |store| store.persist_effect(&effect))?,
        PortErrorKind::Conflict,
    );
    assert!(fixture
        .store
        .load_effect(&ResponseEffectKey {
            tenant_id: effect.tenant_id,
            effect_id: effect.effect_id
        })?
        .is_none());
    Ok(())
}
