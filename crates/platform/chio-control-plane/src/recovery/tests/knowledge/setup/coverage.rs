//! Required setup coverage commits the actual selected mediator inventory.
use super::*;

#[test]
fn setup_coverage_changes_when_an_enabled_artifact_recipient_is_added() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let receipt_key = f.f.kernel.receipt_signing_public_key();
    let previous = store.observe_setup_coverage(&actor, &receipt_key, &fence, now_ms()?)?;
    let mut profile = f.profile.clone();
    let mut recipients = profile.recipients.as_slice().to_vec();
    let mut added = recipients
        .first()
        .ok_or("installed artifact recipient")?
        .clone();
    added.recipient.recipient = ArtifactRecipientId::new("second-enabled-agent-recipient")?;
    recipients.push(added);
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    let _current = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.broker.clone(),
        profile,
        fence.clone(),
    )?;
    let current = store.observe_setup_coverage(&actor, &receipt_key, &fence, now_ms()?)?;
    assert_ne!(
        previous, current,
        "an additional enabled artifact path must change the authenticated required inventory"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}

#[test]
fn setup_coverage_observation_is_stable_effect_free_and_requires_live_inspection() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let receipt_key = f.f.kernel.receipt_signing_public_key();
    let records = || -> TestResult<Vec<(String, Vec<u8>)>> {
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let mut statement = connection.prepare("SELECT record_key,payload FROM admission_operation_recovery_records ORDER BY record_key")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let values = rows.collect::<Result<_, _>>()?;
        Ok(values)
    };
    let before = records()?;
    let expected = store.observe_setup_coverage(&actor, &receipt_key, &fence, now_ms()?)?;
    for _ in 0..3 {
        assert_eq!(
            store.observe_setup_coverage(&actor, &receipt_key, &fence, now_ms()?)?,
            expected
        );
    }
    assert_eq!(records()?, before);
    let reporter = f.actor(RecoveryPermission::Report)?;
    assert!(store
        .observe_setup_coverage(&reporter, &receipt_key, &fence, now_ms()?)
        .is_err());
    f.f.kernel.revoke_capability(&f.f.control.id)?;
    assert!(store
        .observe_setup_coverage(&actor, &receipt_key, &fence, now_ms()?)
        .is_err());
    assert_eq!(records()?, before);
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}
