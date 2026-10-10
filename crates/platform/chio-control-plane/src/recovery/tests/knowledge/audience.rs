//! Historical data remains decodable without granting operational Top clearance.
use super::*;

fn events(f: &KnowledgeFixture) -> TestResult<i64> {
    Ok(
        rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?,
    )
}

#[test]
fn artifacts_modeled_historical_top_actor_cannot_use_live_audience_ports() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("legacy-actor-audience", b"known-predecessor-content")?;
    let reference = f
        .runtime
        .publish(&f.f.control, &input, b"known-predecessor-content", None)?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let handle = f.runtime.handle(&f.f.control, &reference, &recipient)?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let (record, _) = store.prepare_artifact_read(&reader, &handle, &fence, now_ms()?)?;
    let seal = record.seal.as_ref().ok_or("finite control seal")?;
    let storage = f.broker.storage_usage(&f.profile.scope.process_id)?;
    let legacy = retain_recovery_fixture_legacy_top_actor(
        &store,
        &fence,
        &f.profile.scope,
        reader.principal(),
    )?;
    assert_eq!(
        legacy.actors.as_slice()[0].preview_clearance,
        InformationLabel::Top
    );
    assert_eq!(
        f.f.kernel
            .recovery_deployment(&f.profile.scope)?
            .authority_scope,
        legacy.authority_scope
    );
    let before = events(&f)?;
    // Actors prove the unchanged roles/capability. Each native writer must
    // independently resolve the current historical audience before access.
    assert!(store
        .issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)
        .is_err());
    assert!(store
        .prepare_artifact_read(&reader, &handle, &fence, now_ms()?)
        .is_err());
    assert!(store
        .artifact_transfer_inventory(&reader, &reference, &fence, now_ms()?)
        .is_err());
    assert!(store
        .reserve_artifact(&writer, &input, &fence, now_ms()?)
        .is_err());
    assert!(store
        .move_artifact(
            &writer,
            &reference,
            &ProtectedText::new("legacy-move")?,
            &fence,
            now_ms()?
        )
        .is_err());
    assert!(store
        .pin_artifact(
            &admin,
            &reference,
            &EvidenceRef::new("legacy-audience-pin")?,
            &fence,
            now_ms()?
        )
        .is_err());
    assert!(store
        .admit_artifact_release(
            &reader,
            &handle,
            &RequestId::new("legacy-audience-release")?,
            seal,
            &fence,
            now_ms()?
        )
        .is_err());
    let sink = f.sink();
    assert!(f
        .runtime
        .release_into(
            &f.f.control,
            &RequestId::new("legacy-prepared-release")?,
            prepared,
            &sink
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert_eq!(events(&f)?, before);
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_bytes,
        storage.tree_bytes
    );
    assert_eq!(f.broker.read_private(seal)?, b"known-predecessor-content");
    Ok(())
}

#[test]
fn artifacts_modeled_historical_top_recipient_cannot_receive_a_handle() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("legacy-recipient-audience", b"known-recipient-content")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    assert!(f
        .runtime
        .handle(&f.f.control, &reference, &recipient)
        .is_ok());
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let legacy = retain_knowledge_fixture_legacy_top_recipient(
        &store,
        &fence,
        &f.profile.scope,
        &recipient,
    )?;
    assert_eq!(
        legacy.recipients.as_slice()[0].recipient.clearance,
        InformationLabel::Top
    );
    assert_eq!(
        store
            .knowledge_installation(&reader, &fence, now_ms()?)?
            .generation,
        legacy.generation
    );
    let before = events(&f)?;
    assert!(store
        .issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)
        .is_err());
    assert!(f
        .runtime
        .handle(&f.f.control, &reference, &recipient)
        .is_err());
    assert_eq!(events(&f)?, before);
    Ok(())
}

#[test]
fn artifacts_fresh_top_recipient_installation_is_refused() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let mut profile = f.profile.clone();
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = InformationLabel::Top;
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    assert!(f
        .f
        .authority
        .admission_operation_store()
        .configure_knowledge(&profile)
        .is_err());
    Ok(())
}
