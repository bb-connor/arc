//! Distinct finite native floors preserve a valid checkpoint's exact meaning.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn incoming_label() -> TestResult<InformationLabel> {
    let mut owners = BTreeMap::new();
    for index in 0..4 {
        let owner = PrincipalId::new(format!("owner-{index}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..60 {
            readers.insert(PrincipalId::new(format!(
                "reader-{index}-{reader:02}-{}",
                "r".repeat(238)
            ))?);
        }
        owners.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(owners, BTreeSet::new())?)
}

fn historical_label() -> TestResult<InformationLabel> {
    let mut owners = BTreeMap::new();
    for index in 0..5 {
        let owner = PrincipalId::new(format!("history-owner-{index}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..64 {
            let prefix = format!("history-reader-{index}-{reader:02}-");
            readers.insert(PrincipalId::new(format!(
                "{prefix}{}",
                "h".repeat(255 - prefix.len())
            ))?);
        }
        owners.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(owners, BTreeSet::new())?)
}

fn native_snapshot(
    f: &KnowledgeFixture,
) -> TestResult<chio_security_types::ports::FlowStateSnapshot> {
    let observed =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    Ok(observed.snapshot().ok_or("native snapshot absent")?.clone())
}

#[test]
fn memory_checkpoint_preserves_distinct_large_native_labels_within_its_envelope() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let incoming = incoming_label()?;
    let historical = historical_label()?;
    let joined = incoming.join_restrictions(&historical)?;
    assert_ne!(incoming, historical);
    assert_ne!(incoming, joined);
    assert_ne!(historical, joined);
    assert!(!matches!(joined, InformationLabel::Top));
    assert!(incoming.flows_to(&joined));
    assert!(historical.flows_to(&joined));
    let label_bytes = |label: &InformationLabel| -> TestResult<usize> {
        Ok(chio_core_types::canonical_json_bytes(label)?.len())
    };
    let incoming_bytes = label_bytes(&incoming)?;
    let historical_bytes = label_bytes(&historical)?;
    let joined_bytes = label_bytes(&joined)?;
    assert!(incoming_bytes < 64 * 1024);
    assert!(historical_bytes < 96 * 1024);
    assert!(joined_bytes < 160 * 1024);
    assert!(incoming_bytes + historical_bytes + joined_bytes > 256 * 1024);

    let store = f.f.authority.admission_operation_store();
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = joined.clone();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store
        .configure_recovery_deployment(&deployment)
        .map_err(|error| format!("distinct labels finite actor installation: {error}"))?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = historical.clone();
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    store
        .configure_knowledge(&profile)
        .map_err(|error| format!("distinct labels historical recipient installation: {error}"))?;

    let incoming_body = b"retained-small-checkpoint-body";
    let incoming_artifact = publish_label(
        &f,
        "distinct-incoming-label",
        incoming_body,
        incoming.clone(),
    )
    .map_err(|error| format!("distinct labels genuine incoming publication: {error}"))?;
    let saved = f
        .runtime
        .checkpoint(
            &f.f.control,
            &CheckpointId::new("distinct-large-labels")?,
            0,
            std::slice::from_ref(&incoming_artifact),
            &[],
        )
        .map_err(|error| format!("distinct labels bounded original checkpoint save: {error}"))?;
    assert_eq!(saved.label, incoming);
    let envelope = chio_core_types::canonical_json_bytes(&saved)?;
    assert!(envelope.len() <= 64 * 1024);
    let before = native_snapshot(&f)?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());

    let historical_artifact = publish_label(
        &f,
        "distinct-historical-label",
        b"ordinary-observed-history",
        historical.clone(),
    )
    .map_err(|error| format!("distinct labels genuine historical publication: {error}"))?;
    let handle = f
        .runtime
        .handle(
            &f.f.control,
            &historical_artifact,
            &ArtifactRecipientId::new("agent-root")?,
        )
        .map_err(|error| format!("distinct labels historical handle: {error}"))?;
    let mut history_sink = f.sink();
    history_sink.recipient = profile.recipients.as_slice()[0].recipient.clone();
    f.runtime
        .release_into(
            &f.f.control,
            &RequestId::new("distinct-large-history")?,
            f.runtime.prepare_read(&f.f.control, &handle)?,
            &history_sink,
        )
        .map_err(|error| format!("distinct labels ordinary historical native release: {error}"))?;
    assert_eq!(
        history_sink
            .delivered
            .lock()
            .map_err(|_| "sink")?
            .as_slice(),
        &[b"ordinary-observed-history".to_vec()]
    );
    let observed = native_snapshot(&f)?;
    assert_eq!(observed.principal_label, historical);
    assert_eq!(observed.lineage_label, historical);
    assert_eq!(observed.session_label, historical);
    assert!(observed.context_generation > before.context_generation);

    profile.generation = SafeInteger::new(3)?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = joined.clone();
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    store.configure_knowledge(&profile).map_err(|error| {
        format!("distinct labels joined current recipient installation: {error}")
    })?;
    let request = RequestId::new("bounded-envelope-restore")?;
    let _encoding = store.observe_knowledge_join_encoding_fixture(&profile.scope, &request)?;
    let mut sink = f.sink();
    sink.recipient = profile.recipients.as_slice()[0].recipient.clone();
    let restored = f
        .runtime
        .restore_into(&f.f.control, &saved.checkpoint, 1, &request, &sink);
    let (journal_bytes, change_image_bytes) = store
        .knowledge_join_encoding_fixture(&profile.scope, &request)?
        .ok_or("distinct labels restore did not reach native journal encoding")?;
    let restore_bytes = store.restore_record_encoding_fixture(&profile.scope, &request)?;
    if journal_bytes > 256 * 1024 {
        assert!(restored.is_err());
        assert!(restore_bytes.is_none());
        assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
        let unchanged = native_snapshot(&f)?;
        assert_eq!(unchanged.principal_label, historical);
        assert_eq!(unchanged.lineage_label, historical);
        assert_eq!(unchanged.session_label, historical);
        return Err(format!(
            "distinct finite labels exceed private journal representation: incoming_bytes={incoming_bytes},historical_bytes={historical_bytes},joined_bytes={joined_bytes},envelope_bytes={},journal_bytes={journal_bytes},change_image_bytes={change_image_bytes},row_ceiling=262144",
            envelope.len()
        )
        .into());
    }
    if let Some(bytes) = restore_bytes {
        if bytes > 256 * 1024 {
            assert!(restored.is_err());
            assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
            return Err(format!(
                "distinct finite labels reached oversize private RestoreRecord: restore_bytes={bytes},row_ceiling=262144"
            )
            .into());
        }
    }
    let outcome = restored
        .map_err(|error| format!("distinct labels genuine bounded checkpoint restore: {error}"))?;
    release_audience::assert_opaque_outcome(&serde_json::to_value(outcome)?);
    let after = native_snapshot(&f)?;
    assert_eq!(after.principal_label, joined);
    assert_eq!(after.lineage_label, joined);
    assert_eq!(after.session_label, joined);
    let deliveries = sink.delivered.lock().map_err(|_| "sink")?;
    assert_eq!(deliveries.len(), 1);
    let delivered = &deliveries[0];
    let envelope_len = usize::try_from(u32::from_be_bytes(
        delivered
            .get(..4)
            .ok_or("checkpoint frame length absent")?
            .try_into()?,
    ))?;
    assert_eq!(envelope_len, envelope.len());
    assert_eq!(
        delivered.get(4..4 + envelope_len),
        Some(envelope.as_slice())
    );
    let body_offset = 4 + envelope_len;
    let body_len = usize::try_from(u32::from_be_bytes(
        delivered
            .get(body_offset..body_offset + 4)
            .ok_or("body frame absent")?
            .try_into()?,
    ))?;
    assert_eq!(body_len, incoming_body.len());
    assert_eq!(
        delivered.get(body_offset + 4..),
        Some(incoming_body.as_slice())
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
