//! Fresh storage authority can retire retained data after execution has ended.
use super::*;

#[test]
fn artifacts_fresh_admin_exports_cancelled_owner_to_selected_host_archive() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let bytes = b"cancelled-owner-export-content";
    let reference = f.publish("retained-host-export-root", bytes)?;
    let mut profile = f.profile.clone();
    let mut archive = profile.recipients.as_slice()[0].clone();
    archive.recipient.recipient = ArtifactRecipientId::new("retained-host-archive")?;
    archive.recipient.sink = ArtifactSinkV1::Archive;
    profile.recipients = NonEmptyBoundedList::new(vec![
        profile.recipients.as_slice()[0].clone(),
        archive.clone(),
    ])?;
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    f.runtime = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.broker.clone(),
        profile.clone(),
        f.f.authority.mutation_fence(),
    )?;
    f.profile = profile;
    let root = f
        .runtime
        .handle(&f.f.control, &reference, &archive.recipient.recipient)?;
    let read_write = super::release_audience::install_actor(
        &f,
        223,
        "retained-export-without-admin",
        restricted_label(),
        &[
            RecoveryPermission::KnowledgeRead,
            RecoveryPermission::KnowledgeWrite,
        ],
    )?;
    assert!(f
        .f
        .kernel
        .authenticate_recovery_actor(
            &f.profile.scope,
            &read_write,
            RecoveryPermission::KnowledgeAdmin,
        )
        .is_err());
    let foreign_root = f
        .runtime
        .handle(&read_write, &reference, &archive.recipient.recipient)?;
    let sink = RecordingSink {
        recipient: archive.recipient,
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
    assert!(f.f.process.cancel("root")? > 0);
    assert!(f
        .broker
        .validate_process(&f.profile.scope.process_id, &f.profile.producer_context,)
        .is_err());
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &f.input("cancelled-export-new-execution", b"new")?,
            b"new",
            None,
        )
        .is_err());
    assert!(f
        .runtime
        .export_into(
            &read_write,
            &foreign_root,
            &RequestId::new("retained-export-without-admin")?,
            &signer,
            &sink,
        )
        .is_err());
    assert!(sink
        .delivered
        .lock()
        .map_err(|_| "archive sink")?
        .is_empty());

    f.runtime
        .export_into(
            &f.f.control,
            &root,
            &RequestId::new("fresh-admin-retained-export")?,
            &signer,
            &sink,
        )
        .map_err(|error| format!("fresh admin export of retained cancelled owner: {error}"))?;
    let delivered = sink.delivered.lock().map_err(|_| "archive sink")?;
    assert_eq!(delivered.len(), 1);
    let archived = &delivered[0];
    assert!(archived.len() >= 12);
    assert_eq!(&archived[..8], b"CHIOAK1\0");
    let manifest_bytes = usize::try_from(u32::from_be_bytes(archived[8..12].try_into()?))?;
    let manifest_end = 12_usize
        .checked_add(manifest_bytes)
        .ok_or("archive bound")?;
    assert!(manifest_end <= archived.len());
    let manifest: SignedArtifactArchiveManifestV1 =
        serde_json::from_slice(&archived[12..manifest_end])?;
    assert!(manifest.verify_signature()?);
    assert_eq!(manifest.authority_key(), &f.profile.archive_root);
    assert_eq!(manifest.body().scope, f.profile.scope);
    assert_eq!(manifest.body().root, reference);
    assert_eq!(manifest.body().versions.as_slice().len(), 1);
    assert_eq!(
        manifest.body().total_bytes.get(),
        u64::try_from(bytes.len())?
    );
    assert_eq!(&archived[manifest_end..], bytes);
    assert_eq!(
        f.f.process.process("root")?.state,
        chio_process::ProcessState::Cancelled
    );
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &f.input("cancelled-export-still-no-execution", b"new")?,
            b"new",
            None,
        )
        .is_err());
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn artifacts_fresh_admin_can_collect_cancelled_owner_without_restoring_execution() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let bytes = b"retained-cancelled-owner";
    let input = f.input("cancelled-owner", bytes)?;
    let reference = f.runtime.publish(&f.f.control, &input, bytes, None)?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let (record, _) =
        f.f.authority
            .admission_operation_store()
            .prepare_artifact_read(
                &f.actor(RecoveryPermission::KnowledgeRead)?,
                &handle,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    let seal = record.seal.ok_or("retained owner seal absent")?;
    assert_eq!(f.broker.read_private(&seal)?, bytes);
    let before = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(before.tree_bytes, bytes.len() as u64);
    assert_eq!(before.tree_blobs, 1);

    let reader = super::release_audience::install_read_actor(
        &f,
        221,
        "cleanup-read-only-actor",
        restricted_label(),
    )?;
    assert!(f
        .runtime
        .handle(
            &reader,
            &reference,
            &ArtifactRecipientId::new("agent-root")?
        )
        .is_ok());
    assert!(f.runtime.collect(&reader, &reference).is_err());
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_bytes,
        before.tree_bytes
    );

    assert!(f.f.process.cancel("root")? > 0);
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &f.input("cancelled-new-write", b"new")?,
            b"new",
            None
        )
        .is_err());
    assert!(f
        .broker
        .validate_process(&f.profile.scope.process_id, &f.profile.producer_context)
        .is_err());
    assert!(f.runtime.collect(&reader, &reference).is_err());

    f.runtime
        .collect(&f.f.control, &reference)
        .map_err(|error| format!("fresh admin cleanup of immutable cancelled owner: {error}"))?;
    f.runtime.collect(&f.f.control, &reference)?;
    let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(after.tree_bytes, 0);
    assert_eq!(after.tree_blobs, 0);
    assert!(f.broker.read_private(&seal).is_err());
    assert!(f
        .runtime
        .publish(&f.f.control, &input, bytes, None)
        .is_err());
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    let snapshot = f.f.process.process("root")?;
    assert_eq!(snapshot.state, chio_process::ProcessState::Cancelled);
    let state: String = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-publication:*'
         AND json_extract(payload,'$.metadata.artifact')=?1",
        [reference.artifact.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(state, "retired");
    Ok(())
}

// The original signed process token expires before the independent operator token.
// All native writers and this mediator observe the same selected test clock.
#[test]
fn artifacts_fresh_admin_can_collect_expired_owner_without_renewing_execution() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let bytes = b"retained-expired-owner";
    let input = f.input("expired-owner", bytes)?;
    let reference = f.runtime.publish(&f.f.control, &input, bytes, None)?;
    let reader = super::release_audience::install_read_actor(
        &f,
        222,
        "expired-cleanup-read-only-actor",
        restricted_label(),
    )?;
    assert!(f.runtime.collect(&reader, &reference).is_err());
    let expiry = f.f.seed.capability.expires_at;
    assert!(f.f.control.expires_at > expiry + 1);
    assert!(reader.expires_at > expiry + 1);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expiry + 1, []);
    assert!(f
        .f
        .kernel
        .verify_retained_capability_liveness(&f.f.seed.capability.id, &f.f.seed.capability.subject,)
        .is_err());
    let actor = f.f.kernel.authenticate_recovery_actor(
        &f.profile.scope,
        &f.f.control,
        RecoveryPermission::KnowledgeAdmin,
    )?;
    assert_eq!(actor.permission(), RecoveryPermission::KnowledgeAdmin);
    assert!(f
        .broker
        .validate_process(&f.profile.scope.process_id, &f.profile.producer_context,)
        .is_err());
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &f.input("expired-owner-new-publication", b"new")?,
            b"new",
            None,
        )
        .is_err());
    assert!(f.runtime.collect(&reader, &reference).is_err());

    f.runtime
        .collect(&f.f.control, &reference)
        .map_err(|error| format!("fresh admin cleanup of immutable expired owner: {error}"))?;
    f.runtime.collect(&f.f.control, &reference)?;
    let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(after.tree_bytes, 0);
    assert_eq!(after.tree_blobs, 0);
    assert_eq!(
        f.f.process.process("root")?.state,
        chio_process::ProcessState::Running
    );
    assert!(
        f.f.kernel
            .verify_retained_capability_liveness(
                &f.f.seed.capability.id,
                &f.f.seed.capability.subject,
            )
            .is_err(),
        "storage cleanup must not renew the expired execution capability"
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
