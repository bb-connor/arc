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
    // The explicit fresh-admin retained export refuses a non-admin actor.
    assert!(f
        .runtime
        .export_retained_archive(
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

    // The ordinary export path stays execution-only: a cancelled owner
    // refuses it, and only the explicit host-selected fresh-admin entry
    // exports the retained owner.
    assert!(f
        .runtime
        .export_into(
            &f.f.control,
            &root,
            &RequestId::new("fresh-admin-retained-export")?,
            &signer,
            &sink,
        )
        .is_err());
    f.runtime
        .export_retained_archive(
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

/// A sink whose delivery always fails, to exercise the uncertain
/// acknowledgement path: the release identity and staged frame must be
/// retained for a stable replay instead of being minted twice.
pub(super) struct UncertainSink {
    recipient: ArtifactRecipientV1,
    attempts: std::sync::atomic::AtomicUsize,
}
impl UncertainSink {
    pub(super) fn new(recipient: ArtifactRecipientV1) -> Self {
        Self {
            recipient,
            attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Actual delivery attempts that reached this sink and failed there.
    pub(super) fn attempts(&self) -> usize {
        self.attempts.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl ArtifactReleaseSink for UncertainSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        &self.recipient
    }
    fn deliver(&self, _intent: &ArtifactReleaseIntentV1, _bytes: &[u8]) -> Result<(), KernelError> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(KernelError::Internal("delivery refused".into()))
    }
}

/// Verify durable uncertainty before accepting bytes into the existing sink.
struct UncertainStateProbeSink {
    inner: RecordingSink,
}
impl ArtifactReleaseSink for UncertainStateProbeSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        self.inner.recipient()
    }
    fn deliver(&self, intent: &ArtifactReleaseIntentV1, bytes: &[u8]) -> Result<(), KernelError> {
        let state: String = rusqlite::Connection::open(&self.inner.path)
            .and_then(|connection| {
                connection.query_row(
                    "SELECT json_extract(payload,'$.intent.state')
                     FROM admission_operation_recovery_records
                     WHERE record_key GLOB 'knowledge-release:*'
                     AND json_extract(payload,'$.intent.release')=?1",
                    [intent.release.as_str()],
                    |row| row.get(0),
                )
            })
            .map_err(|_| KernelError::Internal("retained release state probe".into()))?;
        if state != "uncertain" {
            return Err(KernelError::Internal(
                "bytes preceded uncertain retention".into(),
            ));
        }
        self.inner.deliver(intent, bytes)
    }
}

/// Complete the same export while the outer call signs, before its admission.
/// The inner call uses the normal backend and cannot recurse into this one.
struct SameRequestConcurrentExportSigner {
    backend: chio_core_types::crypto::Ed25519Backend,
    runtime: NativeKnowledgeRuntime,
    control: CapabilityToken,
    root: ArtifactHandleV1,
    request: RequestId,
    sink: UncertainStateProbeSink,
    delivered: Mutex<Option<ArtifactDeliveryOutcomeV1>>,
}
impl chio_core_types::SigningBackend for SameRequestConcurrentExportSigner {
    fn algorithm(&self) -> chio_core_types::SigningAlgorithm {
        self.backend.algorithm()
    }
    fn public_key(&self) -> chio_core_types::PublicKey {
        self.backend.public_key()
    }
    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<chio_core_types::Signature> {
        let mut delivered = self.delivered.lock().map_err(|_| {
            chio_core_types::Error::InvalidSignature("inner export outcome state".into())
        })?;
        if delivered.is_none() {
            let outcome = self
                .runtime
                .export_retained_archive(
                    &self.control,
                    &self.root,
                    &self.request,
                    &self.backend,
                    &self.sink,
                )
                .map_err(|error| {
                    chio_core_types::Error::InvalidSignature(format!(
                        "inner concurrent export failed: {error}"
                    ))
                })?;
            *delivered = Some(outcome);
        }
        self.backend.sign_bytes(message)
    }
}

#[test]
fn fresh_admin_retained_export_absorbs_concurrent_delivery_of_same_request() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let bytes = b"retained-concurrent-delivery-source";
    let reference = f.publish("retained-concurrent-delivery-root", bytes)?;
    let mut profile = f.profile.clone();
    let mut archive = profile.recipients.as_slice()[0].clone();
    archive.recipient.recipient = ArtifactRecipientId::new("retained-concurrent-archive")?;
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
    let request = RequestId::new("fresh-admin-retained-concurrent")?;
    let signer = SameRequestConcurrentExportSigner {
        backend: chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone()),
        runtime: f.runtime.clone(),
        control: f.f.control.clone(),
        root: root.clone(),
        request: request.clone(),
        sink: UncertainStateProbeSink {
            inner: RecordingSink {
                recipient: archive.recipient.clone(),
                path: f.f.path.join("admission.db"),
                delivered: Mutex::new(vec![]),
            },
        },
        delivered: Mutex::new(None),
    };
    let outer = RecordingSink {
        recipient: archive.recipient,
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    // The inner export reaches Delivered before the outer admission rechecks it.
    let absorbed = f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &outer)
        .map_err(|error| format!("concurrent retained export: {error}"))?;
    let inner = signer
        .delivered
        .lock()
        .map_err(|_| "inner export outcome state")?
        .clone()
        .ok_or("inner concurrent export absent")?;
    assert_eq!(absorbed.release, inner.release);
    assert_eq!(absorbed.state, ArtifactDeliveryStateV1::Delivered);
    let delivered = signer
        .sink
        .inner
        .delivered
        .lock()
        .map_err(|_| "probe sink")?;
    assert_eq!(delivered.len(), 1);
    drop(delivered);
    assert_eq!(outer.delivered.lock().map_err(|_| "archive sink")?.len(), 0);
    let joins: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(joins, 1);
    Ok(())
}

/// Preparation can race with a completed delivery and collection. Only the
/// completed request may replay after its original sources are gone.
#[test]
fn retained_archive_delivered_replay_survives_source_collection() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let bytes = b"retained-stale-preparation-source";
    let reference = f.publish("retained-stale-preparation-root", bytes)?;
    let mut profile = f.profile.clone();
    let mut archive = profile.recipients.as_slice()[0].clone();
    archive.recipient.recipient = ArtifactRecipientId::new("retained-stale-archive")?;
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
    assert!(f.f.process.cancel("root")? > 0);
    let request = RequestId::new("fresh-admin-retained-stale-preparation")?;
    let store = f.f.authority.admission_operation_store();
    let actor = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    // Captured before any delivery exists: this preparation goes stale when
    // the same request is concurrently delivered and the sources are then
    // collected by the fresh admin.
    let stale = store.prepare_retained_archive(
        &actor,
        NativeRetainedArchiveRequest {
            root: &root,
            request: &request,
            recipient: &archive.recipient,
        },
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let unadmitted_request = RequestId::new("retained-source-collected-new-release")?;
    let unadmitted = store.prepare_retained_archive(
        &actor,
        NativeRetainedArchiveRequest {
            root: &root,
            request: &unadmitted_request,
            recipient: &archive.recipient,
        },
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
    let sink = RecordingSink {
        recipient: archive.recipient.clone(),
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    let delivered = f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
        .map_err(|error| format!("genuine concurrent delivery: {error}"))?;
    assert_eq!(delivered.state, ArtifactDeliveryStateV1::Delivered);
    f.runtime
        .collect(&f.f.control, &reference)
        .map_err(|error| format!("fresh admin source collection: {error}"))?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_bytes,
        0
    );
    // The stale preparation still proposes a genuine freshly signed frame
    // for the exact same request, but its live sources are gone, so only
    // the prior terminal record can answer it.
    let versions = stale
        .records()
        .iter()
        .map(|record| record.metadata.clone())
        .collect::<Vec<_>>();
    let manifest = SignedArtifactArchiveManifestV1::sign_with_backend(
        ArtifactArchiveManifestV1 {
            domain_version: VersionV1,
            scope: stale.profile().scope.clone(),
            root: reference.clone(),
            versions: NonEmptyBoundedList::new(versions)?,
            total_bytes: SafeInteger::new(u64::try_from(bytes.len())?)?,
        },
        &signer,
    )?;
    let encoded = chio_core_types::canonical_json_bytes(&manifest)?;
    let mut frame = NativeRetainedArchiveInput::FRAME_MAGIC.to_vec();
    frame.extend_from_slice(&u32::try_from(encoded.len())?.to_be_bytes());
    frame.extend_from_slice(&encoded);
    frame.extend_from_slice(bytes);
    let absorbed = store
        .admit_retained_archive(
            &actor,
            &stale,
            &root,
            NativeRetainedArchiveInput {
                manifest: &manifest,
                bytes: &frame,
            },
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .map_err(|error| format!("stale preparation admission: {error}"))?;
    assert!(store
        .admit_retained_archive(
            &actor,
            &unadmitted,
            &root,
            NativeRetainedArchiveInput {
                manifest: &manifest,
                bytes: &frame,
            },
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    assert_eq!(absorbed.release, delivered.release);
    assert_eq!(absorbed.state, ArtifactDeliveryStateV1::Delivered);
    assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
    let joins: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(joins, 1);
    Ok(())
}

/// Actual Ed25519 signing that refuses a second call: the durable original
/// frame must never depend on signing the same manifest twice, because a
/// signing backend promises a valid signature, not deterministic bytes.
struct SingleSigningCallBackend {
    backend: chio_core_types::crypto::Ed25519Backend,
    calls: AtomicUsize,
}
impl chio_core_types::SigningBackend for SingleSigningCallBackend {
    fn algorithm(&self) -> chio_core_types::SigningAlgorithm {
        self.backend.algorithm()
    }
    fn public_key(&self) -> chio_core_types::PublicKey {
        self.backend.public_key()
    }
    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<chio_core_types::Signature> {
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            return Err(chio_core_types::Error::InvalidSignature(
                "second retained archive signing call refused".into(),
            ));
        }
        self.backend.sign_bytes(message)
    }
}

/// Retains the offered bytes and release identity, then reports uncertain
/// delivery so the exact original frame must be replayed later.
struct UncertainRetainingSink {
    inner: RecordingSink,
    releases: Mutex<Vec<String>>,
}
impl ArtifactReleaseSink for UncertainRetainingSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        self.inner.recipient()
    }
    fn deliver(&self, intent: &ArtifactReleaseIntentV1, bytes: &[u8]) -> Result<(), KernelError> {
        self.inner.deliver(intent, bytes)?;
        self.releases
            .lock()
            .map_err(|_| KernelError::Internal("uncertain sink".into()))?
            .push(intent.release.as_str().to_string());
        Err(KernelError::Internal("delivery uncertain".into()))
    }
}

#[test]
fn fresh_admin_retained_export_replay_requires_no_second_signing() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let bytes = b"retained-single-signing-source";
    let reference = f.publish("retained-single-signing-root", bytes)?;
    let mut profile = f.profile.clone();
    let mut archive = profile.recipients.as_slice()[0].clone();
    archive.recipient.recipient = ArtifactRecipientId::new("retained-single-signing-archive")?;
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
    let request = RequestId::new("fresh-admin-retained-single-signing")?;
    let signer = SingleSigningCallBackend {
        backend: chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone()),
        calls: AtomicUsize::new(0),
    };
    let uncertain = UncertainRetainingSink {
        inner: RecordingSink {
            recipient: archive.recipient.clone(),
            delivered: Mutex::new(vec![]),
            path: f.f.path.join("admission.db"),
        },
        releases: Mutex::new(vec![]),
    };
    let baseline = f.broker.storage_usage(&f.profile.scope.process_id)?;
    // The uncertain delivery retains the exact originally signed frame; a
    // replaying signer that refuses a second call must still succeed.
    assert!(f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &uncertain)
        .is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let original = uncertain
        .inner
        .delivered
        .lock()
        .map_err(|_| "uncertain sink")?
        .first()
        .cloned()
        .ok_or("uncertain delivery retained no frame")?;
    let original_release = uncertain
        .releases
        .lock()
        .map_err(|_| "uncertain sink")?
        .first()
        .cloned()
        .ok_or("uncertain delivery retained no release")?;
    let sink = RecordingSink {
        recipient: archive.recipient.clone(),
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    // The replay delivers the byte-identical original frame under the same
    // release identity without any second signing call.
    let replayed = f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
        .map_err(|error| format!("single-signing retained export replay: {error}"))?;
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(replayed.release.as_str(), original_release);
    let delivered = sink.delivered.lock().map_err(|_| "archive sink")?;
    assert_eq!(delivered.as_slice(), &[original]);
    drop(delivered);
    // The terminal replay also performs no signing and delivers no bytes.
    f.runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
        .map_err(|error| format!("single-signing terminal replay: {error}"))?;
    assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let joins: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(joins, 1);
    let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(after.tree_bytes, baseline.tree_bytes);
    assert_eq!(after.tree_blobs, baseline.tree_blobs);
    Ok(())
}

#[test]
fn fresh_admin_retained_export_replays_delivery_without_staging_frames() -> TestResult {
    for cancel in [false, true] {
        let mut f = KnowledgeFixture::new()?;
        let bytes = b"retained-export-replay-source";
        let reference = f.publish("retained-export-replay-root", bytes)?;
        let mut profile = f.profile.clone();
        let mut archive = profile.recipients.as_slice()[0].clone();
        archive.recipient.recipient = ArtifactRecipientId::new("retained-replay-archive")?;
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
        let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
        if cancel {
            assert!(f.f.process.cancel("root")? > 0);
            assert!(f
                .broker
                .validate_process(&f.profile.scope.process_id, &f.profile.producer_context)
                .is_err());
        }
        let knowledge_joins = || -> Result<i64, Box<dyn std::error::Error>> {
            Ok(
                rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
                    "SELECT count(*) FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'knowledge-join:*'",
                    [],
                    |row| row.get(0),
                )?,
            )
        };
        let request = RequestId::new("fresh-admin-retained-replay")?;
        let uncertain = UncertainSink::new(archive.recipient.clone());
        // Source-only usage before any export: the archive frame is ephemeral,
        // so no export ever adds Process storage and every settled export must
        // return to exactly this baseline.
        let baseline = f.broker.storage_usage(&f.profile.scope.process_id)?;
        // The refused delivery still admits the release, then retains its exact
        // identity and source pins for the replay; no second join is minted.
        assert!(f
            .runtime
            .export_retained_archive(&f.f.control, &root, &request, &signer, &uncertain)
            .is_err());
        assert_eq!(knowledge_joins()?, 1);
        let sink = RecordingSink {
            recipient: archive.recipient.clone(),
            delivered: Mutex::new(vec![]),
            path: f.f.path.join("admission.db"),
        };
        // The stable replay reproduces the frame from the still-pinned sources
        // and reuses the retained identity: one more delivered export of the
        // same request mints no second knowledge join.
        f.runtime
            .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
            .map_err(|error| format!("fresh admin retained export replay: {error}"))?;
        assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
        assert_eq!(knowledge_joins()?, 1);
        // A delivered request is terminal: its replay returns the stable
        // delivered outcome under fresh authority without a new join and
        // without re-delivering bytes.
        f.runtime
            .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
            .map_err(|error| format!("fresh admin retained delivered replay: {error}"))?;
        assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
        assert_eq!(knowledge_joins()?, 1);
        if !cancel {
            // Both permissions and ordinary reads are live. Reusing the same
            // actor/request through the ordinary entry must still reject the
            // archive purpose before delivering bytes or admitting another join.
            let ordinary = f.runtime.prepare_read(&f.f.control, &root)?;
            assert!(f
                .runtime
                .release_into(&f.f.control, &request, ordinary, &sink)
                .is_err());
            assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
            assert_eq!(knowledge_joins()?, 1);
        }
        let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
        assert_eq!(after.tree_bytes, baseline.tree_bytes);
        assert_eq!(after.tree_blobs, baseline.tree_blobs);
        // A distinct request is an independent release with its own join.
        let second = RequestId::new("fresh-admin-retained-second")?;
        let sink_two = RecordingSink {
            recipient: archive.recipient.clone(),
            delivered: Mutex::new(vec![]),
            path: f.f.path.join("admission.db"),
        };
        f.runtime
            .export_retained_archive(&f.f.control, &root, &second, &signer, &sink_two)
            .map_err(|error| format!("fresh admin retained export second request: {error}"))?;
        assert_eq!(knowledge_joins()?, 2);
        let settled = f.broker.storage_usage(&f.profile.scope.process_id)?;
        assert_eq!(settled.tree_bytes, baseline.tree_bytes);
        assert_eq!(settled.tree_blobs, baseline.tree_blobs);
    }
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

#[test]
fn retained_archive_delivery_progress_settles_under_high_wal_and_refunds_once() -> TestResult {
    use super::retention::{active_reference_owners, census_retired, custody, HighWal};
    let mut f = KnowledgeFixture::new()?;
    let reference = f.publish("high-wal-archive-root", b"high-wal-archive")?;
    let mut profile = f.profile.clone();
    let mut archive = profile.recipients.as_slice()[0].clone();
    archive.recipient.recipient = ArtifactRecipientId::new("high-wal-archive")?;
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
    let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
    let request = RequestId::new("high-wal-retained-archive")?;
    let uncertain = UncertainSink::new(archive.recipient.clone());
    // Admission and its pre-send Uncertain are one Runtime call; admission is
    // ordinary intake, so the first attempt precedes pressure.
    assert!(f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &uncertain)
        .is_err());
    let owners = active_reference_owners(&f, &reference, "artifact_release")?;
    assert!(
        owners > 0,
        "an Uncertain archive release retains its sources"
    );
    let pressure = HighWal::begin(&f)?;
    let pending = custody(&f)?;
    let reached = uncertain.attempts();
    assert!(f
        .runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &uncertain)
        .is_err());
    assert_eq!(
        uncertain.attempts(),
        reached + 1,
        "the failed replay must reach the archive sink"
    );
    assert_eq!(
        custody(&f)?,
        pending,
        "a failed replay repeats Uncertain and writes nothing"
    );
    let sink = RecordingSink {
        recipient: archive.recipient.clone(),
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    f.runtime
        .export_retained_archive(&f.f.control, &root, &request, &signer, &sink)
        .map_err(|error| format!("retained archive replay under pressure: {error}"))?;
    let delivered = custody(&f)?;
    let refunded = u64::try_from(owners)?;
    // Uncertain to Delivered plus three owner records per retained source and
    // the tenant census.
    assert_eq!(
        delivered.events - pending.events,
        i64::try_from(1 + 3 * refunded + 1)?
    );
    assert_eq!(
        delivered.commits - pending.commits,
        delivered.events - pending.events
    );
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        0
    );
    assert_eq!(
        census_retired(&delivered)?,
        census_retired(&pending)? + refunded
    );
    assert_eq!(sink.delivered.lock().map_err(|_| "archive sink")?.len(), 1);
    pressure.release()
}
