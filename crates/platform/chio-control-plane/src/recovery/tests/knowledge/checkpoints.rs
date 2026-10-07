//! Checkpoint history retains exact identities and bytes through ordinary writes.
use super::*;

fn assert_restored_checkpoint(
    sink: &RecordingSink,
    id: &str,
    revision: u64,
    artifact_bytes: &[u8],
) -> TestResult {
    let deliveries = sink.delivered.lock().map_err(|_| "sink")?;
    assert_eq!(deliveries.len(), 1);
    let bytes = &deliveries[0];
    let envelope_size = usize::try_from(u32::from_be_bytes(
        bytes.get(..4).ok_or("envelope frame")?.try_into()?,
    ))?;
    let envelope_end = 4 + envelope_size;
    let envelope: serde_json::Value =
        serde_json::from_slice(bytes.get(4..envelope_end).ok_or("checkpoint envelope")?)?;
    assert_eq!(envelope["checkpoint"], id);
    assert_eq!(envelope["revision"], revision);
    let artifact_size = usize::try_from(u32::from_be_bytes(
        bytes
            .get(envelope_end..envelope_end + 4)
            .ok_or("artifact frame")?
            .try_into()?,
    ))?;
    assert_eq!(artifact_size, artifact_bytes.len());
    assert_eq!(bytes.get(envelope_end + 4..), Some(artifact_bytes));
    Ok(())
}

#[test]
fn memory_checkpoint_suffix_ids_preserve_history_pins_and_exact_restore() -> TestResult {
    // Either write order previously caused the two checkpoint identities to
    // overwrite each other's latest or retained revision record.
    for suffix_first in [false, true] {
        let mut f = KnowledgeFixture::new()?;
        let first = f.publish("history-first", b"retained-revision-one")?;
        let second = f.publish("history-second", b"current-revision-two")?;
        let suffix_artifact = f.publish("history-suffix", b"independent-suffix-checkpoint")?;
        let suffix_current = f.publish("history-suffix-current", b"current-suffix-checkpoint")?;
        let id = CheckpointId::new("job")?;
        let suffix = CheckpointId::new("job:1")?;
        for next in if suffix_first {
            [(&suffix, &suffix_artifact), (&id, &first)]
        } else {
            [(&id, &first), (&suffix, &suffix_artifact)]
        } {
            let saved =
                f.runtime
                    .checkpoint(&f.f.control, next.0, 0, std::slice::from_ref(next.1), &[]);
            assert!(
                saved.is_ok(),
                "independent checkpoint must start at revision one"
            );
            let saved = saved?;
            assert_eq!(saved.checkpoint, *next.0);
            assert_eq!(saved.revision.get(), 1);
        }
        let updated =
            f.runtime
                .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&second), &[])?;
        assert_eq!(updated.revision.get(), 2);
        let suffix_updated = f.runtime.checkpoint(
            &f.f.control,
            &suffix,
            1,
            std::slice::from_ref(&suffix_current),
            &[],
        )?;
        assert_eq!(suffix_updated.revision.get(), 2);
        assert!(f.runtime.collect(&f.f.control, &first).is_err());
        assert!(f.runtime.collect(&f.f.control, &suffix_artifact).is_err());

        let path = f.f.path.clone();
        let directory = f.f._directory.take();
        drop(f);
        let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
        // Collection must remain refused before any restore introduces a
        // release pin, proving that the historical checkpoint owns this pin.
        assert!(f.runtime.collect(&f.f.control, &first).is_err());
        assert!(f.runtime.collect(&f.f.control, &suffix_artifact).is_err());
        for (checkpoint, requested, retained, bytes, request) in [
            (
                &id,
                1,
                1,
                b"retained-revision-one".as_slice(),
                "restore-history",
            ),
            (
                &id,
                0,
                2,
                b"current-revision-two".as_slice(),
                "restore-latest",
            ),
            (
                &suffix,
                1,
                1,
                b"independent-suffix-checkpoint".as_slice(),
                "restore-suffix-revision",
            ),
            (
                &suffix,
                0,
                2,
                b"current-suffix-checkpoint".as_slice(),
                "restore-suffix-latest",
            ),
        ] {
            let sink = f.sink();
            f.runtime.restore_into(
                &f.f.control,
                checkpoint,
                requested,
                &RequestId::new(request)?,
                &sink,
            )?;
            assert_restored_checkpoint(&sink, checkpoint.as_str(), retained, bytes)?;
        }
    }
    Ok(())
}

#[test]
fn memory_checkpoint_suffix_cannot_borrow_another_checkpoint_revision() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("borrow-first", b"immutable-first-checkpoint")?;
    let second = f.publish("borrow-second", b"new-current-checkpoint")?;
    let foreign = f.publish("borrow-foreign", b"foreign-checkpoint")?;
    let id = CheckpointId::new("job")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&first), &[])?;
    f.runtime
        .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&second), &[])?;
    let attempted = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("job:1")?,
        1,
        std::slice::from_ref(&foreign),
        &[],
    );
    assert!(
        attempted.is_err(),
        "foreign revision must never satisfy checkpoint CAS"
    );
    assert!(f.runtime.collect(&f.f.control, &first).is_err());
    let sink = f.sink();
    f.runtime.restore_into(
        &f.f.control,
        &id,
        1,
        &RequestId::new("restore-immutable-first")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "job", 1, b"immutable-first-checkpoint")?;
    Ok(())
}

#[test]
fn memory_checkpoint_absent_suffix_read_never_delivers_a_foreign_envelope() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("absent-first", b"first-checkpoint-bytes")?;
    f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("job")?,
        0,
        std::slice::from_ref(&first),
        &[],
    )?;
    let sink = f.sink();
    let result = f.runtime.restore_into(
        &f.f.control,
        &CheckpointId::new("job:1")?,
        0,
        &RequestId::new("restore-absent-suffix")?,
        &sink,
    );
    assert!(
        result.is_err(),
        "absent checkpoint must not alias a retained revision"
    );
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert!(f.runtime.collect(&f.f.control, &first).is_err());
    Ok(())
}

fn legacy_key(f: &KnowledgeFixture, id: &str, revision: u64) -> TestResult<String> {
    let scope =
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(&f.profile.scope)?);
    let key = format!("knowledge-checkpoint:{scope}:{id}");
    Ok(if revision == 0 {
        key
    } else {
        format!("{key}:{revision}")
    })
}

fn legacy_envelope(
    template: &LabeledCheckpointV1,
    id: &str,
    revision: u64,
    artifact: &ArtifactVersionRefV1,
) -> TestResult<LabeledCheckpointV1> {
    let mut envelope = template.clone();
    envelope.checkpoint = CheckpointId::new(id)?;
    envelope.revision = SafeInteger::new(revision)?;
    envelope.artifacts = NonEmptyBoundedList::new(vec![artifact.clone()])?;
    Ok(envelope)
}

fn seed_legacy(f: &KnowledgeFixture, records: &[(String, &LabeledCheckpointV1)]) -> TestResult {
    let records = records
        .iter()
        .map(|(key, envelope)| {
            Ok(RecoveryQuotaFixtureRecord {
                scope: f.profile.scope.clone(),
                key: key.clone(),
                payload: chio_core_types::canonical_json_bytes(*envelope)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    retain_recovery_quota_fixture_records(
        &f.f.authority.admission_operation_store(),
        &f.f.authority.mutation_fence(),
        &records,
    )?;
    Ok(())
}

#[test]
fn memory_legacy_damaged_latest_recovers_public_cas_restore_and_pins() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let old = f.publish("legacy-old", b"intact-legacy-revision")?;
    let new = f.publish("legacy-new", b"post-upgrade-revision")?;
    let template = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("template")?,
        0,
        std::slice::from_ref(&new),
        &[],
    )?;
    let first = legacy_envelope(&template, "job:1", 1, &old)?;
    let latest = legacy_envelope(&template, "job:1", 2, &old)?;
    let foreign = legacy_envelope(&template, "job", 1, &new)?;
    seed_legacy(
        &f,
        &[
            (legacy_key(&f, "job:1", 1)?, &first),
            (legacy_key(&f, "job:1", 2)?, &latest),
            (legacy_key(&f, "job:1", 0)?, &foreign),
        ],
    )?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let legacy: Vec<(String, i64, Vec<u8>)> = connection
        .prepare(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records
         WHERE record_key GLOB ?1 ORDER BY record_key",
        )?
        .query_map(
            [format!(
                "knowledge-checkpoint:{}:*",
                chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(
                    &f.profile.scope
                )?,)
            )],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?
        .collect::<Result<_, _>>()?;
    let sink = f.sink();
    f.runtime.restore_into(
        &f.f.control,
        &CheckpointId::new("job:1")?,
        0,
        &RequestId::new("legacy-latest")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "job:1", 2, b"intact-legacy-revision")?;
    assert!(f.runtime.collect(&f.f.control, &old).is_err());
    let saved = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("job:1")?,
        2,
        std::slice::from_ref(&new),
        &[],
    )?;
    assert_eq!(saved.revision.get(), 3);
    for (key, version, payload) in &legacy {
        let observed: (i64, Vec<u8>) = connection.query_row(
            "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(observed, (*version, payload.clone()));
    }
    drop(connection);
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(f);
    let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    assert!(f.runtime.collect(&f.f.control, &old).is_err());
    let sink = f.sink();
    f.runtime.restore_into(
        &f.f.control,
        &CheckpointId::new("job:1")?,
        2,
        &RequestId::new("legacy-reopen")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "job:1", 2, b"intact-legacy-revision")?;
    Ok(())
}

#[test]
fn memory_legacy_latest_restores_when_its_revision_slot_belongs_to_another_id() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("legacy-latest-only", b"latest-envelope-content")?;
    let template = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("template")?,
        0,
        std::slice::from_ref(&reference),
        &[],
    )?;
    let latest = legacy_envelope(&template, "k", 1, &reference)?;
    let foreign = legacy_envelope(&template, "k:1", 1, &reference)?;
    seed_legacy(
        &f,
        &[
            (legacy_key(&f, "k", 0)?, &latest),
            (legacy_key(&f, "k", 1)?, &foreign),
        ],
    )?;
    let sink = f.sink();
    f.runtime.restore_into(
        &f.f.control,
        &CheckpointId::new("k")?,
        0,
        &RequestId::new("legacy-latest-only")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "k", 1, b"latest-envelope-content")?;
    let next = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("k")?,
        1,
        std::slice::from_ref(&reference),
        &[],
    )?;
    assert_eq!(next.revision.get(), 2);
    Ok(())
}

fn restore_outcome(
    f: &KnowledgeFixture,
    request: &RequestId,
) -> TestResult<(ReleaseId, ArtifactDeliveryStateV1)> {
    f.f.authority
        .admission_operation_store()
        .checkpoint_restore_outcome_fixture(
            &f.actor(RecoveryPermission::KnowledgeRead)?,
            request,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or_else(|| "restore outcome absent".into())
}

fn restore_state(f: &KnowledgeFixture, request: &RequestId) -> TestResult<String> {
    let (_, state) = restore_outcome(f, request)?;
    let serialized = serde_json::to_value(state)?;
    Ok(serialized
        .as_str()
        .ok_or("restore state encoding")?
        .to_owned())
}

struct FailingRestoreSink {
    recipient: ArtifactRecipientV1,
    attempts: AtomicUsize,
    store: chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore,
    actor: AuthenticatedRecoveryActor,
    fence: chio_kernel::admission_operation::StoreMutationFence,
    request: RequestId,
    observed: Mutex<Vec<String>>,
}

impl ArtifactReleaseSink for FailingRestoreSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        &self.recipient
    }

    fn deliver(&self, _intent: &ArtifactReleaseIntentV1, bytes: &[u8]) -> Result<(), KernelError> {
        assert!(
            !bytes.is_empty(),
            "the failure follows a real delivery attempt"
        );
        let (_, state) = self
            .store
            .checkpoint_restore_outcome_fixture(
                &self.actor,
                &self.request,
                &self.fence,
                now_ms().map_err(|error| {
                    KernelError::Internal(format!("sink custody clock: {error}"))
                })?,
            )
            .map_err(|error| KernelError::Internal(format!("sink custody readback: {error}")))?
            .ok_or_else(|| KernelError::Internal("sink custody absent".into()))?;
        let state = serde_json::to_value(state)
            .map_err(|error| KernelError::Internal(format!("sink custody encoding: {error}")))?;
        let state = state
            .as_str()
            .ok_or_else(|| KernelError::Internal("sink custody state".into()))?
            .to_owned();
        self.observed
            .lock()
            .map_err(|_| KernelError::Internal("sink custody observation".into()))?
            .push(state);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal("restore acknowledgement lost".into()))
    }
}

#[test]
fn memory_restore_outcome_is_uncertain_until_delivery_and_never_downgrades() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("restore-state", b"bounded-restore-material")?;
    let id = CheckpointId::new("restore-state")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    let request = RequestId::new("restore-state")?;
    let failure = FailingRestoreSink {
        recipient: f.profile.recipients.as_slice()[0].recipient.clone(),
        attempts: AtomicUsize::new(0),
        store: f.f.authority.admission_operation_store(),
        actor: f.actor(RecoveryPermission::KnowledgeRead)?,
        fence: f.f.authority.mutation_fence(),
        request: request.clone(),
        observed: Mutex::new(Vec::new()),
    };
    assert!(f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &failure)
        .is_err());
    assert_eq!(failure.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        failure.observed.lock().map_err(|_| "sink")?.as_slice(),
        ["uncertain"],
        "an independent reader must see retained uncertainty before sink I/O"
    );
    assert_eq!(restore_state(&f, &request)?, "uncertain");

    let sink = f.sink();
    let delivered = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    assert_eq!(restore_state(&f, &request)?, "delivered");
    assert!(f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &failure)
        .is_err());
    assert_eq!(failure.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        failure.observed.lock().map_err(|_| "sink")?.as_slice(),
        ["uncertain", "delivered"],
        "a repeated delivery attempt cannot downgrade acknowledged custody"
    );
    assert_eq!(restore_state(&f, &request)?, "delivered");
    let replay = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    assert_eq!(replay.release, delivered.release);
    Ok(())
}

#[test]
fn memory_restore_lost_success_acknowledgement_retains_uncertain_delivery() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("restore-cutpoint", b"restored-before-acknowledgement")?;
    let id = CheckpointId::new("restore-cutpoint")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    let once = Arc::new(AtomicUsize::new(0));
    let seen = once.clone();
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == KnowledgeCutpoint::DeliveryCompleted && seen.fetch_add(1, Ordering::SeqCst) == 0
        {
            return Err(KernelError::Internal(
                "restore completion acknowledgement lost".into(),
            ));
        }
        Ok(())
    }));
    let request = RequestId::new("restore-cutpoint")?;
    let sink = f.sink();
    assert!(faulty
        .restore_into(&f.f.control, &id, 1, &request, &sink)
        .is_err());
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    assert_eq!(restore_state(&f, &request)?, "uncertain");
    f.runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 2);
    assert_eq!(restore_state(&f, &request)?, "delivered");
    Ok(())
}

fn assert_exact_checkpoint_frame(
    sink: &RecordingSink,
    checkpoint: &LabeledCheckpointV1,
    artifact_bytes: &[u8],
) -> TestResult {
    let deliveries = sink.delivered.lock().map_err(|_| "sink")?;
    assert_eq!(deliveries.len(), 1);
    let bytes = &deliveries[0];
    let canonical = chio_core_types::canonical_json_bytes(checkpoint)?;
    let framed_length = usize::try_from(u32::from_be_bytes(
        bytes.get(..4).ok_or("envelope frame")?.try_into()?,
    ))?;
    assert_eq!(framed_length, canonical.len());
    let envelope_end = 4usize
        .checked_add(framed_length)
        .ok_or("checkpoint frame overflow")?;
    assert_eq!(
        bytes.get(4..envelope_end),
        Some(canonical.as_slice()),
        "restore preserves the complete exact canonical envelope"
    );
    let artifact_end = envelope_end
        .checked_add(4)
        .ok_or("artifact frame overflow")?;
    let artifact_length = usize::try_from(u32::from_be_bytes(
        bytes
            .get(envelope_end..artifact_end)
            .ok_or("artifact frame")?
            .try_into()?,
    ))?;
    assert_eq!(artifact_length, artifact_bytes.len());
    assert_eq!(bytes.get(artifact_end..), Some(artifact_bytes));
    Ok(())
}

fn checkpoint_envelope_boundary(
    readers_per_owner: usize,
    reader_suffix: &str,
    label_fits_envelope: bool,
    oversized: bool,
) -> TestResult {
    use std::collections::{BTreeMap, BTreeSet};

    let mut f = KnowledgeFixture::new()?;
    let template = if label_fits_envelope {
        let reference = f
            .publish("metadata-template", b"small-metadata-template")
            .map_err(|error| format!("envelope boundary template publication: {error}"))?;
        Some(
            f.runtime
                .checkpoint(
                    &f.f.control,
                    &CheckpointId::new("metadata-template")?,
                    0,
                    &[reference],
                    &[],
                )
                .map_err(|error| format!("envelope boundary template save: {error}"))?,
        )
    } else {
        None
    };
    let mut owners = BTreeMap::new();
    for index in 0..4 {
        let owner = chio_security_types::PrincipalId::new(format!("owner-{index}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..readers_per_owner {
            readers.insert(chio_security_types::PrincipalId::new(format!(
                "reader-{index}-{reader:02}-{}",
                reader_suffix,
            ))?);
        }
        owners.insert(owner, readers);
    }
    let label = InformationLabel::try_known(owners, BTreeSet::new())?;
    let label_bytes = chio_core_types::canonical_json_bytes(&label)?.len();
    if label_fits_envelope {
        assert!(label_bytes < 64 * 1024);
    } else {
        assert!(label_bytes > 64 * 1024);
    }
    assert!(label_bytes < 96 * 1024);
    let store = f.f.authority.admission_operation_store();
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = label.clone();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store
        .configure_recovery_deployment(&deployment)
        .map_err(|error| format!("large envelope actor setup: {error}"))?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = label.clone();
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    store
        .configure_knowledge(&profile)
        .map_err(|error| format!("large envelope recipient setup: {error}"))?;
    let reference = publish_label(
        &f,
        "large-checkpoint-label",
        b"small-content",
        label.clone(),
    )
    .map_err(|error| format!("large envelope finite-label publication: {error}"))?;
    if let Some(mut expected) = template {
        expected.checkpoint = CheckpointId::new("oversized-envelope")?;
        expected.label = label;
        expected.artifacts = NonEmptyBoundedList::new(vec![reference.clone()])?;
        assert_eq!(
            chio_core_types::canonical_json_bytes(&expected)?.len() > 64 * 1024,
            oversized,
            "the complete envelope includes metadata beyond its label"
        );
    }
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let counts = || -> TestResult<(i64, i64)> {
        Ok((
            connection.query_row(
                "SELECT count(*) FROM admission_operation_recovery_records",
                [],
                |row| row.get(0),
            )?,
            connection.query_row(
                "SELECT count(*) FROM admission_operation_recovery_events",
                [],
                |row| row.get(0),
            )?,
        ))
    };
    let before = counts()?;
    let saved = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("oversized-envelope")?,
        0,
        std::slice::from_ref(&reference),
        &[],
    );
    if oversized {
        assert!(
            saved.is_err(),
            "an admitted checkpoint must fit its restore envelope"
        );
        assert_eq!(
            counts()?,
            before,
            "refusal must not consume rows, events or pins"
        );
        f.runtime
            .collect(&f.f.control, &reference)
            .map_err(|error| format!("envelope boundary refused-save unpinned cleanup: {error}"))?;
    } else {
        let saved = saved
            .map_err(|error| format!("envelope boundary below-limit positive save: {error}"))?;
        let envelope_bytes = chio_core_types::canonical_json_bytes(&saved)?.len();
        assert!(envelope_bytes <= 64 * 1024);
        let mut sink = f.sink();
        sink.recipient = profile.recipients.as_slice()[0].recipient.clone();
        let request = RequestId::new("bounded-envelope-restore")?;
        let _encoding = store.observe_knowledge_join_encoding_fixture(&profile.scope, &request)?;
        let restored = f
            .runtime
            .restore_into(&f.f.control, &saved.checkpoint, 1, &request, &sink);
        let encoding = store.knowledge_join_encoding_fixture(&profile.scope, &request)?;
        let restore_encoding = store.restore_record_encoding_fixture(&profile.scope, &request)?;
        assert!(
            encoding.is_some(),
            "the real restore must reach native knowledge journal encoding"
        );
        if let Some((journal_bytes, change_image_bytes)) = encoding {
            if journal_bytes > 256 * 1024 {
                assert!(restored.is_err(), "oversize private encoding still refuses");
                assert!(
                    restore_encoding.is_none(),
                    "oversize native journal fails before a restore record is encoded"
                );
                return Err(format!(
                    "envelope boundary actual native journal encoding exceeds the unchanged row ceiling: envelope_bytes={envelope_bytes},journal_bytes={journal_bytes},change_image_bytes={change_image_bytes},row_ceiling=262144"
                )
                .into());
            }
        }
        if let Some(restore_bytes) = restore_encoding {
            if restore_bytes > 256 * 1024 {
                assert!(restored.is_err(), "oversize private encoding still refuses");
                return Err(format!(
                    "envelope boundary actual restore record encoding exceeds the unchanged row ceiling: envelope_bytes={envelope_bytes},restore_bytes={restore_bytes},row_ceiling=262144"
                )
                .into());
            }
        }
        let delivered = restored.map_err(|error| {
            format!(
                "envelope boundary below-limit positive restore after journal encoding: {error}"
            )
        })?;
        assert!(
            restore_encoding.is_some(),
            "successful restore must record its actual private encoding size"
        );
        assert_exact_checkpoint_frame(&sink, &saved, b"small-content")?;
        assert_eq!(restore_state(&f, &request)?, "delivered");

        // A lost completion acknowledgement must retain the original private
        // release and uncertainty even for a large reconstructed envelope.
        let lost_request = RequestId::new("bounded-envelope-lost-ack")?;
        let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
            if stage == KnowledgeCutpoint::DeliveryCompleted {
                return Err(KernelError::Internal(
                    "bounded restore acknowledgement lost".into(),
                ));
            }
            Ok(())
        }));
        let mut lost_sink = f.sink();
        lost_sink.recipient = profile.recipients.as_slice()[0].recipient.clone();
        assert!(faulty
            .restore_into(
                &f.f.control,
                &saved.checkpoint,
                1,
                &lost_request,
                &lost_sink
            )
            .is_err());
        assert_exact_checkpoint_frame(&lost_sink, &saved, b"small-content")?;
        assert_eq!(restore_state(&f, &lost_request)?, "uncertain");
        let (retained_release, retained_state) = restore_outcome(&f, &lost_request)?;
        assert_eq!(retained_state, ArtifactDeliveryStateV1::Uncertain);
        let mut completed_sink = f.sink();
        completed_sink.recipient = profile.recipients.as_slice()[0].recipient.clone();
        let completed = f.runtime.restore_into(
            &f.f.control,
            &saved.checkpoint,
            1,
            &lost_request,
            &completed_sink,
        )?;
        assert_eq!(completed.release, retained_release);
        assert_exact_checkpoint_frame(&completed_sink, &saved, b"small-content")?;
        assert_eq!(restore_state(&f, &lost_request)?, "delivered");
        assert!(faulty
            .restore_into(
                &f.f.control,
                &saved.checkpoint,
                1,
                &lost_request,
                &lost_sink
            )
            .is_err());
        assert_eq!(restore_state(&f, &lost_request)?, "delivered");
        drop(faulty);

        // Reopen the real authority/process stores. Keep the exact original
        // opaque read capability and installed generation2 profile, rather
        // than regenerating an authorization or resetting its finite label.
        let original_capability = f.f.control.clone();
        let path = f.f.path.clone();
        let directory = f.f._directory.take();
        drop(_encoding);
        drop(store);
        drop(connection);
        drop(f);
        let mut reopened = RecoveryFixture::open(path, directory, false)?;
        reopened.control = original_capability;
        let broker = Arc::new(reopened.process.enable_durable_knowledge()?);
        let runtime = NativeKnowledgeRuntime::new(
            reopened.kernel.clone(),
            Arc::new(reopened.authority.admission_operation_store()),
            broker.clone(),
            profile.clone(),
            reopened.authority.mutation_fence(),
        )?;
        let reopened = KnowledgeFixture {
            f: reopened,
            runtime,
            profile,
            broker,
            certificate: Keypair::from_seed(&[217; 32]),
        };
        let replay_sink = reopened.sink();
        let replay = reopened.runtime.restore_into(
            &reopened.f.control,
            &saved.checkpoint,
            1,
            &request,
            &replay_sink,
        )?;
        assert_eq!(replay.release, delivered.release);
        assert_eq!(restore_state(&reopened, &request)?, "delivered");
        assert_exact_checkpoint_frame(&replay_sink, &saved, b"small-content")?;
        assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn memory_checkpoint_refuses_unrestorable_envelopes_without_writes_or_pins() -> TestResult {
    checkpoint_envelope_boundary(72, &"r".repeat(238), false, true)
        .map_err(|error| format!("oversized canonical label case: {error}"))?;
    // The label alone fits. Runtime, provenance and policy metadata make the
    // complete canonical checkpoint exceed its accepted byte ceiling.
    checkpoint_envelope_boundary(64, &"r".repeat(238), true, true)
        .map_err(|error| format!("oversized complete metadata envelope case: {error}"))?;
    // UTF-8 and JSON escape expansion must be measured as encoded bytes.
    checkpoint_envelope_boundary(64, &"é\"\\".repeat(52), false, true)
        .map_err(|error| format!("oversized escaped UTF8 envelope case: {error}"))?;
    checkpoint_envelope_boundary(60, &"r".repeat(238), true, false)
        .map_err(|error| format!("bounded complete envelope case: {error}"))?;
    Ok(())
}

#[test]
fn memory_checkpoint_reset_history_cannot_escape_the_latest_revision_fence() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let old = f
        .publish("reset-history-old", b"pre-reset-history")
        .map_err(|error| format!("reset history old publication: {error}"))?;
    let new = f
        .publish("reset-history-new", b"post-reset-latest")
        .map_err(|error| format!("reset history new publication: {error}"))?;
    let id = CheckpointId::new("reset-history")?;
    let template = f
        .runtime
        .checkpoint(
            &f.f.control,
            &CheckpointId::new("reset-template")?,
            0,
            std::slice::from_ref(&new),
            &[],
        )
        .map_err(|error| format!("reset history template checkpoint: {error}"))?;
    let latest = legacy_envelope(&template, "reset-history", 1, &new)?;
    let previous_epoch = legacy_envelope(&latest, "reset-history", 2, &old)?;
    let key = legacy_key(&f, "reset-history", 2)?;
    // Seed the old v2 latest and revision before any new-code activation of
    // this identity. A new checkpoint-head descriptor must fold these rows.
    let scope =
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(&f.profile.scope)?);
    seed_legacy(
        &f,
        &[
            (
                format!("knowledge-checkpoint:v2:latest:{scope}:13:reset-history"),
                &latest,
            ),
            (
                format!("knowledge-checkpoint:v2:revision:{scope}:13:reset-history:1"),
                &latest,
            ),
            (key.clone(), &previous_epoch),
        ],
    )
    .map_err(|error| format!("reset history protected predecessor retention: {error}"))?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let historical_row: (i64, Vec<u8>) = connection.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let sink = f.sink();
    assert!(
        f.runtime
            .restore_into(
                &f.f.control,
                &id,
                2,
                &RequestId::new("reset-future-revision")?,
                &sink,
            )
            .is_err(),
        "an older epoch cannot expose a revision above the current latest"
    );
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let store = f.f.authority.admission_operation_store();
    let _ = store.take_checkpoint_history_collisions_for_test();
    let advanced = f
        .runtime
        .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&new), &[])
        .map_err(|error| {
            let collisions = store.take_checkpoint_history_collisions_for_test();
            format!("reset history public CAS immutable_collisions={collisions}: {error}")
        })?;
    assert_eq!(
        advanced.revision.get(),
        3,
        "CAS preserves consumed revision identities"
    );
    let after: (i64, Vec<u8>) = connection.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(after, historical_row);
    assert!(f.runtime.collect(&f.f.control, &old).is_err());
    Ok(())
}

/// The real private broker still performs every read, identity check and write.
/// Only the protected profile rotation at the verification boundary is injected.
struct RotatingRestoreBroker {
    broker: Arc<chio_process::ProcessArtifactBroker>,
    store: SqliteAdmissionOperationStore,
    next: NativeKnowledgeInstallationV1,
    reads: AtomicUsize,
    rotated: std::sync::atomic::AtomicBool,
}

impl ArtifactBlobPort for RotatingRestoreBroker {
    fn runtime_id(&self) -> &str {
        self.broker.runtime_id()
    }

    fn validate_process(
        &self,
        process: &ProcessId,
        context: &chio_kernel::SecurityInvocationContext,
    ) -> Result<(), KernelError> {
        self.broker.validate_process(process, context)
    }

    fn stage(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        self.broker.stage(object, process, bytes)
    }

    fn resolve_private(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        content: CanonicalPayloadDigest,
        bytes: SafeInteger,
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        self.broker.resolve_private(object, process, content, bytes)
    }

    fn read_private(&self, seal: &ArtifactBlobSealV1) -> Result<Vec<u8>, KernelError> {
        let bytes = self.broker.read_private(seal)?;
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            self.store
                .configure_knowledge(&self.next)
                .map_err(|error| {
                    KernelError::Internal(format!("test profile rotation failed: {error}"))
                })?;
            self.rotated.store(true, Ordering::SeqCst);
        }
        Ok(bytes)
    }

    fn collect_private(&self, seal: &ArtifactBlobSealV1) -> Result<(), KernelError> {
        self.broker.collect_private(seal)
    }
}

#[test]
fn memory_restore_profile_rotation_during_private_verification_withholds_delivery() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("restore-generation", b"profile-bound-material")?;
    let id = CheckpointId::new("restore-generation")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    let mut next = f.profile.clone();
    next.generation = SafeInteger::new(2)?;
    next.contract = ContractDigest::from_bytes([239; 32]);
    let broker = Arc::new(RotatingRestoreBroker {
        broker: f.broker.clone(),
        store: f.f.authority.admission_operation_store(),
        next,
        reads: AtomicUsize::new(0),
        rotated: std::sync::atomic::AtomicBool::new(false),
    });
    let runtime = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        broker.clone(),
        f.profile.clone(),
        f.f.authority.mutation_fence(),
    )?;
    let sink = f.sink();
    assert!(
        runtime
            .restore_into(
                &f.f.control,
                &id,
                1,
                &RequestId::new("restore-generation")?,
                &sink,
            )
            .is_err(),
        "a restore cannot admit under a different profile than its preparation"
    );
    assert_eq!(broker.reads.load(Ordering::SeqCst), 2);
    assert!(
        broker.rotated.load(Ordering::SeqCst),
        "the fixture must actually commit the profile rotation"
    );
    let current = broker.store.knowledge_installation(
        &f.actor(RecoveryPermission::KnowledgeRead)?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(current.generation.get(), 2);
    assert_eq!(current.contract, ContractDigest::from_bytes([239; 32]));
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let committed: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-restore:*' OR record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        committed, 0,
        "stale preparation must not consume disclosure authority"
    );
    Ok(())
}

#[test]
fn memory_restore_request_is_owned_by_the_original_actor_principal() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("restore-principal", b"actor-bound-material")?;
    let id = CheckpointId::new("restore-principal")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    let request = RequestId::new("restore-principal")?;
    let sink = f.sink();
    let original = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    let original = super::acceptance::private_release_observation(&f, &original.release)?;
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);

    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].principal = chio_security_types::PrincipalId::new("replacement-reviewer")?;
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    assert_eq!(
        f.actor(RecoveryPermission::KnowledgeRead)?
            .principal()
            .as_str(),
        "replacement-reviewer"
    );
    assert!(
        f.f.authority
            .admission_operation_store()
            .acknowledge_checkpoint_delivery(
                &f.actor(RecoveryPermission::KnowledgeRead)?,
                &request,
                &original,
                true,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )
            .is_err(),
        "a reassigned subject cannot acknowledge another principal's intent"
    );
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    let independent = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    assert_ne!(
        independent.release, original.release,
        "request names are actor-scoped"
    );
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 2);
    Ok(())
}

#[test]
fn memory_legacy_restore_preserves_opaque_authority_and_proves_its_original_actor() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("legacy-restore-owner", b"legacy-owned-material")?;
    let id = CheckpointId::new("legacy-restore-owner")?;
    let checkpoint = f
        .runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    let request = RequestId::new("legacy-restore-owner")?;
    let sink = f.sink();
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let guard = construct_legacy_checkpoint_restore_fixture(&actor, &request)?;
    let first =
        f.f.authority
            .admission_operation_store()
            .admit_checkpoint_restore(
                &actor,
                NativeCheckpointRestore {
                    checkpoint: &checkpoint,
                    recipient: &sink.recipient,
                    request: &request,
                    installation_generation: f.profile.generation,
                },
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    drop(guard);
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let (key, bytes): (String, Vec<u8>) = connection.query_row(
        "SELECT record_key,payload FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-restore:*'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let legacy: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(legacy.get("actor_binding").is_none());
    assert!(legacy.get("installation_generation").is_none());
    assert!(!key.starts_with("knowledge-restore:v2:"));
    let store = f.f.authority.admission_operation_store();
    store.take_legacy_restore_actor_resolution_calls_for_test();
    let proven = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink);
    let resolver_calls = store.take_legacy_restore_actor_resolution_calls_for_test();
    let proven = proven.map_err(|error| {
        format!("legacy actual restore resolver_calls={resolver_calls}: {error}")
    })?;
    assert!(
        resolver_calls > 0,
        "legacy replay proves its original actor"
    );
    assert_eq!(proven.release, first.release);
    let original_observation = super::acceptance::private_release_observation(&f, &proven.release)?;
    assert_eq!(original_observation.authorization, first.authorization);
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    let before: (i64, Vec<u8>) = connection.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(restore_state(&f, &request)?, "delivered");

    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].principal = chio_security_types::PrincipalId::new("legacy-replacement-reviewer")?;
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    assert_eq!(
        f.actor(RecoveryPermission::KnowledgeRead)?
            .principal()
            .as_str(),
        "legacy-replacement-reviewer"
    );
    assert!(f
        .f
        .authority
        .admission_operation_store()
        .acknowledge_checkpoint_delivery(
            &f.actor(RecoveryPermission::KnowledgeRead)?,
            &request,
            &first,
            true,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    let independent = f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &sink)?;
    assert_ne!(independent.release, first.release);
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 2);
    let after: (i64, Vec<u8>) = connection.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        after, before,
        "proving a legacy owner must not rewrite opaque custody"
    );
    Ok(())
}

#[test]
fn memory_checkpoint_revision_retirement_preserves_history_and_reclaims_unreferenced_bytes(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let old = f.publish("retired-checkpoint-old", b"old-revision-material")?;
    let current = f.publish("retired-checkpoint-current", b"current-revision-material")?;
    let id = CheckpointId::new("retired-checkpoint")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&old), &[])?;
    f.runtime
        .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&current), &[])?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let retained = || -> TestResult<(String, i64, Vec<u8>)> {
        Ok(connection.query_row(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-checkpoint:v2:revision:*'
               AND json_extract(payload,'$.checkpoint')=?1
               AND json_extract(payload,'$.revision')=1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    };
    let before = retained()?;
    assert!(f.runtime.collect(&f.f.control, &old).is_err());
    let retired = f.runtime.retire_checkpoint_revision(&f.f.control, &id, 1);
    assert!(
        retired.is_ok(),
        "fresh admin authority must retire an exact historical revision"
    );
    retired?;
    assert_eq!(retained()?, before, "retirement retains immutable history");
    f.runtime.retire_checkpoint_revision(&f.f.control, &id, 1)?;
    let sink = f.sink();
    assert!(f
        .runtime
        .restore_into(
            &f.f.control,
            &id,
            1,
            &RequestId::new("retired-checkpoint-refusal")?,
            &sink,
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    f.runtime.collect(&f.f.control, &old)?;
    f.runtime.restore_into(
        &f.f.control,
        &id,
        0,
        &RequestId::new("retired-checkpoint-current")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, id.as_str(), 2, b"current-revision-material")?;
    assert_eq!(retained()?, before);
    Ok(())
}

#[test]
fn memory_checkpoint_retirement_cannot_release_uncertain_restore_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("uncertain-retirement", b"uncertain-restored-material")?;
    let id = CheckpointId::new("uncertain-retirement")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&reference), &[])?;
    let request = RequestId::new("uncertain-retirement")?;
    let failure = FailingRestoreSink {
        recipient: f.profile.recipients.as_slice()[0].recipient.clone(),
        attempts: AtomicUsize::new(0),
        store: f.f.authority.admission_operation_store(),
        actor: f.actor(RecoveryPermission::KnowledgeRead)?,
        fence: f.f.authority.mutation_fence(),
        request: request.clone(),
        observed: Mutex::new(Vec::new()),
    };
    assert!(f
        .runtime
        .restore_into(&f.f.control, &id, 1, &request, &failure)
        .is_err());
    assert_eq!(failure.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(restore_state(&f, &request)?, "uncertain");
    let retired = f.runtime.retire_checkpoint_revision(&f.f.control, &id, 1);
    assert!(retired.is_ok(), "an exact current revision can be retired");
    retired?;
    assert!(
        f.runtime.collect(&f.f.control, &reference).is_err(),
        "retiring the checkpoint cannot erase independent unknown custody"
    );
    let sink = f.sink();
    assert!(f
        .runtime
        .restore_into(&f.f.control, &id, 0, &request, &sink)
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert_eq!(restore_state(&f, &request)?, "uncertain");
    Ok(())
}

#[test]
fn memory_checkpoint_latest_retirement_preserves_consumed_revision_identity() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("retired-latest-first", b"retired-latest-material")?;
    let next = f.publish("retired-latest-next", b"new-live-checkpoint-material")?;
    let id = CheckpointId::new("retired-latest")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&first), &[])?;
    let retired = f.runtime.retire_checkpoint_revision(&f.f.control, &id, 1);
    assert!(retired.is_ok(), "admin retirement can disable the latest");
    retired?;
    f.runtime.collect(&f.f.control, &first)?;
    assert!(f
        .runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&next), &[])
        .is_err());
    let advanced = f
        .runtime
        .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&next), &[])?;
    assert_eq!(advanced.revision.get(), 2);
    let sink = f.sink();
    assert!(f
        .runtime
        .restore_into(
            &f.f.control,
            &id,
            1,
            &RequestId::new("retired-latest-old")?,
            &sink,
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    f.runtime.restore_into(
        &f.f.control,
        &id,
        0,
        &RequestId::new("retired-latest-live")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, id.as_str(), 2, b"new-live-checkpoint-material")?;
    Ok(())
}

#[tokio::test]
async fn memory_restore_public_outcome_and_replay_preserve_native_recipient_audience() -> TestResult
{
    use super::release_audience::{
        assert_opaque_outcome, install_read_actor, prime_native_recipient,
    };

    let f = KnowledgeFixture::from(semantic::native_fixture("read")?)?;
    let bytes = b"public-checkpoint-before-native-observation";
    let reference = f.publish("public-checkpoint-before-observation", bytes)?;
    assert_eq!(f.metadata(&reference)?.label, InformationLabel::bottom());
    let id = CheckpointId::new("public-checkpoint-before-observation")?;
    let checkpoint = f
        .runtime
        .checkpoint(&f.f.control, &id, 0, &[reference], &[])?;
    assert_eq!(checkpoint.label, InformationLabel::bottom());
    prime_native_recipient(&f).await?;

    let low = install_read_actor(
        &f,
        228,
        "public-checkpoint-outcome-reader",
        InformationLabel::bottom(),
    )?;
    let request = RequestId::new("opaque-public-checkpoint-outcome")?;
    let sink = f.sink();
    let first = f.runtime.restore_into(&low, &id, 1, &request, &sink)?;
    let value = serde_json::to_value(&first)?;
    let release = value.get("release").ok_or("release identity absent")?;
    let private_label: String = rusqlite::Connection::open(f.f.path.join("admission.db"))?
        .query_row(
            "SELECT json_extract(payload,'$.release.source_label')
             FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'
             AND json_extract(payload,'$.release.release')=?1",
            [release.as_str().ok_or("release identity is not text")?],
            |row| row.get(0),
        )?;
    assert_eq!(
        serde_json::from_str::<InformationLabel>(&private_label)?,
        restricted_label(),
        "private restore admission retains the full joined native source"
    );
    assert_restored_checkpoint(&sink, id.as_str(), 1, bytes)?;
    assert_opaque_outcome(&value);
    for _ in 0..2 {
        let replay = f.runtime.restore_into(&low, &id, 1, &request, &sink)?;
        let replay_value = serde_json::to_value(replay)?;
        assert_opaque_outcome(&replay_value);
        assert_eq!(replay_value, value, "the public outcome has a fixed shape");
    }
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 3);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 1);
    let joins: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(joins, 1, "public replay retains original read custody");
    Ok(())
}

#[test]
fn memory_checkpoint_retirement_rechecks_native_admin_after_actor_acquisition() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish(
        "fresh-retirement-admin",
        b"retained-admin-revocation-material",
    )?;
    let id = CheckpointId::new("fresh-retirement-admin")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&reference), &[])?;
    let acquired = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let store = f.f.authority.admission_operation_store();
    let installed = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut revoked = installed.clone();
    let mut actors = revoked.actors.as_slice().to_vec();
    let permissions = actors[0]
        .permissions
        .as_slice()
        .iter()
        .copied()
        .filter(|permission| *permission != RecoveryPermission::KnowledgeAdmin)
        .collect();
    actors[0].permissions = BoundedList::new(permissions)?;
    revoked.actors = NonEmptyBoundedList::new(actors)?;
    revoked.authority_scope = recovery_authority_scope_digest(&revoked)?;
    store.configure_recovery_deployment(&revoked)?;
    assert!(store
        .retire_checkpoint_revision(
            &acquired,
            &id,
            1,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    let retired: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-checkpoint-retired:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retired, 0, "stale actor acquisition grants no retirement");
    store.configure_recovery_deployment(&installed)?;
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    let sink = f.sink();
    f.runtime.restore_into(
        &f.f.control,
        &id,
        1,
        &RequestId::new("fresh-retirement-admin-remains-live")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, id.as_str(), 1, b"retained-admin-revocation-material")?;
    Ok(())
}

fn checkpoint_retirement_after_owner_ends(expired: bool) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("ended-checkpoint-owner", b"ended-owner-checkpoint-material")?;
    let id = CheckpointId::new("ended-checkpoint-owner")?;
    f.runtime
        .checkpoint(&f.f.control, &id, 0, std::slice::from_ref(&reference), &[])?;
    let reader = super::release_audience::install_read_actor(
        &f,
        229,
        "ended-checkpoint-read-only-actor",
        restricted_label(),
    )?;
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    assert!(f
        .runtime
        .retire_checkpoint_revision(&reader, &id, 1)
        .is_err());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let retained = || -> TestResult<Vec<(String, i64, Vec<u8>)>> {
        let mut statement = connection.prepare(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-checkpoint:*'
               AND json_extract(payload,'$.checkpoint')=?1 ORDER BY record_key",
        )?;
        let rows = statement.query_map([id.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    };
    let before = retained()?;
    assert_eq!(before.len(), 2);
    let after_expiry =
        f.f.seed
            .capability
            .expires_at
            .checked_add(1)
            .ok_or("execution expiry overflow")?;
    let _clock = if expired {
        assert!(f.f.control.expires_at > after_expiry);
        assert!(reader.expires_at > after_expiry);
        Some(chio_kernel::scope_fixed_runtime_for_current_thread(
            after_expiry,
            [],
        ))
    } else {
        assert!(f.f.process.cancel(f.profile.scope.process_id.as_str())? > 0);
        None
    };
    if expired {
        assert!(f
            .f
            .kernel
            .verify_retained_capability_liveness(
                &f.f.seed.capability.id,
                &f.f.seed.capability.subject,
            )
            .is_err());
    }
    let admin = f
        .actor(RecoveryPermission::KnowledgeAdmin)
        .map_err(|error| {
            format!("ended checkpoint owner fresh native Admin acquisition: {error}")
        })?;
    assert_eq!(admin.permission(), RecoveryPermission::KnowledgeAdmin);
    assert!(f
        .broker
        .validate_process(&f.profile.scope.process_id, &f.profile.producer_context)
        .is_err());
    assert!(f
        .runtime
        .retire_checkpoint_revision(&reader, &id, 1)
        .is_err());
    assert!(f
        .runtime
        .checkpoint(&f.f.control, &id, 1, std::slice::from_ref(&reference), &[])
        .is_err());
    let sink = f.sink();
    assert!(f
        .runtime
        .restore_into(
            &f.f.control,
            &id,
            1,
            &RequestId::new("ended-owner-restore-refused")?,
            &sink,
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());

    f.runtime
        .retire_checkpoint_revision(&f.f.control, &id, 1)
        .map_err(|error| format!("fresh admin retirement of ended checkpoint owner: {error}"))?;
    let replay_time = if expired {
        after_expiry
            .checked_mul(1000)
            .ok_or("selected expiry clock milliseconds overflow")?
    } else {
        now_ms()?
    };
    f.f.authority
        .admission_operation_store()
        .retire_checkpoint_revision(&admin, &id, 1, &f.f.authority.mutation_fence(), replay_time)
        .map_err(|error| {
            format!("ended checkpoint owner direct Admin retirement replay: {error}")
        })?;
    assert_eq!(
        retained()?,
        before,
        "cleanup retains immutable checkpoint evidence"
    );
    f.runtime
        .collect(&f.f.control, &reference)
        .map_err(|error| format!("ended checkpoint owner post-retirement collection: {error}"))?;
    let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(after.tree_bytes, 0);
    assert_eq!(after.tree_blobs, 0);
    assert!(f
        .broker
        .validate_process(&f.profile.scope.process_id, &f.profile.producer_context)
        .is_err());
    let process = f.f.process.process(f.profile.scope.process_id.as_str())?;
    assert_eq!(
        process.state,
        if expired {
            chio_process::ProcessState::Running
        } else {
            chio_process::ProcessState::Cancelled
        }
    );
    if expired {
        assert!(f
            .f
            .kernel
            .verify_retained_capability_liveness(
                &f.f.seed.capability.id,
                &f.f.seed.capability.subject,
            )
            .is_err());
    }
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn memory_fresh_admin_retires_cancelled_owner_checkpoint_without_restoring_execution() -> TestResult
{
    checkpoint_retirement_after_owner_ends(false)
}

#[test]
fn memory_fresh_admin_retires_expired_owner_checkpoint_without_renewing_execution() -> TestResult {
    checkpoint_retirement_after_owner_ends(true)
}

fn checkpoint_chunk_label(
    tag: &str,
    owners: usize,
    readers_per_owner: usize,
) -> TestResult<InformationLabel> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut policies = BTreeMap::new();
    for index in 0..owners {
        let owner = chio_security_types::PrincipalId::new(format!("chunk-{tag}-owner-{index}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..readers_per_owner {
            let prefix = format!("chunk-{tag}-reader-{index}-{reader:02}-");
            readers.insert(chio_security_types::PrincipalId::new(format!(
                "{prefix}{}",
                "r".repeat(255usize.checked_sub(prefix.len()).ok_or("reader bound")?)
            ))?);
        }
        policies.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(policies, BTreeSet::new())?)
}

fn checkpoint_chunk_snapshot(
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
    Ok(observed
        .snapshot()
        .ok_or("chunk native snapshot absent")?
        .clone())
}

fn checkpoint_chunk_kernel_error_class(error: &KernelError) -> &'static str {
    match error {
        KernelError::CapabilityExpired => "capability_expired",
        KernelError::CapabilityNotYetValid => "capability_not_yet_valid",
        KernelError::CapabilityRevoked(_) => "capability_revoked",
        KernelError::InvalidSignature => "invalid_signature",
        KernelError::UntrustedIssuer => "untrusted_issuer",
        KernelError::RecoveryAuthorityDenied => "recovery_authority_denied",
        KernelError::RecoveryMediationRequired => "recovery_mediation_required",
        KernelError::DurableAdmission(_) => "durable_admission",
        KernelError::DurableAdmissionRetained(_) => "durable_admission_retained",
        KernelError::Internal(reason) if reason == "chunked restore acknowledgement lost" => {
            "expected_lost_acknowledgement"
        }
        KernelError::Internal(_) => "internal",
        _ => "other_kernel_error",
    }
}

fn checkpoint_chunk_test_error_class(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if let Some(error) = error.downcast_ref::<KernelError>() {
        return checkpoint_chunk_kernel_error_class(error);
    }
    if let Some(error) =
        error.downcast_ref::<chio_kernel::admission_operation::AdmissionOperationStoreError>()
    {
        use chio_kernel::admission_operation::AdmissionOperationStoreError;
        return match error {
            AdmissionOperationStoreError::RecoveryAuthorityDenied => "store_authority_denied",
            AdmissionOperationStoreError::RecoveryMediationRequired => "store_mediation_required",
            AdmissionOperationStoreError::Unavailable(_) => "store_unavailable",
            AdmissionOperationStoreError::Fenced => "store_fenced",
            AdmissionOperationStoreError::NotFound => "store_not_found",
            AdmissionOperationStoreError::Invariant(_) => "store_invariant",
            AdmissionOperationStoreError::OutcomeUnknown(_) => "store_outcome_unknown",
            AdmissionOperationStoreError::Operation(_) => "store_operation",
        };
    }
    "other_test_error"
}

mod chunk_phase_progress;

// Tag the exact caller before evaluating an operation, including callbacks and
// assertion helpers. The result and its original typed error remain unchanged.
macro_rules! checkpoint_chunk_phase {
    ($fixture:expr, $phase:literal, $index:expr, $operation:expr) => {{
        let phase: &'static str = $phase;
        let index: Option<usize> = $index;
        eprintln!(
            "{}",
            serde_json::json!({"phase": phase, "index": index, "status": "entered"})
        );
        checkpoint_chunk_phase_result($fixture, phase, index, $operation)
    }};
}

fn checkpoint_chunk_phase_result<T, E: 'static>(
    fixture: Option<&KnowledgeFixture>,
    phase: &'static str,
    index: Option<usize>,
    result: Result<T, E>,
) -> Result<T, E> {
    match &result {
        Ok(_) => eprintln!(
            "{}",
            serde_json::json!({"phase": phase, "index": index, "status": "complete"})
        ),
        Err(error) => {
            let diagnostic = serde_json::json!({
                "phase": phase,
                "index": index,
                "status": "error",
                "error_class": checkpoint_chunk_phase_error_class(error),
                "progress": fixture.map(chunk_phase_progress::checkpoint_chunk_failure_progress),
            });
            eprintln!("{diagnostic}");
        }
    }
    result
}

fn checkpoint_chunk_phase_error_class<E: 'static>(error: &E) -> &'static str {
    let error: &dyn std::any::Any = error;
    if let Some(error) = error.downcast_ref::<Box<dyn std::error::Error>>() {
        return checkpoint_chunk_test_error_class(error.as_ref());
    }
    if let Some(error) = error.downcast_ref::<KernelError>() {
        return checkpoint_chunk_kernel_error_class(error);
    }
    if let Some(error) =
        error.downcast_ref::<chio_kernel::admission_operation::AdmissionOperationStoreError>()
    {
        return checkpoint_chunk_test_error_class(error);
    }
    if error.is::<rusqlite::Error>() {
        return "diagnostic_sql_error";
    }
    if error.is::<serde_json::Error>() {
        return "diagnostic_json_error";
    }
    "other_test_error"
}

#[test]
fn memory_checkpoint_chunked_restore_preserves_exact_custody_and_reopen() -> TestResult {
    use std::collections::{BTreeMap, BTreeSet};
    let mut f = checkpoint_chunk_phase!(
        None,
        "chunk_custody_fixture_open",
        None,
        KnowledgeFixture::new()
    )?;
    let historical = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_historical_label",
        None,
        checkpoint_chunk_label("history", 6, 64)
    )?;
    let incoming = [
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_incoming_label",
            Some(0),
            checkpoint_chunk_label("one", 4, 60)
        )?,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_incoming_label",
            Some(1),
            checkpoint_chunk_label("two", 4, 60)
        )?,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_incoming_label",
            Some(2),
            checkpoint_chunk_label("three", 4, 60)
        )?,
    ];
    let mut joined = historical.clone();
    for (label_index, label) in incoming.iter().enumerate() {
        joined = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_input_label_join",
            Some(label_index),
            joined.join_restrictions(label)
        )?;
    }
    let InformationLabel::Known {
        owners,
        compartments,
        ..
    } = &joined
    else {
        return Err("chunk inputs must retain a finite native label".into());
    };
    // A stricter finite audience contains every owner and only its self-reader.
    // It accepts each full source without copying a large label into a profile.
    let clearance = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_finite_clearance",
        None,
        InformationLabel::try_known(
            owners
                .keys()
                .map(|owner| (owner.clone(), BTreeSet::from([owner.clone()])))
                .collect::<BTreeMap<_, _>>(),
            compartments.clone(),
        )
    )?;
    assert!(!matches!(clearance, InformationLabel::Top));
    assert!(joined.flows_to(&clearance));
    assert!(historical.flows_to(&clearance));
    for (label_index, label) in incoming.iter().enumerate() {
        assert!(label.flows_to(&clearance));
        assert!(
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_incoming_label_bytes",
                Some(label_index),
                chio_core_types::canonical_json_bytes(label)
            )?
            .len()
                < 64 * 1024
        );
    }
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_historical_label_bytes",
            None,
            chio_core_types::canonical_json_bytes(&historical)
        )?
        .len()
            < 104 * 1024
    );
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_joined_label_lower_bound",
            None,
            chio_core_types::canonical_json_bytes(&joined)
        )?
        .len()
            > 256 * 1024
    );
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_joined_label_upper_bound",
            None,
            chio_core_types::canonical_json_bytes(&joined)
        )?
        .len()
            < 512 * 1024
    );

    let store = f.f.authority.admission_operation_store();
    let mut deployment = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_native_deployment_read",
        None,
        f.f.kernel.recovery_deployment(&f.profile.scope)
    )?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = clearance.clone();
    deployment.actors = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_actor_list",
        None,
        NonEmptyBoundedList::new(actors)
    )?;
    deployment.authority_scope = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_authority_scope_digest",
        None,
        recovery_authority_scope_digest(&deployment)
    )?;
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_actor_installation",
        None,
        store.configure_recovery_deployment(&deployment)
    )
    .map_err(|error| format!("chunk finite actor installation: {error}"))?;
    let mut profile = f.profile.clone();
    profile.generation = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_profile_generation",
        None,
        SafeInteger::new(2)
    )?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = clearance;
    profile.recipients = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_recipient_list",
        None,
        NonEmptyBoundedList::new(recipients)
    )?;
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_profile_installation",
        None,
        store.configure_knowledge(&profile)
    )
    .map_err(|error| format!("chunk finite recipient installation: {error}"))?;
    f.profile = profile.clone();

    let body = b"exact-chunked-checkpoint-material";
    let mut saved = Vec::new();
    for (index, label) in incoming.iter().enumerate() {
        let reference = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_incoming_publication",
            Some(index),
            publish_label(&f, &format!("chunk-incoming-{index}"), body, label.clone())
        )
        .map_err(|error| format!("chunk genuine incoming publication {index}: {error}"))?;
        let checkpoint = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_checkpoint_save",
            Some(index),
            f.runtime.checkpoint(
                &f.f.control,
                &checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_checkpoint_identity",
                    Some(index),
                    CheckpointId::new(&format!("chunk-checkpoint-{index}"))
                )?,
                0,
                std::slice::from_ref(&reference),
                &[],
            )
        )
        .map_err(|error| format!("chunk genuine bounded checkpoint {index}: {error}"))?;
        assert_eq!(checkpoint.label, *label);
        assert!(
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_checkpoint_envelope_bytes",
                Some(index),
                chio_core_types::canonical_json_bytes(&checkpoint)
            )?
            .len()
                <= 65_536
        );
        saved.push(checkpoint);
    }
    let before = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_initial_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());

    // The initial artifact's exact metadata and classification certificate fit
    // ordinary protected rows. Every later native floor comes from real reads
    // and restores of the already published, bounded checkpoint envelopes.
    let reference = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_historical_publication",
        None,
        publish_label(
            &f,
            "chunk-native-history",
            b"native-history",
            historical.clone(),
        )
    )
    .map_err(|error| format!("chunk genuine historical publication: {error}"))?;
    let handle = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_historical_handle",
        None,
        f.runtime.handle(
            &f.f.control,
            &reference,
            &checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_historical_recipient_identity",
                None,
                ArtifactRecipientId::new("agent-root")
            )?,
        )
    )?;
    let history_sink = f.sink();
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_historical_release",
        None,
        f.runtime.release_into(
            &f.f.control,
            &checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_historical_request_identity",
                None,
                RequestId::new("chunk-native-history")
            )?,
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_historical_prepare_read",
                None,
                f.runtime.prepare_read(&f.f.control, &handle)
            )?,
            &history_sink,
        )
    )
    .map_err(|error| format!("chunk genuine historical release: {error}"))?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_historical_sink_lock",
            None,
            history_sink.delivered.lock().map_err(|_| "history sink")
        )?
        .as_slice(),
        &[b"native-history".to_vec()]
    );
    let history = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_historical_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(history.principal_label, historical);
    assert_eq!(history.lineage_label, historical);
    assert_eq!(history.session_label, historical);
    let mut expected = historical.clone();
    for (index, checkpoint) in saved.iter().take(2).enumerate() {
        let sink = f.sink();
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_intermediate_restore",
            Some(index),
            f.runtime.restore_into(
                &f.f.control,
                &checkpoint.checkpoint,
                1,
                &checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_intermediate_request_identity",
                    Some(index),
                    RequestId::new(&format!("chunk-native-floor-{index}"))
                )?,
                &sink,
            )
        )
        .map_err(|error| format!("chunk genuine intermediate restore {index}: {error}"))?;
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_intermediate_frame",
            Some(index),
            assert_exact_checkpoint_frame(&sink, checkpoint, body)
        )?;
        expected = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_intermediate_expected_label",
            Some(index),
            expected.join_restrictions(&incoming[index])
        )?;
        let observed = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_intermediate_native_snapshot",
            Some(index),
            checkpoint_chunk_snapshot(&f)
        )?;
        assert_eq!(observed.principal_label, expected);
        assert_eq!(observed.lineage_label, expected);
        assert_eq!(observed.session_label, expected);
    }

    let checkpoint = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_checkpoint_presence",
        None,
        saved.last().ok_or("final chunk checkpoint absent")
    )?
    .clone();
    let request = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_request_identity",
        None,
        RequestId::new("chunked-checkpoint-lost-ack")
    )?;
    let _restore_inner_trace = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_inner_restore_observer_install",
        None,
        f.runtime
            .observe_checkpoint_restore_stages_for_test(&request)
    )?;
    let _process_validation_trace = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_process_validation_observer_install",
        None,
        f.broker
            .observe_checkpoint_process_validation_fixture(&f.profile.scope.process_id, &request)
    )?;
    let captured = Arc::new(Mutex::new(None::<(u64, Vec<u8>)>));
    let capture = captured.clone();
    let capture_store = f.f.authority.admission_operation_store();
    let capture_actor = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_capture_read_authority",
        None,
        f.actor(RecoveryPermission::KnowledgeRead)
    )?;
    let capture_fence = f.f.authority.mutation_fence();
    let capture_request = request.clone();
    let capture_database = f.f.path.join("admission.db");
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == KnowledgeCutpoint::ReleaseCommitted
            && checkpoint_chunk_phase!(
                None,
                "chunk_custody_capture_lock_read",
                None,
                capture
                    .lock()
                    .map_err(|_| KernelError::Internal("root capture".into()))
            )?
            .is_none()
        {
            let (release, state) = checkpoint_chunk_phase!(
                None,
                "chunk_custody_capture_owner_presence",
                None,
                checkpoint_chunk_phase!(
                    None,
                    "chunk_custody_capture_owner_read",
                    None,
                    capture_store.checkpoint_restore_outcome_fixture(
                        &capture_actor,
                        &capture_request,
                        &capture_fence,
                        checkpoint_chunk_phase!(
                            None,
                            "chunk_custody_capture_clock",
                            None,
                            now_ms()
                        )
                        .map_err(|error| {
                            KernelError::Internal(format!("capture clock: {error}"))
                        })?,
                    )
                )
                .map_err(|error| KernelError::Internal(format!("capture owner: {error}")))?
                .ok_or_else(|| KernelError::Internal("capture outcome absent".into()))
            )?;
            if state != ArtifactDeliveryStateV1::Admitted {
                return checkpoint_chunk_phase!(
                    None,
                    "chunk_custody_capture_not_admitted",
                    None,
                    Err(KernelError::Internal(
                        "capture follows outcome mutation".into(),
                    ))
                );
            }
            let connection = checkpoint_chunk_phase!(
                None,
                "chunk_custody_capture_database_open",
                None,
                rusqlite::Connection::open(&capture_database)
            )
            .map_err(|error| KernelError::Internal(format!("capture connection: {error}")))?;
            let original: (i64, Vec<u8>) = checkpoint_chunk_phase!(
                None,
                "chunk_custody_capture_root_query",
                None,
                connection.query_row(
                    "SELECT version,payload FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'knowledge-restore:*'
                   AND json_extract(payload,'$.intent.release')=?1",
                    [release.as_str()],
                    |row| Ok((
                        checkpoint_chunk_phase!(
                            None,
                            "chunk_custody_capture_version_column",
                            None,
                            row.get(0)
                        )?,
                        checkpoint_chunk_phase!(
                            None,
                            "chunk_custody_capture_payload_column",
                            None,
                            row.get(1)
                        )?
                    )),
                )
            )
            .map_err(|error| KernelError::Internal(format!("capture source: {error}")))?;
            if original.0 != 1 {
                return checkpoint_chunk_phase!(
                    None,
                    "chunk_custody_capture_not_original_version",
                    None,
                    Err(KernelError::Internal(
                        "capture lost original version".into(),
                    ))
                );
            }
            *checkpoint_chunk_phase!(
                None,
                "chunk_custody_capture_lock_write",
                None,
                capture
                    .lock()
                    .map_err(|_| KernelError::Internal("root capture".into()))
            )? = Some((
                checkpoint_chunk_phase!(
                    None,
                    "chunk_custody_capture_version_conversion",
                    None,
                    u64::try_from(original.0)
                        .map_err(|_| KernelError::Internal("capture version".into()))
                )?,
                original.1,
            ));
        }
        if stage == KnowledgeCutpoint::DeliveryCompleted {
            return checkpoint_chunk_phase!(
                None,
                "chunk_custody_delivery_completed_fault",
                None,
                Err(KernelError::Internal(
                    "chunked restore acknowledgement lost".into(),
                ))
            );
        }
        Ok(())
    }));
    let encoding_observer = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_encoding_observer_install",
        None,
        store.observe_knowledge_join_encoding_fixture(&f.profile.scope, &request)
    )?;
    let sink = f.sink();
    let final_restore = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_restore",
        None,
        faulty.restore_into(&f.f.control, &checkpoint.checkpoint, 1, &request, &sink)
    );
    let delivered_frames = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_sink_lock",
        None,
        sink.delivered.lock().map_err(|_| "chunk final sink")
    )?
    .len();
    if delivered_frames == 0 {
        let release_committed = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_capture_lock",
            None,
            captured.lock().map_err(|_| "root capture")
        )?
        .is_some();
        let journal = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_journal_wire_bytes",
            None,
            store.knowledge_join_encoding_fixture(&f.profile.scope, &request)
        )?;
        let restore = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_restore_wire_bytes",
            None,
            store.restore_record_encoding_fixture(&f.profile.scope, &request)
        )?;
        let current_auth = match checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_current_authority",
            None,
            f.actor(RecoveryPermission::KnowledgeRead)
        ) {
            Ok(actor) => serde_json::json!({
                "accepted": actor.permission() == RecoveryPermission::KnowledgeRead,
                "error_class": null,
            }),
            Err(error) => serde_json::json!({
                "accepted": false,
                "error_class": checkpoint_chunk_test_error_class(error.as_ref()),
            }),
        };
        let outcome = match checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_current_outcome",
            None,
            restore_outcome(&f, &request)
        ) {
            Ok((_, state)) => serde_json::json!({
                "present": true,
                "state": state,
                "error_class": null,
            }),
            Err(error) => serde_json::json!({
                "present": false,
                "state": null,
                "error_class": checkpoint_chunk_test_error_class(error.as_ref()),
            }),
        };
        let native_phase = match checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_native_snapshot",
            None,
            checkpoint_chunk_snapshot(&f)
        ) {
            Ok(snapshot) => {
                let before_join = snapshot.principal_label == expected
                    && snapshot.lineage_label == expected
                    && snapshot.session_label == expected;
                let after_join = snapshot.principal_label == joined
                    && snapshot.lineage_label == joined
                    && snapshot.session_label == joined;
                let label_bytes = [
                    checkpoint_chunk_phase!(
                        Some(&f),
                        "chunk_custody_diagnostic_principal_bytes",
                        None,
                        chio_core_types::canonical_json_bytes(&snapshot.principal_label)
                    )
                    .map(|bytes| bytes.len())
                    .ok(),
                    checkpoint_chunk_phase!(
                        Some(&f),
                        "chunk_custody_diagnostic_lineage_bytes",
                        None,
                        chio_core_types::canonical_json_bytes(&snapshot.lineage_label)
                    )
                    .map(|bytes| bytes.len())
                    .ok(),
                    checkpoint_chunk_phase!(
                        Some(&f),
                        "chunk_custody_diagnostic_session_bytes",
                        None,
                        chio_core_types::canonical_json_bytes(&snapshot.session_label)
                    )
                    .map(|bytes| bytes.len())
                    .ok(),
                ];
                serde_json::json!({
                    "observed": true,
                    "before_join": before_join,
                    "after_join": after_join,
                    "label_bytes": label_bytes,
                    "error_class": null,
                })
            }
            Err(error) => serde_json::json!({
                "observed": false,
                "before_join": null,
                "after_join": null,
                "label_bytes": null,
                "error_class": checkpoint_chunk_test_error_class(error.as_ref()),
            }),
        };
        let diagnostic = serde_json::json!({
            "phase": "chunk_final_restore_before_delivery",
            "restore_returned_success": final_restore.is_ok(),
            "restore_error_class": final_restore.as_ref().err()
                .map(checkpoint_chunk_kernel_error_class),
            "delivered_frames": delivered_frames,
            "release_committed": release_committed,
            "journal_wire_and_change_image_bytes": journal,
            "restore_wire_bytes": restore,
            "current_read_authority": current_auth,
            "authenticated_outcome": outcome,
            "native_phase": native_phase,
        });
        return Err(checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_diagnostic_json_encoding",
            None,
            serde_json::to_string(&diagnostic)
        )?
        .into());
    }
    assert!(final_restore.is_err());
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_frame",
        None,
        assert_exact_checkpoint_frame(&sink, &checkpoint, body)
    )?;
    drop(encoding_observer);
    let (release, fate) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_outcome",
        None,
        restore_outcome(&f, &request)
    )?;
    assert_eq!(fate, ArtifactDeliveryStateV1::Uncertain);
    let observed = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_final_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(observed.principal_label, joined);
    assert_eq!(observed.lineage_label, joined);
    assert_eq!(observed.session_label, joined);

    let connection = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_outcome_database_open",
        None,
        rusqlite::Connection::open(f.f.path.join("admission.db"))
    )?;
    let (root_key, payload): (String, Vec<u8>) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_outcome_root_query",
        None,
        connection.query_row(
            "SELECT record_key,payload FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-restore:*'
           AND json_extract(payload,'$.intent.release')=?1",
            [release.as_str()],
            |row| Ok((
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_outcome_root_key_column",
                    None,
                    row.get(0)
                )?,
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_outcome_root_payload_column",
                    None,
                    row.get(1)
                )?
            )),
        )
    )?;
    let root: serde_json::Value = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_outcome_root_json",
        None,
        serde_json::from_slice(&payload)
    )?;
    assert_eq!(
        root["checkpoint_restore_encoding"],
        "chunked_label_atoms_v1"
    );
    assert_eq!(root["body"]["knowledge_chunk_encoding"], "label_atoms_v1");
    assert!(payload.len() <= 262_144);
    let journal_payload: Vec<u8> = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_outcome_journal_query",
        None,
        connection.query_row(
            "SELECT payload FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*'
           AND json_extract(payload,'$.release.release')=?1",
            [release.as_str()],
            |row| checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_sql_result_column",
                None,
                row.get(0)
            ),
        )
    )?;
    let journal: serde_json::Value = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_outcome_journal_json",
        None,
        serde_json::from_slice(&journal_payload)
    )?;
    assert_eq!(journal["knowledge_join_encoding"], "chunked_label_atoms_v1");
    assert_eq!(
        journal["body"]["knowledge_chunk_encoding"],
        "label_atoms_v1"
    );
    assert!(journal_payload.len() <= 262_144);
    let journal_chunks = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_journal_chunk_count",
        None,
        journal["body"]["chunk_count"]
            .as_u64()
            .ok_or("journal chunks")
    )?;
    assert!(journal_chunks > 1);
    let journal_digest = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_journal_body_digest",
        None,
        journal["body"]["body_digest"]
            .as_str()
            .ok_or("journal chunk digest")
    )?;
    let actual_journal_chunks: i64 = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_physical_journal_chunks",
        None,
        connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-encoding-chunk:*'
           AND json_extract(payload,'$.owner.kind')='journal'
           AND json_extract(payload,'$.owner.release')=?1
           AND json_extract(payload,'$.body_digest')=?2
           AND version=1 AND kind='command'
           AND native_namespace IS NULL AND native_request IS NULL
           AND length(payload)<=262144",
            (release.as_str(), journal_digest),
            |row| checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_sql_result_column",
                None,
                row.get(0)
            ),
        )
    )?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_physical_journal_count_conversion",
            None,
            u64::try_from(actual_journal_chunks)
        )?,
        journal_chunks
    );
    let expected_chunks = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_restore_chunk_count",
        None,
        root["body"]["chunk_count"].as_u64().ok_or("chunk count")
    )?;
    assert!(expected_chunks > 1);
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_restore_body_bytes",
            None,
            root["body"]["body_bytes"]
                .as_u64()
                .ok_or("chunk body bytes")
        )? > 262_144
    );
    let digest = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_restore_body_digest",
        None,
        root["body"]["body_digest"]
            .as_str()
            .ok_or("chunk body digest")
    )?;
    let (count, bounded): (i64, bool) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_physical_restore_chunks",
        None,
        connection.query_row(
            "SELECT count(*),coalesce(min(version=1 AND kind='command'
            AND native_namespace IS NULL AND native_request IS NULL
            AND length(payload)<=262144),0)
         FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-encoding-chunk:*'
           AND json_extract(payload,'$.owner.kind')='restore'
           AND json_extract(payload,'$.owner.record_key')=?1
           AND json_extract(payload,'$.body_digest')=?2",
            (&root_key, digest),
            |row| Ok((
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_physical_restore_count_column",
                    None,
                    row.get(0)
                )?,
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_physical_restore_bounds_column",
                    None,
                    row.get(1)
                )?
            )),
        )
    )?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_physical_restore_count_conversion",
            None,
            u64::try_from(count)
        )?,
        expected_chunks
    );
    assert!(
        bounded,
        "every real immutable chunk keeps the original row ceiling"
    );

    let native_before_retry = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_retry_native_baseline",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    let native_journals_before: i64 = checkpoint_chunk_phase!(Some(&f), "chunk_custody_retry_journal_baseline", None, connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",
        [], |row| checkpoint_chunk_phase!(Some(&f), "chunk_custody_sql_result_column", None, row.get(0)),
    ))?;
    let retry_sink = f.sink();
    let completed = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_retry_restore",
        None,
        f.runtime.restore_into(
            &f.f.control,
            &checkpoint.checkpoint,
            1,
            &request,
            &retry_sink,
        )
    )?;
    assert_eq!(completed.release, release);
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_retry_frame",
        None,
        assert_exact_checkpoint_frame(&retry_sink, &checkpoint, body)
    )?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_retry_outcome",
            None,
            restore_outcome(&f, &request)
        )?
        .1,
        ArtifactDeliveryStateV1::Delivered
    );
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_retry_native_snapshot",
            None,
            checkpoint_chunk_snapshot(&f)
        )?,
        native_before_retry
    );
    let native_journals_after_retry: i64 = checkpoint_chunk_phase!(Some(&f), "chunk_custody_retry_journal_count", None, connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",
        [], |row| checkpoint_chunk_phase!(Some(&f), "chunk_custody_sql_result_column", None, row.get(0)),
    ))?;
    assert_eq!(native_journals_after_retry, native_journals_before);
    let later_sink = f.sink();
    assert!(checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_delivered_replay_restore",
        None,
        faulty.restore_into(
            &f.f.control,
            &checkpoint.checkpoint,
            1,
            &request,
            &later_sink,
        )
    )
    .is_err());
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_delivered_replay_frame",
        None,
        assert_exact_checkpoint_frame(&later_sink, &checkpoint, body)
    )?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_delivered_replay_outcome",
            None,
            restore_outcome(&f, &request)
        )?
        .1,
        ArtifactDeliveryStateV1::Delivered
    );
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_delivered_replay_native_snapshot",
            None,
            checkpoint_chunk_snapshot(&f)
        )?,
        native_before_retry
    );
    let native_journals_after_replay: i64 = checkpoint_chunk_phase!(Some(&f), "chunk_custody_delivered_replay_journal_count", None, connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",
        [], |row| checkpoint_chunk_phase!(Some(&f), "chunk_custody_sql_result_column", None, row.get(0)),
    ))?;
    assert_eq!(native_journals_after_replay, native_journals_before);
    let (original_version, original_root) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_original_capture_presence",
        None,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_original_capture_lock",
            None,
            captured.lock().map_err(|_| "root capture")
        )?
        .clone()
        .ok_or("original root capture absent")
    )?;
    assert_eq!(original_version, 1);
    let original_root_json: serde_json::Value = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_original_root_json",
        None,
        serde_json::from_slice(&original_root)
    )?;
    assert_eq!(
        original_root_json["checkpoint_restore_encoding"],
        "chunked_label_atoms_v1"
    );
    let current_version: i64 = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_custody_current_root_version",
        None,
        connection.query_row(
            "SELECT version FROM admission_operation_recovery_records WHERE record_key=?1",
            [&root_key],
            |row| checkpoint_chunk_phase!(
                Some(&f),
                "chunk_custody_sql_result_column",
                None,
                row.get(0)
            ),
        )
    )?;
    assert_eq!(current_version, 3);
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_custody_historical_original_read",
            None,
            store.checkpoint_restore_historical_outcome_fixture(
                &checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_historical_read_authority",
                    None,
                    f.actor(RecoveryPermission::KnowledgeRead)
                )?,
                &request,
                original_version,
                &original_root,
                &f.f.authority.mutation_fence(),
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_custody_historical_read_clock",
                    None,
                    now_ms()
                )?,
            )
        )?,
        (release.clone(), ArtifactDeliveryStateV1::Admitted)
    );
    drop(faulty);

    let original = f.f.control.clone();
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(connection);
    drop(store);
    drop(_process_validation_trace);
    drop(_restore_inner_trace);
    drop(f);
    let mut reopened = checkpoint_chunk_phase!(
        None,
        "chunk_custody_reopen_fixture",
        None,
        RecoveryFixture::open(path, directory, false)
    )?;
    reopened.control = original;
    let broker = Arc::new(checkpoint_chunk_phase!(
        None,
        "chunk_custody_reopen_broker",
        None,
        reopened.process.enable_durable_knowledge()
    )?);
    let runtime = checkpoint_chunk_phase!(
        None,
        "chunk_custody_reopen_runtime",
        None,
        NativeKnowledgeRuntime::new(
            reopened.kernel.clone(),
            Arc::new(reopened.authority.admission_operation_store()),
            broker.clone(),
            profile.clone(),
            reopened.authority.mutation_fence(),
        )
    )?;
    let reopened = KnowledgeFixture {
        f: reopened,
        runtime,
        profile,
        broker,
        certificate: Keypair::from_seed(&[217; 32]),
    };
    let replay_sink = reopened.sink();
    let replay = checkpoint_chunk_phase!(
        Some(&reopened),
        "chunk_custody_reopen_restore",
        None,
        reopened.runtime.restore_into(
            &reopened.f.control,
            &checkpoint.checkpoint,
            1,
            &request,
            &replay_sink,
        )
    )?;
    assert_eq!(replay.release, release);
    checkpoint_chunk_phase!(
        Some(&reopened),
        "chunk_custody_reopen_frame",
        None,
        assert_exact_checkpoint_frame(&replay_sink, &checkpoint, body)
    )?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&reopened),
            "chunk_custody_reopen_outcome",
            None,
            restore_outcome(&reopened, &request)
        )?
        .1,
        ArtifactDeliveryStateV1::Delivered
    );
    let replayed = checkpoint_chunk_phase!(
        Some(&reopened),
        "chunk_custody_reopen_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&reopened)
    )?;
    assert_eq!(replayed, native_before_retry);
    let replayed_connection = checkpoint_chunk_phase!(
        Some(&reopened),
        "chunk_custody_reopen_database_open",
        None,
        rusqlite::Connection::open(reopened.f.path.join("admission.db"))
    )?;
    let native_journals_after_reopen: i64 = checkpoint_chunk_phase!(Some(&reopened), "chunk_custody_reopen_journal_count", None, replayed_connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",
        [], |row| checkpoint_chunk_phase!(Some(&reopened), "chunk_custody_sql_result_column", None, row.get(0)),
    ))?;
    assert_eq!(native_journals_after_reopen, native_journals_before);
    assert_eq!(replayed.principal_label, joined);
    assert_eq!(replayed.lineage_label, joined);
    assert_eq!(replayed.session_label, joined);
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&reopened),
            "chunk_custody_reopen_historical_original_read",
            None,
            reopened
                .f
                .authority
                .admission_operation_store()
                .checkpoint_restore_historical_outcome_fixture(
                    &checkpoint_chunk_phase!(
                        Some(&reopened),
                        "chunk_custody_reopen_historical_read_authority",
                        None,
                        reopened.actor(RecoveryPermission::KnowledgeRead)
                    )?,
                    &request,
                    original_version,
                    &original_root,
                    &reopened.f.authority.mutation_fence(),
                    checkpoint_chunk_phase!(
                        Some(&reopened),
                        "chunk_custody_reopen_historical_read_clock",
                        None,
                        now_ms()
                    )?,
                )
        )?,
        (release, ArtifactDeliveryStateV1::Admitted)
    );
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn memory_checkpoint_uncertain_ack_refuses_an_authenticated_extra_chunk_prefix() -> TestResult {
    use std::collections::{BTreeMap, BTreeSet};
    let mut f = checkpoint_chunk_phase!(
        None,
        "chunk_prefix_fixture_open",
        None,
        KnowledgeFixture::new()
    )?;
    let historical = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_historical_label",
        None,
        checkpoint_chunk_label("history", 6, 64)
    )?;
    let incoming = [
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_incoming_label",
            Some(0),
            checkpoint_chunk_label("one", 4, 60)
        )?,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_incoming_label",
            Some(1),
            checkpoint_chunk_label("two", 4, 60)
        )?,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_incoming_label",
            Some(2),
            checkpoint_chunk_label("three", 4, 60)
        )?,
    ];
    let mut joined = historical.clone();
    for (label_index, label) in incoming.iter().enumerate() {
        joined = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_input_label_join",
            Some(label_index),
            joined.join_restrictions(label)
        )?;
    }
    let InformationLabel::Known {
        owners,
        compartments,
        ..
    } = &joined
    else {
        return Err("chunk inputs must retain a finite native label".into());
    };
    // A stricter finite audience contains every owner and only its self-reader.
    // It accepts each full source without copying a large label into a profile.
    let clearance = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_finite_clearance",
        None,
        InformationLabel::try_known(
            owners
                .keys()
                .map(|owner| (owner.clone(), BTreeSet::from([owner.clone()])))
                .collect::<BTreeMap<_, _>>(),
            compartments.clone(),
        )
    )?;
    assert!(!matches!(clearance, InformationLabel::Top));
    assert!(joined.flows_to(&clearance));
    assert!(historical.flows_to(&clearance));
    for (label_index, label) in incoming.iter().enumerate() {
        assert!(label.flows_to(&clearance));
        assert!(
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_incoming_label_bytes",
                Some(label_index),
                chio_core_types::canonical_json_bytes(label)
            )?
            .len()
                < 64 * 1024
        );
    }
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_historical_label_bytes",
            None,
            chio_core_types::canonical_json_bytes(&historical)
        )?
        .len()
            < 104 * 1024
    );
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_joined_label_lower_bound",
            None,
            chio_core_types::canonical_json_bytes(&joined)
        )?
        .len()
            > 256 * 1024
    );
    assert!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_joined_label_upper_bound",
            None,
            chio_core_types::canonical_json_bytes(&joined)
        )?
        .len()
            < 512 * 1024
    );

    let store = f.f.authority.admission_operation_store();
    let mut deployment = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_native_deployment_read",
        None,
        f.f.kernel.recovery_deployment(&f.profile.scope)
    )?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = clearance.clone();
    deployment.actors = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_actor_list",
        None,
        NonEmptyBoundedList::new(actors)
    )?;
    deployment.authority_scope = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_authority_scope_digest",
        None,
        recovery_authority_scope_digest(&deployment)
    )?;
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_actor_installation",
        None,
        store.configure_recovery_deployment(&deployment)
    )
    .map_err(|error| format!("chunk finite actor installation: {error}"))?;
    let mut profile = f.profile.clone();
    profile.generation = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_profile_generation",
        None,
        SafeInteger::new(2)
    )?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = clearance;
    profile.recipients = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_recipient_list",
        None,
        NonEmptyBoundedList::new(recipients)
    )?;
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_profile_installation",
        None,
        store.configure_knowledge(&profile)
    )
    .map_err(|error| format!("chunk finite recipient installation: {error}"))?;
    f.profile = profile.clone();

    let body = b"exact-chunked-checkpoint-material";
    let mut saved = Vec::new();
    for (index, label) in incoming.iter().enumerate() {
        let reference = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_incoming_publication",
            Some(index),
            publish_label(&f, &format!("chunk-incoming-{index}"), body, label.clone())
        )
        .map_err(|error| format!("chunk genuine incoming publication {index}: {error}"))?;
        let checkpoint = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_checkpoint_save",
            Some(index),
            f.runtime.checkpoint(
                &f.f.control,
                &checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_prefix_checkpoint_identity",
                    Some(index),
                    CheckpointId::new(&format!("chunk-checkpoint-{index}"))
                )?,
                0,
                std::slice::from_ref(&reference),
                &[],
            )
        )
        .map_err(|error| format!("chunk genuine bounded checkpoint {index}: {error}"))?;
        assert_eq!(checkpoint.label, *label);
        assert!(
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_checkpoint_envelope_bytes",
                Some(index),
                chio_core_types::canonical_json_bytes(&checkpoint)
            )?
            .len()
                <= 65_536
        );
        saved.push(checkpoint);
    }
    let before = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_initial_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());

    // The initial artifact's exact metadata and classification certificate fit
    // ordinary protected rows. Every later native floor comes from real reads
    // and restores of the already published, bounded checkpoint envelopes.
    let reference = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_historical_publication",
        None,
        publish_label(
            &f,
            "chunk-native-history",
            b"native-history",
            historical.clone(),
        )
    )
    .map_err(|error| format!("chunk genuine historical publication: {error}"))?;
    let handle = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_historical_handle",
        None,
        f.runtime.handle(
            &f.f.control,
            &reference,
            &checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_historical_recipient_identity",
                None,
                ArtifactRecipientId::new("agent-root")
            )?,
        )
    )?;
    let history_sink = f.sink();
    checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_historical_release",
        None,
        f.runtime.release_into(
            &f.f.control,
            &checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_historical_request_identity",
                None,
                RequestId::new("chunk-native-history")
            )?,
            checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_historical_prepare_read",
                None,
                f.runtime.prepare_read(&f.f.control, &handle)
            )?,
            &history_sink,
        )
    )
    .map_err(|error| format!("chunk genuine historical release: {error}"))?;
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_historical_sink_lock",
            None,
            history_sink.delivered.lock().map_err(|_| "history sink")
        )?
        .as_slice(),
        &[b"native-history".to_vec()]
    );
    let history = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_historical_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(history.principal_label, historical);
    assert_eq!(history.lineage_label, historical);
    assert_eq!(history.session_label, historical);
    let mut expected = historical.clone();
    for (index, checkpoint) in saved.iter().take(2).enumerate() {
        let sink = f.sink();
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_intermediate_restore",
            Some(index),
            f.runtime.restore_into(
                &f.f.control,
                &checkpoint.checkpoint,
                1,
                &checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_prefix_intermediate_request_identity",
                    Some(index),
                    RequestId::new(&format!("chunk-native-floor-{index}"))
                )?,
                &sink,
            )
        )
        .map_err(|error| format!("chunk genuine intermediate restore {index}: {error}"))?;
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_intermediate_frame",
            Some(index),
            assert_exact_checkpoint_frame(&sink, checkpoint, body)
        )?;
        expected = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_intermediate_expected_label",
            Some(index),
            expected.join_restrictions(&incoming[index])
        )?;
        let observed = checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_intermediate_native_snapshot",
            Some(index),
            checkpoint_chunk_snapshot(&f)
        )?;
        assert_eq!(observed.principal_label, expected);
        assert_eq!(observed.lineage_label, expected);
        assert_eq!(observed.session_label, expected);
    }

    let checkpoint = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_final_checkpoint_presence",
        None,
        saved.last().ok_or("final chunk checkpoint absent")
    )?
    .clone();
    let request = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_final_request_identity",
        None,
        RequestId::new("chunked-checkpoint-prefix-refusal")
    )?;
    let store = f.f.authority.admission_operation_store();
    let _fault = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_prefix_fault_install",
        None,
        store.inject_checkpoint_restore_extra_prefix_fixture(&f.profile.scope, &request)
    )?;
    assert!(checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_prefix_fault_initial_observation",
        None,
        store.checkpoint_restore_extra_prefix_fixture(&f.profile.scope, &request)
    )?
    .is_none());
    type Baseline = (
        String,
        Vec<u8>,
        i64,
        String,
        i64,
        i64,
        chio_security_types::ports::FlowStateSnapshot,
    );
    let baseline = Arc::new(Mutex::new(None::<Baseline>));
    let captured = baseline.clone();
    let capture_store = f.f.authority.admission_operation_store();
    let capture_actor = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_capture_read_authority",
        None,
        f.actor(RecoveryPermission::KnowledgeRead)
    )?;
    let capture_fence = f.f.authority.mutation_fence();
    let capture_request = request.clone();
    let capture_profile = f.profile.clone();
    let _restore_inner_trace = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_inner_restore_observer_install",
        None,
        f.runtime
            .observe_checkpoint_restore_stages_for_test(&request)
    )?;
    let _process_validation_trace = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_process_validation_observer_install",
        None,
        f.broker
            .observe_checkpoint_process_validation_fixture(&f.profile.scope.process_id, &request)
    )?;
    let capture_database = f.f.path.join("admission.db");
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == KnowledgeCutpoint::ReleaseCommitted {
            let (release, state) = checkpoint_chunk_phase!(None, "chunk_prefix_capture_owner_presence", None, checkpoint_chunk_phase!(None, "chunk_prefix_capture_owner_read", None, capture_store.checkpoint_restore_outcome_fixture(
                &capture_actor, &capture_request, &capture_fence,
                checkpoint_chunk_phase!(None, "chunk_prefix_capture_clock", None, now_ms()).map_err(|error| KernelError::Internal(format!("prefix capture clock: {error}")))?,
            )).map_err(|error| KernelError::Internal(format!("prefix capture source: {error}")))?
                .ok_or_else(|| KernelError::Internal("prefix source absent before ACK".into())))?;
            if state != ArtifactDeliveryStateV1::Admitted {
                return checkpoint_chunk_phase!(None, "chunk_prefix_capture_not_admitted", None, Err(KernelError::Internal("prefix fixture did not reach real admission".into())));
            }
            let connection = checkpoint_chunk_phase!(None, "chunk_prefix_capture_database_open", None, rusqlite::Connection::open(&capture_database)
                ).map_err(|error| KernelError::Internal(format!("prefix capture connection: {error}")))?;
            let original: (String, i64, Vec<u8>) = checkpoint_chunk_phase!(None, "chunk_prefix_capture_root_query", None, connection.query_row(
                "SELECT record_key,version,payload FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'knowledge-restore:*' AND json_extract(payload,'$.intent.release')=?1",
                [release.as_str()], |row| Ok((checkpoint_chunk_phase!(None, "chunk_prefix_capture_key_column", None, row.get(0))?,checkpoint_chunk_phase!(None, "chunk_prefix_capture_version_column", None, row.get(1))?,checkpoint_chunk_phase!(None, "chunk_prefix_capture_payload_column", None, row.get(2))?)),
            )).map_err(|error| KernelError::Internal(format!("prefix capture root: {error}")))?;
            let root: serde_json::Value = checkpoint_chunk_phase!(None, "chunk_prefix_capture_root_json", None, serde_json::from_slice(&original.2)
                ).map_err(|error| KernelError::Internal(format!("prefix capture wire: {error}")))?;
            if original.1 != 1 || root["checkpoint_restore_encoding"] != "chunked_label_atoms_v1"
                || root["body"]["body_bytes"].as_u64().unwrap_or(0) <= 262_144
                || root["body"]["chunk_count"].as_u64().unwrap_or(0) < 5 {
                return checkpoint_chunk_phase!(None, "chunk_prefix_capture_not_chunked", None, Err(KernelError::Internal("prefix fixture missed genuine chunk prerequisite".into())));
            }
            let (head, chain): (i64,String) = checkpoint_chunk_phase!(None, "chunk_prefix_capture_global_head", None, connection.query_row(
                "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1",
                [], |row| Ok((checkpoint_chunk_phase!(None, "chunk_prefix_capture_global_sequence_column", None, row.get(0))?,checkpoint_chunk_phase!(None, "chunk_prefix_capture_global_digest_column", None, row.get(1))?)),
            )).map_err(|error| KernelError::Internal(format!("prefix baseline head: {error}")))?;
            let records: i64 = checkpoint_chunk_phase!(None, "chunk_prefix_capture_records_count", None, connection.query_row("SELECT count(*) FROM admission_operation_recovery_records", [], |row| checkpoint_chunk_phase!(None, "chunk_prefix_sql_result_column", None, row.get(0)))
                ).map_err(|error| KernelError::Internal(format!("prefix baseline records: {error}")))?;
            let journals: i64 = checkpoint_chunk_phase!(None, "chunk_prefix_capture_journal_count", None, connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'", [], |row| checkpoint_chunk_phase!(None, "chunk_prefix_sql_result_column", None, row.get(0)))
                ).map_err(|error| KernelError::Internal(format!("prefix baseline journals: {error}")))?;
            let native = checkpoint_chunk_phase!(None, "chunk_prefix_capture_native_observation", None, capture_store.observe_security_participant_flow(
                &capture_profile.native_authority, &recovery_flow_key(&capture_profile.producer_context),
                &capture_fence, checkpoint_chunk_phase!(None, "chunk_prefix_capture_native_clock", None, now_ms()).map_err(|error| KernelError::Internal(format!("prefix native clock: {error}")))?,
            )).map_err(|error| KernelError::Internal(format!("prefix native snapshot: {error}")))?;
            let snapshot = checkpoint_chunk_phase!(None, "chunk_prefix_capture_native_presence", None, native.snapshot().ok_or_else(|| KernelError::Internal("prefix native snapshot absent".into())))?.clone();
            *checkpoint_chunk_phase!(None, "chunk_prefix_capture_baseline_lock", None, captured.lock().map_err(|_| KernelError::Internal("prefix baseline poisoned".into())))? = Some((original.0,original.2,head,chain,records,journals,snapshot));
        }
        if stage == KnowledgeCutpoint::DeliveryCompleted {
            return checkpoint_chunk_phase!(None, "chunk_prefix_delivery_completed_fault", None, Err(KernelError::Internal("prefix fixture loses original delivery ACK".into())));
        }
        Ok(())
    }));
    let sink = f.sink();
    assert!(checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_prefix_refusal_restore",
        None,
        faulty.restore_into(&f.f.control, &checkpoint.checkpoint, 1, &request, &sink)
    )
    .is_err());
    let observation = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_prefix_fault_presence",
        None,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_prefix_fault_observation",
            None,
            store.checkpoint_restore_extra_prefix_fixture(&f.profile.scope, &request)
        )?
        .ok_or("prefix fixture never reached actual typed Uncertain ACK")
    )?;
    assert_eq!(
        observation.0, 1,
        "one actual authenticated extra append before global-head capture"
    );
    assert!(
        observation.1 > 262_144,
        "actual Uncertain ACK requires chunks"
    );
    assert!(observation.2 >= 5);
    let (root_key, original, head, chain, records, journals, snapshot) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_baseline_presence",
        None,
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_baseline_lock",
            None,
            baseline.lock().map_err(|_| "prefix baseline poisoned")
        )?
        .clone()
        .ok_or("prefix original admission capture absent")
    )?;
    // A failed writer without the pristine-prefix check may already disclose
    // a frame. Preserve exact RED evidence without requiring delivery on a
    // correct refusal, which occurs during Uncertain ACK before the sink.
    let delivered_frames = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_final_sink_lock",
        None,
        sink.delivered.lock().map_err(|_| "prefix sink")
    )?
    .len();
    if delivered_frames != 0 {
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_disclosed_frame",
            None,
            assert_exact_checkpoint_frame(&sink, &checkpoint, body)
        )?;
    }
    let connection = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_outcome_database_open",
        None,
        rusqlite::Connection::open(f.f.path.join("admission.db"))
    )?;
    let after: (i64, Vec<u8>) = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_outcome_root_query",
        None,
        connection.query_row(
            "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [&root_key],
            |row| Ok((
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_prefix_outcome_version_column",
                    None,
                    row.get(0)
                )?,
                checkpoint_chunk_phase!(
                    Some(&f),
                    "chunk_prefix_outcome_payload_column",
                    None,
                    row.get(1)
                )?
            )),
        )
    )?;
    let current_head: (i64,String) = checkpoint_chunk_phase!(Some(&f), "chunk_prefix_outcome_global_head", None, connection.query_row("SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1", [], |row| Ok((checkpoint_chunk_phase!(Some(&f), "chunk_prefix_outcome_global_sequence_column", None, row.get(0))?,checkpoint_chunk_phase!(Some(&f), "chunk_prefix_outcome_global_digest_column", None, row.get(1))?))))?;
    let current_records: i64 = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_outcome_records_count",
        None,
        connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records",
            [],
            |row| checkpoint_chunk_phase!(
                Some(&f),
                "chunk_prefix_sql_result_column",
                None,
                row.get(0)
            ),
        )
    )?;
    let current_journals: i64 = checkpoint_chunk_phase!(Some(&f), "chunk_prefix_outcome_journal_count", None, connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'", [], |row| checkpoint_chunk_phase!(Some(&f), "chunk_prefix_sql_result_column", None, row.get(0))))?;
    let current_snapshot = checkpoint_chunk_phase!(
        Some(&f),
        "chunk_prefix_outcome_native_snapshot",
        None,
        checkpoint_chunk_snapshot(&f)
    )?;
    assert_eq!(
        current_snapshot, snapshot,
        "ACK must not make another native observation"
    );
    assert_eq!(current_journals, journals);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    eprintln!("actual-prefix-fixture phase=uncertain-ack body_bytes={} planned_chunks={} extra_appends={} root_version={} records_before={} records_after={} global_before={} global_after={}", observation.1, observation.2, observation.0, after.0, records, current_records, head, current_head.0);
    assert_eq!(after.0, 1, "owning Uncertain ACK must refuse the extra authenticated owner/body prefix before root advancement");
    assert_eq!(after.1, original, "original root bytes survive refused ACK");
    assert_eq!(
        current_records, records,
        "all planned and extra ACK chunks must roll back"
    );
    assert_eq!(
        current_head,
        (head, chain),
        "authenticated extra append and ACK family must roll back together"
    );
    assert_eq!(
        checkpoint_chunk_phase!(
            Some(&f),
            "chunk_prefix_outcome_custody_read",
            None,
            restore_outcome(&f, &request)
        )?
        .1,
        ArtifactDeliveryStateV1::Admitted
    );
    assert_eq!(
        delivered_frames, 0,
        "a refused Uncertain ACK must not reach the delivery sink"
    );
    Ok(())
}
