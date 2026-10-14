//! A signed import manifest belongs to the reservation that cites it, and an
//! origin map to the publication it makes available.
use super::*;
use chio_core_types::capability::token::CapabilityToken;
use std::sync::atomic::{AtomicUsize, Ordering};

fn count(f: &KnowledgeFixture, table: &str, glob: &str) -> TestResult<i64> {
    Ok(
        rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
            &format!("SELECT count(*) FROM admission_operation_recovery_{table} WHERE record_key GLOB ?1"),
            [glob],
            |row| row.get(0),
        )?,
    )
}

fn rows(f: &KnowledgeFixture, glob: &str) -> TestResult<i64> {
    count(f, "records", glob)
}

fn history(f: &KnowledgeFixture) -> TestResult<(i64, i64)> {
    Ok((count(f, "events", "*")?, rows(f, "*")?))
}

fn archive_profile(
    f: &KnowledgeFixture,
) -> TestResult<(NativeKnowledgeInstallationV1, RecordingSink)> {
    let mut profile = f.profile.clone();
    let mut entry = profile.recipients.as_slice()[0].clone();
    entry.recipient.recipient = ArtifactRecipientId::new("archive")?;
    entry.recipient.sink = ArtifactSinkV1::Archive;
    profile.recipients = NonEmptyBoundedList::new(vec![
        profile.recipients.as_slice()[0].clone(),
        entry.clone(),
    ])?;
    profile.generation = SafeInteger::new(2)?;
    f.f.authority
        .admission_operation_store()
        .configure_knowledge(&profile)?;
    let sink = RecordingSink {
        recipient: entry.recipient,
        delivered: Mutex::new(Vec::new()),
        path: f.f.path.join("admission.db"),
    };
    Ok((profile, sink))
}

/// An archive of a two-version DAG: a published source and its derived copy.
fn export_dag(f: &KnowledgeFixture, sink: &RecordingSink, name: &str) -> TestResult<Vec<u8>> {
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let source = f.publish(&format!("{name}-source"), name.as_bytes())?;
    let handle = f.runtime.handle(&f.f.control, &source, &recipient)?;
    let copy = f.runtime.copy(
        &f.f.control,
        &handle,
        &CommandId::new(&format!("{name}-copy"))?,
    )?;
    let copy_handle = f.runtime.handle(&f.f.control, &copy, &recipient)?;
    let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
    f.runtime.export_into(
        &f.f.control,
        &copy_handle,
        &RequestId::new(&format!("{name}-export"))?,
        &signer,
        sink,
    )?;
    let delivered = sink.delivered.lock().map_err(|_| "sink")?;
    Ok(delivered.last().ok_or("archive")?.clone())
}

fn manifest_of(bytes: &[u8]) -> TestResult<SignedArtifactArchiveManifestV1> {
    let length = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    Ok(serde_json::from_slice(&bytes[12..12 + length])?)
}

fn import_input(
    manifest: &SignedArtifactArchiveManifestV1,
    index: usize,
) -> TestResult<ArtifactPublicationInputV1> {
    let digest = artifact_archive_digest(manifest.body())?;
    let original = &manifest.body().versions.as_slice()[index];
    Ok(ArtifactPublicationInputV1 {
        publication: CommandId::new(&format!(
            "import:{}:{index}",
            chio_core_types::sha256_hex(digest.as_bytes())
        ))?,
        producer: ArtifactProducerV1::Import {
            manifest: digest,
            origin: artifact_version_reference(original)?,
        },
        content: original.content,
        size_bytes: original.size_bytes,
        media_type: original.media_type.clone(),
        schema: original.schema,
        dependencies: BoundedList::new(vec![])?,
        retention: original.retention,
    })
}

fn reopen(
    path: std::path::PathBuf,
    directory: Option<tempfile::TempDir>,
    control: CapabilityToken,
    profile: NativeKnowledgeInstallationV1,
) -> TestResult<KnowledgeFixture> {
    let mut reopened = RecoveryFixture::open(path, directory, false)?;
    reopened.control = control;
    let broker = Arc::new(reopened.process.enable_durable_knowledge()?);
    let runtime = NativeKnowledgeRuntime::new(
        reopened.kernel.clone(),
        Arc::new(reopened.authority.admission_operation_store()),
        broker.clone(),
        profile.clone(),
        reopened.authority.mutation_fence(),
    )?;
    Ok(KnowledgeFixture {
        f: reopened,
        runtime,
        profile,
        broker,
        certificate: Keypair::from_seed(&[217; 32]),
    })
}

#[test]
fn import_replay_and_interrupted_dag_retain_one_row_per_owner() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let (_, sink) = archive_profile(&f)?;
    let bytes = export_dag(&f, &sink, "resume")?;
    assert_eq!(rows(&f, "knowledge-import:*")?, 0);
    let interrupted = Arc::new(AtomicUsize::new(0));
    let seen = interrupted.clone();
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == KnowledgeCutpoint::MetadataCommitted && seen.fetch_add(1, Ordering::SeqCst) == 1
        {
            return Err(KernelError::Internal("lost acknowledgement".into()));
        }
        Ok(())
    }));
    assert!(faulty.import_archive(&f.f.control, &bytes).is_err());
    assert_eq!(rows(&f, "knowledge-import:*")?, 1);
    assert_eq!(rows(&f, "knowledge-import-map:*")?, 1);
    let imported = f.runtime.import_archive(&f.f.control, &bytes)?;
    assert_eq!(rows(&f, "knowledge-import:*")?, 1);
    assert_eq!(rows(&f, "knowledge-import-map:*")?, 2);
    let settled = history(&f)?;
    assert_eq!(f.runtime.import_archive(&f.f.control, &bytes)?, imported);
    assert_eq!(history(&f)?, settled, "an exact import replay wrote rows");
    f.publish("after-import", b"ordinary")?;
    publish_label(
        &f,
        "after-import-adoption",
        b"adopted",
        InformationLabel::bottom(),
    )?;
    Ok(())
}

#[test]
fn import_reservation_refuses_foreign_manifest_and_source_without_a_write() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let (_, sink) = archive_profile(&f)?;
    let right = manifest_of(&export_dag(&f, &sink, "right")?)?;
    let other = manifest_of(&export_dag(&f, &sink, "other")?)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    let input = import_input(&right, 0)?;
    let before = history(&f)?;
    assert!(store
        .reserve_artifact_from(
            &writer,
            &input,
            ArtifactReservationSource::Import { manifest: &other },
            &fence,
            now_ms()?
        )
        .is_err());
    assert!(store
        .reserve_artifact(&writer, &input, &fence, now_ms()?)
        .is_err());
    assert!(store
        .reserve_artifact_from(
            &writer,
            &f.input("not-an-import", b"x")?,
            ArtifactReservationSource::Import { manifest: &right },
            &fence,
            now_ms()?
        )
        .is_err());
    let mut resized = input.clone();
    resized.size_bytes = SafeInteger::new(resized.size_bytes.get() + 1)?;
    assert!(store
        .reserve_artifact_from(
            &writer,
            &resized,
            ArtifactReservationSource::Import { manifest: &right },
            &fence,
            now_ms()?
        )
        .is_err());
    assert_eq!(history(&f)?, before);
    assert_eq!(rows(&f, "knowledge-import:*")?, 0);
    Ok(())
}

#[test]
fn import_refused_after_slot_charge_leaves_neither_manifest_nor_publication() -> TestResult {
    let _prior = PriorFormatImportStartupGuard::arm();
    let f = KnowledgeFixture::new()?;
    let (_, sink) = archive_profile(&f)?;
    let bytes = export_dag(&f, &sink, "rolled-back")?;
    let before = history(&f)?;
    let publications = rows(&f, "knowledge-publication:*")?;
    assert!(f.runtime.import_archive(&f.f.control, &bytes).is_err());
    assert_eq!(history(&f)?, before);
    assert_eq!(rows(&f, "knowledge-publication:*")?, publications);
    assert_eq!(rows(&f, "knowledge-import:*")?, 0);
    Ok(())
}

#[test]
fn redirected_import_map_refuses_availability() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let (_, sink) = archive_profile(&f)?;
    let bytes = export_dag(&f, &sink, "redirected")?;
    let manifest = manifest_of(&bytes)?;
    let origin = artifact_version_reference(&manifest.body().versions.as_slice()[0])?;
    let elsewhere = f.publish("redirect-target", b"elsewhere")?;
    f.f.authority
        .admission_operation_store()
        .retain_prior_format_import_map_fixture(
            &f.actor(RecoveryPermission::KnowledgeWrite)?,
            artifact_archive_digest(manifest.body())?,
            &origin,
            &elsewhere,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(f.runtime.import_archive(&f.f.control, &bytes).is_err());
    assert_eq!(rows(&f, "knowledge-import-map:*")?, 1);
    let state: String = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-publication:*'
           AND json_extract(payload,'$.input.publication') GLOB 'import:*'",
        [],
        |row| row.get(0),
    )?;
    assert_ne!(state, "available");
    Ok(())
}

#[test]
fn prior_standalone_manifest_is_adopted_and_a_later_uncited_one_refuses_open() -> TestResult {
    let prior = PriorFormatImportStartupGuard::arm();
    let mut f = KnowledgeFixture::new()?;
    let (profile, sink) = archive_profile(&f)?;
    let (cited, uncited) = (
        export_dag(&f, &sink, "retained")?,
        export_dag(&f, &sink, "uncited")?,
    );
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    f.f.authority
        .admission_operation_store()
        .retain_prior_format_import_manifest_fixture(
            &writer,
            &manifest_of(&cited)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert_eq!(rows(&f, "knowledge-import-baseline:*")?, 0);
    let control = f.f.control.clone();
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(f);
    drop(prior);
    let mut f = reopen(path.clone(), directory, control, profile)?;
    assert_eq!(rows(&f, "knowledge-import-baseline:*")?, 1);
    f.runtime.import_archive(&f.f.control, &cited)?;
    assert_eq!(rows(&f, "knowledge-import:*")?, 1);
    assert_eq!(count(&f, "events", "knowledge-import:*")?, 1);
    f.f.authority
        .admission_operation_store()
        .retain_prior_format_import_manifest_fixture(
            &f.actor(RecoveryPermission::KnowledgeWrite)?,
            &manifest_of(&uncited)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    let directory = f.f._directory.take();
    drop(f);
    assert!(RecoveryFixture::open(path, directory, false).is_err());
    Ok(())
}
