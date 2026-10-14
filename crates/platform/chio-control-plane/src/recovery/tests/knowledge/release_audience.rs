//! Requester-visible release outcomes obey the current native audience.
use super::*;
use chio_security_types::semantic::SemanticOutputDispositionV1;

pub(super) fn install_read_actor(
    f: &KnowledgeFixture,
    seed: u8,
    principal: &str,
    clearance: InformationLabel,
) -> TestResult<CapabilityToken> {
    install_actor(
        f,
        seed,
        principal,
        clearance,
        &[RecoveryPermission::KnowledgeRead],
    )
}

pub(super) fn install_actor(
    f: &KnowledgeFixture,
    seed: u8,
    principal: &str,
    clearance: InformationLabel,
    permissions: &[RecoveryPermission],
) -> TestResult<CapabilityToken> {
    let key = Keypair::from_seed(&[seed; 32]);
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let mut actor = actors[0].clone();
    actor.subject = key.public_key();
    actor.principal = PrincipalId::new(principal)?;
    actor.preview_clearance = clearance;
    let mut permissions = permissions.to_vec();
    permissions.sort();
    actor.permissions = BoundedList::new(permissions)?;
    actors.push(actor);
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(f.f
        .kernel
        .issue_capability(&key.public_key(), f.f.control.scope.clone(), 1200)?)
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

pub(super) async fn prime_native_recipient(f: &KnowledgeFixture) -> TestResult {
    let before = native_snapshot(f)?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());

    // This is an actual native SupportRead with a signed Restricted output floor.
    // It neither adopts a legacy blob nor writes synthetic flow state.
    let (runtime, request, _) = semantic::prepare(
        &f.f,
        "prime-finite-recipient-context",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let response = runtime
        .execute_step(
            &f.f.process,
            "root",
            "prime-finite-recipient-context",
            &request,
        )
        .await?;
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "native recipient priming did not complete: {:?}",
        response.reason
    );
    assert!(response.output.is_some());
    let high = native_snapshot(f)?;
    assert_eq!(high.principal_label, restricted_label());
    assert_eq!(high.lineage_label, restricted_label());
    assert_eq!(high.session_label, restricted_label());
    assert!(high.context_generation > before.context_generation);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 1);

    Ok(())
}

pub(super) fn assert_opaque_outcome(value: &serde_json::Value) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("public outcome is not an object"));
    for private in [
        "source_label",
        "admitted_label",
        "influence",
        "recipient",
        "policy",
        "authorization",
        "observation_transition",
        "observation_generation",
    ] {
        assert!(
            !object.contains_key(private),
            "public outcome exposes private native metadata: {private}"
        );
    }
    assert!(object.contains_key("release"));
}

#[tokio::test]
async fn artifacts_public_outcome_and_replay_preserve_native_recipient_audience() -> TestResult {
    let f = KnowledgeFixture::from(semantic::native_fixture("read")?)?;
    let bytes = b"public-immutable-content";
    let reference = f.publish("public-before-strong-observation", bytes)?;
    assert_eq!(f.metadata(&reference)?.label, InformationLabel::bottom());
    prime_native_recipient(&f).await?;

    let low = install_read_actor(&f, 220, "public-outcome-reader", InformationLabel::bottom())?;
    let handle = f
        .runtime
        .handle(&low, &reference, &ArtifactRecipientId::new("agent-root")?)?;
    let request = RequestId::new("opaque-public-outcome")?;
    let sink = f.sink();
    let first = f.runtime.release_into(
        &low,
        &request,
        f.runtime.prepare_read(&low, &handle)?,
        &sink,
    )?;
    let first_value = serde_json::to_value(&first)?;
    let release = first_value
        .get("release")
        .ok_or("opaque release identity absent")?
        .clone();
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[bytes.to_vec()]
    );
    let release_id = release
        .as_str()
        .ok_or("opaque release identity is not text")?;
    let private_label: String = rusqlite::Connection::open(f.f.path.join("admission.db"))?
        .query_row(
            "SELECT json_extract(payload,'$.release.source_label')
             FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'
             AND json_extract(payload,'$.release.release')=?1",
            [release_id],
            |row| row.get(0),
        )?;
    assert_eq!(
        serde_json::from_str::<InformationLabel>(&private_label)?,
        restricted_label(),
        "private admission must retain the full joined native source"
    );
    assert_opaque_outcome(&first_value);

    for _ in 0..2 {
        let again = f.runtime.release_into(
            &low,
            &request,
            f.runtime.prepare_read(&low, &handle)?,
            &sink,
        )?;
        let value = serde_json::to_value(&again)?;
        assert_opaque_outcome(&value);
        assert_eq!(value.get("release"), Some(&release));
        assert_eq!(
            value, first_value,
            "public response shape must not reveal historical context"
        );
    }
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[bytes.to_vec(), bytes.to_vec(), bytes.to_vec()]
    );
    assert_eq!(
        f.f.effects.load(Ordering::SeqCst),
        1,
        "byte redelivery cannot rerun native SupportRead"
    );
    let joins: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(joins, 1);
    Ok(())
}

#[test]
fn artifacts_delivery_progress_settles_under_high_wal_and_refunds_once() -> TestResult {
    use super::retention::{active_reference_owners, census_retired, custody, HighWal};
    let f = KnowledgeFixture::new()?;
    let bytes = b"high-wal-release";
    let reference = f.publish("high-wal-release", bytes)?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let failed_read = f.runtime.prepare_read(&f.f.control, &handle)?;
    let replay_read = f.runtime.prepare_read(&f.f.control, &handle)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let (record, _) = store.prepare_artifact_read(&reader, &handle, &fence, now_ms()?)?;
    let seal = record.seal.ok_or("published artifact seal")?;
    let request = RequestId::new("high-wal-release")?;
    // Admission is ordinary intake and happens before pressure.
    store.admit_artifact_release(&reader, &handle, &request, &seal, &fence, now_ms()?)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        1
    );
    let pressure = HighWal::begin(&f)?;
    let admitted = custody(&f)?;
    let refused = super::retained_owner::UncertainSink::new(
        f.profile.recipients.as_slice()[0].recipient.clone(),
    );
    assert!(f
        .runtime
        .release_into(&f.f.control, &request, failed_read, &refused)
        .is_err());
    assert_eq!(refused.attempts(), 1, "the failure must reach the sink");
    let uncertain = custody(&f)?;
    // Only the pre-send Admitted to Uncertain progress; the failed sink's
    // second Uncertain is a repeat. Uncertain retains its owner and refunds nothing.
    assert_eq!(
        (
            uncertain.events - admitted.events,
            uncertain.commits - admitted.commits
        ),
        (1, 1)
    );
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        1
    );
    assert_eq!(census_retired(&uncertain)?, census_retired(&admitted)?);

    let sink = f.sink();
    f.runtime
        .release_into(&f.f.control, &request, replay_read, &sink)
        .map_err(|error| format!("replayed delivery under pressure: {error}"))?;
    let delivered = custody(&f)?;
    // Uncertain to Delivered plus the single-reference refund.
    assert_eq!(
        (
            delivered.events - uncertain.events,
            delivered.commits - uncertain.commits
        ),
        (5, 5)
    );
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        0
    );
    assert_eq!(census_retired(&delivered)?, census_retired(&uncertain)? + 1);
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[bytes.to_vec()]
    );
    let delivered_read = f.runtime.prepare_read(&f.f.control, &handle)?;
    assert!(f
        .runtime
        .release_into(&f.f.control, &request, delivered_read, &refused)
        .is_err());
    assert_eq!(
        refused.attempts(),
        2,
        "the sticky replay must reach the sink"
    );
    assert_eq!(
        custody(&f)?,
        delivered,
        "Delivered is sticky: a later failed outcome writes nothing"
    );
    pressure.release()
}

const MAX_RELEASE_ROW: usize = 262_144;

/// The exact release record key of one admitted inline request.
fn release_key(path: &std::path::Path, request: &str) -> TestResult<String> {
    Ok(
        rusqlite::Connection::open(path.join("admission.db"))?.query_row(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-release:*'
           AND json_extract(payload,'$.intent.kind.request')=?1",
            [request],
            |row| row.get(0),
        )?,
    )
}

fn release_row(path: &std::path::Path, key: &str) -> TestResult<(i64, Vec<u8>)> {
    Ok(
        rusqlite::Connection::open(path.join("admission.db"))?.query_row(
            "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
    )
}

fn chunk_rows(path: &std::path::Path) -> TestResult<i64> {
    Ok(
        rusqlite::Connection::open(path.join("admission.db"))?.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-encoding-chunk:*'",
            [],
            |row| row.get(0),
        )?,
    )
}

/// The original clearance joined with padded owner policies so its canonical
/// form is exactly `target` bytes. New owners keep every admitted flow valid.
fn clearance_of(base: &InformationLabel, target: usize) -> TestResult<InformationLabel> {
    use std::collections::{BTreeMap, BTreeSet};
    let pad = |full: usize, tail: usize| -> TestResult<InformationLabel> {
        let mut owners: BTreeMap<chio_security_types::PrincipalId, BTreeSet<_>> = BTreeMap::new();
        for index in 0..=full {
            let owner =
                chio_security_types::PrincipalId::new(format!("pad-owner-{:02}", index / 200))?;
            let reader = if index == full {
                format!("t{}", "t".repeat(tail))
            } else {
                format!("pad-reader-{index:05}-{}", "r".repeat(150))
            };
            owners
                .entry(owner.clone())
                .or_insert_with(|| BTreeSet::from([owner]))
                .insert(chio_security_types::PrincipalId::new(reader)?);
        }
        Ok(base.join_restrictions(&InformationLabel::try_known(owners, BTreeSet::new())?)?)
    };
    let size = |label: &InformationLabel| -> TestResult<usize> {
        Ok(chio_core_types::canonical_json_bytes(label)?.len())
    };
    // Each padded reader adds at most about 170 bytes including an owner
    // boundary, so one tail reader of up to 200 bytes closes any gap.
    for full in 0..2_000 {
        let current = size(&pad(full, 0)?)?;
        if current > target {
            break;
        }
        if target - current <= 200 {
            let exact = pad(full, target - current)?;
            if size(&exact)? == target {
                return Ok(exact);
            }
        }
    }
    Err("no valid clearance reaches the exact size".into())
}

/// Install a successor profile whose agent recipient has this clearance,
/// through the real profile writer.
fn with_clearance(f: &mut KnowledgeFixture, clearance: InformationLabel) -> TestResult {
    let mut profile = f.profile.clone();
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = clearance;
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    f.runtime = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.broker.clone(),
        profile.clone(),
        f.f.authority.mutation_fence(),
    )?;
    f.profile = profile;
    Ok(())
}

/// Admit one release through the actual typed release writer.
fn admit_release(
    f: &KnowledgeFixture,
    reference: &ArtifactVersionRefV1,
    request: &RequestId,
) -> TestResult<(ArtifactHandleV1, ArtifactReleaseIntentV1)> {
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let handle = f.runtime.handle(
        &f.f.control,
        reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let (record, _) = store.prepare_artifact_read(&reader, &handle, &fence, now_ms()?)?;
    let seal = record.seal.ok_or("published artifact seal")?;
    let intent =
        store.admit_artifact_release(&reader, &handle, request, &seal, &fence, now_ms()?)?;
    Ok((handle, intent))
}

/// A real admitted inline release of exactly the 262,144-byte row ceiling,
/// reached by calibrating the actual recipient clearance through the real
/// profile writer. Returns its handle, intent, request, key and stored bytes.
fn max_admitted_release(
    f: &mut KnowledgeFixture,
    reference: &ArtifactVersionRefV1,
) -> TestResult<(
    ArtifactHandleV1,
    ArtifactReleaseIntentV1,
    RequestId,
    String,
    Vec<u8>,
)> {
    let base = f.profile.recipients.as_slice()[0]
        .recipient
        .clearance
        .clone();
    let mut clearance = base.clone();
    let mut clearance_bytes = chio_core_types::canonical_json_bytes(&base)?.len();
    for attempt in 0..4 {
        let request = RequestId::new(&format!("max-release-{attempt}"))?;
        with_clearance(f, clearance.clone())?;
        let (handle, intent) = admit_release(f, reference, &request)?;
        let key = release_key(&f.f.path, request.as_str())?;
        let (version, payload) = release_row(&f.f.path, &key)?;
        assert_eq!(version, 1);
        if payload.len() == MAX_RELEASE_ROW {
            return Ok((handle, intent, request, key, payload));
        }
        clearance_bytes += MAX_RELEASE_ROW - payload.len();
        clearance = clearance_of(&base, clearance_bytes)?;
    }
    Err("no real release reached the exact row ceiling".into())
}

#[test]
fn artifacts_max_admitted_release_finishes_through_the_encoded_writer() -> TestResult {
    use super::retention::{active_reference_owners, census_retired, custody, HighWal};
    let mut f = KnowledgeFixture::new()?;
    let bytes = b"max-release";
    let reference = f.publish("max-release", bytes)?;
    let (handle, intent, request, key, original) = max_admitted_release(&mut f, &reference)?;
    let failed_read = f.runtime.prepare_read(&f.f.control, &handle)?;
    let replay_read = f.runtime.prepare_read(&f.f.control, &handle)?;
    let owners = active_reference_owners(&f, &reference, "artifact_release")?;
    let pressure = HighWal::begin(&f)?;
    let before = custody(&f)?;
    let chunks = chunk_rows(&f.f.path)?;

    let refused = super::retained_owner::UncertainSink::new(
        f.profile.recipients.as_slice()[0].recipient.clone(),
    );
    assert!(f
        .runtime
        .release_into(&f.f.control, &request, failed_read, &refused)
        .is_err());
    assert_eq!(refused.attempts(), 1, "the failure must reach the sink");
    let uncertain = custody(&f)?;
    // The 262,145-byte Uncertain record: one bounded root over five fresh
    // immutable chunks. Uncertain refunds nothing.
    assert_eq!(
        (
            uncertain.events - before.events,
            uncertain.commits - before.commits
        ),
        (6, 6)
    );
    assert_eq!(chunk_rows(&f.f.path)? - chunks, 5);
    let (version, root) = release_row(&f.f.path, &key)?;
    let root: serde_json::Value = serde_json::from_slice(&root)?;
    assert_eq!(version, 2);
    assert_eq!(
        root["knowledge_release_encoding"],
        "chunked_release_record_v1"
    );
    assert_eq!(root["original_version"], 1);
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        owners
    );
    assert_eq!(census_retired(&uncertain)?, census_retired(&before)?);

    let sink = f.sink();
    f.runtime
        .release_into(&f.f.control, &request, replay_read, &sink)
        .map_err(|error| format!("encoded Delivered under pressure: {error}"))?;
    let delivered = custody(&f)?;
    // A second fresh chunk set and root, plus the single-reference refund.
    assert_eq!(
        (
            delivered.events - uncertain.events,
            delivered.commits - uncertain.commits
        ),
        (10, 10)
    );
    assert_eq!(chunk_rows(&f.f.path)? - chunks, 10);
    assert_eq!(release_row(&f.f.path, &key)?.0, 3);
    assert_eq!(
        active_reference_owners(&f, &reference, "artifact_release")?,
        owners - 1
    );
    assert_eq!(census_retired(&delivered)?, census_retired(&uncertain)? + 1);
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[bytes.to_vec()]
    );
    pressure.release()?;

    // Restart: the reopened store decodes the encoded Delivered root and its
    // exact original admission, and the sticky outcome writes nothing. The
    // reader reuses the original capability token its release digest binds.
    let scope = f.profile.scope.clone();
    let control = f.f.control.clone();
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(f);
    let reopened = RecoveryFixture::open(path.clone(), directory, false)?;
    let reader = reopened.kernel.authenticate_recovery_actor(
        &scope,
        &control,
        RecoveryPermission::KnowledgeRead,
    )?;
    let store = reopened.authority.admission_operation_store();
    let fence = reopened.authority.mutation_fence();
    let settled = custody_at(&path)?;
    store.acknowledge_artifact_delivery(&reader, &request, &intent, true, &fence, now_ms()?)?;
    assert_eq!(
        custody_at(&path)?,
        settled,
        "Delivered is sticky after restart"
    );
    assert_eq!(original.len(), MAX_RELEASE_ROW);
    Ok(())
}

#[test]
fn artifacts_max_release_refuses_a_missing_or_corrupt_encoded_chunk() -> TestResult {
    let refusal = Some(
        chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
            "knowledge atom chunk framing is invalid".to_owned(),
        ),
    );
    for missing in [true, false] {
        let mut f = KnowledgeFixture::new()?;
        let reference = f.publish("max-release-fault", b"max-release-fault")?;
        let (_, intent, request, key, original) = max_admitted_release(&mut f, &reference)?;
        let store = f.f.authority.admission_operation_store();
        let fence = f.f.authority.mutation_fence();
        let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
        let fault = if missing {
            store.inject_missing_release_chunk_fixture(&f.profile.scope, &key)?
        } else {
            store.inject_corrupt_release_chunk_fixture(&f.profile.scope, &key)?
        };
        // The actual pre-send outcome commits its encoded Uncertain root while
        // the armed fault withholds or alters the last of its five chunks.
        let chunks = chunk_rows(&f.f.path)?;
        store.acknowledge_artifact_delivery(
            &reader,
            &request,
            &intent,
            false,
            &fence,
            now_ms()?,
        )?;
        drop(fault);
        assert_eq!(chunk_rows(&f.f.path)? - chunks, if missing { 4 } else { 5 });
        assert_eq!(release_row(&f.f.path, &key)?.0, 2);
        // Every later authenticated decode refuses the body and writes nothing.
        let settled = custody_at(&f.f.path)?;
        assert_eq!(
            store
                .acknowledge_artifact_delivery(&reader, &request, &intent, true, &fence, now_ms()?)
                .err(),
            refusal
        );
        assert_eq!(custody_at(&f.f.path)?, settled);

        // After restart, the original capability authenticates and the decode
        // refuses identically; the admitted original bytes are unchanged.
        let scope = f.profile.scope.clone();
        let control = f.f.control.clone();
        let path = f.f.path.clone();
        let directory = f.f._directory.take();
        drop(store);
        drop(f);
        let reopened = RecoveryFixture::open(path.clone(), directory, false)?;
        let reader = reopened.kernel.authenticate_recovery_actor(
            &scope,
            &control,
            RecoveryPermission::KnowledgeRead,
        )?;
        assert_eq!(
            reopened
                .authority
                .admission_operation_store()
                .acknowledge_artifact_delivery(
                    &reader,
                    &request,
                    &intent,
                    true,
                    &reopened.authority.mutation_fence(),
                    now_ms()?,
                )
                .err(),
            refusal
        );
        assert_eq!(custody_at(&path)?, settled);
        assert_eq!(original.len(), MAX_RELEASE_ROW);
    }
    Ok(())
}

fn custody_at(path: &std::path::Path) -> TestResult<(i64, i64)> {
    let connection = rusqlite::Connection::open(path.join("admission.db"))?;
    Ok((
        connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?,
        connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })?,
    ))
}

#[test]
fn artifacts_delivery_acknowledgement_refuses_when_setup_is_not_ready() -> TestResult {
    use super::retention::custody;
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("not-ready-release", b"not-ready-release")?;
    let request = RequestId::new("not-ready-release")?;
    let (_, intent) = admit_release(&f, &reference, &request)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    deployment.setup_policy = Some(chio_kernel::recovery::NativeSetupPolicyV1 {
        operator_root: Keypair::from_seed(&[212; 32]).public_key(),
    });
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let before = custody(&f)?;
    assert_eq!(
        store
            .acknowledge_artifact_delivery(&reader, &request, &intent, false, &fence, now_ms()?)
            .err(),
        Some(chio_kernel::admission_operation::AdmissionOperationStoreError::RecoveryMediationRequired)
    );
    assert_eq!(
        custody(&f)?,
        before,
        "a refused acknowledgement writes nothing"
    );
    Ok(())
}

/// The canonical per-version bound: one record over one 66-byte identity.
const HANDLE_INDEX_BOUND: u64 = 262_144 / 66;

/// Handle rows, the version of every index row in key order, and baselines.
fn handle_family(path: &std::path::Path) -> TestResult<(i64, Vec<i64>, i64)> {
    let connection = rusqlite::Connection::open(path.join("admission.db"))?;
    let count = |pattern: &str| -> rusqlite::Result<i64> {
        connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
            [pattern],
            |row| row.get(0),
        )
    };
    let mut statement = connection.prepare(
        "SELECT version FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-handle-index:*' ORDER BY record_key",
    )?;
    let indices = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<i64>, _>>()?;
    Ok((
        count("knowledge-handle:*")?,
        indices,
        count("knowledge-handle-baseline:*")?,
    ))
}

/// Drop the serving fixture and reopen its store, as a process restart.
fn restart(mut f: RecoveryFixture) -> TestResult<RecoveryFixture> {
    let path = f.path.clone();
    let directory = f._directory.take();
    drop(f);
    RecoveryFixture::open(path, directory, false)
}

/// A store whose handles the prior-44 binary issued: no baseline and no index.
/// The restart runs the one migration under the current binary. The fixture
/// control persisted by the prior binary predates the knowledge deployment,
/// so the original knowledge capability travels with the returned fixture.
fn migrated_prior_handles(
    name: &str,
    generations: std::ops::RangeInclusive<u64>,
) -> TestResult<(
    RecoveryFixture,
    NativeKnowledgeInstallationV1,
    ArtifactVersionRefV1,
    Vec<ArtifactHandleV1>,
    CapabilityToken,
)> {
    let prior = PriorFormatHandleStartupGuard::arm();
    let mut f = KnowledgeFixture::new()?;
    let reference = f.publish(name, name.as_bytes())?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let handles =
        f.f.authority
            .admission_operation_store()
            .retain_prior_format_handles_fixture(
                &reader,
                &reference,
                &ArtifactRecipientId::new("agent-root")?,
                generations,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    let count = i64::try_from(handles.len())?;
    assert_eq!(handle_family(&f.f.path)?, (count, vec![], 0));
    let control = f.f.control.clone();
    let profile = f.profile.clone();
    let directory = f.f._directory.take();
    let path = f.f.path.clone();
    drop(f);
    drop(prior);
    let migrated = RecoveryFixture::open(path.clone(), directory, false)?;
    assert_eq!(handle_family(&path)?, (count, vec![1], 1));
    Ok((migrated, profile, reference, handles, control))
}

/// Knowledge read authentication for a restarted fixture. The control token
/// the plain RecoveryFixture reopen loads from fixture.json carries only the
/// recovery permissions the prior binary persisted, so the caller supplies the
/// original knowledge capability that the deployment in the reopened store
/// still assigns to the same principal.
fn reader_of(
    fixture: &RecoveryFixture,
    scope: &RecoveryScopeV1,
    control: &CapabilityToken,
) -> TestResult<AuthenticatedRecoveryActor> {
    Ok(fixture.kernel.authenticate_recovery_actor(
        scope,
        control,
        RecoveryPermission::KnowledgeRead,
    )?)
}

#[test]
fn artifacts_handle_index_charges_each_new_alias_once_and_retries_write_nothing() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("handle-index", b"handle-index")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let clearance =
        f.f.kernel
            .recovery_deployment(&f.profile.scope)?
            .actors
            .as_slice()[0]
            .preview_clearance
            .clone();
    let token = install_read_actor(&f, 61, "handle-index-second-principal", clearance)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let second = f.f.kernel.authenticate_recovery_actor(
        &f.profile.scope,
        &token,
        RecoveryPermission::KnowledgeRead,
    )?;
    let before = custody_at(&f.f.path)?;
    let first = store.issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)?;
    let issued = custody_at(&f.f.path)?;
    assert_eq!(
        (issued.0 - before.0, issued.1 - before.1),
        (2, 2),
        "a new alias writes its row and appends its version index"
    );
    assert_eq!(handle_family(&f.f.path)?, (1, vec![1], 1));
    let retry = store.issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)?;
    assert!(retry == first);
    assert_eq!(
        custody_at(&f.f.path)?,
        issued,
        "an exact retry writes nothing"
    );

    let other = store.issue_artifact_handle(&second, &reference, &recipient, &fence, now_ms()?)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    store.configure_knowledge(&profile)?;
    let rotated =
        store.issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)?;
    assert!(other != first && rotated != first && rotated != other);
    assert_eq!(
        handle_family(&f.f.path)?,
        (3, vec![3], 1),
        "every principal and profile generation appends to the one index of its version"
    );
    for (actor, handle) in [(&reader, &first), (&second, &other), (&reader, &rotated)] {
        store.prepare_artifact_read(actor, handle, &fence, now_ms()?)?;
    }
    Ok(())
}

#[test]
fn artifacts_handle_collection_ends_the_live_obligation_and_keeps_history() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("handle-collected", b"handle-collected")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let handle = f.runtime.handle(&f.f.control, &reference, &recipient)?;
    f.runtime.collect(&f.f.control, &reference)?;
    let retained = handle_family(&f.f.path)?;
    assert_eq!(retained, (1, vec![1], 1));
    let settled = custody_at(&f.f.path)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    assert!(store
        .issue_artifact_handle(&reader, &reference, &recipient, &fence, now_ms()?)
        .is_err());
    assert!(store
        .prepare_artifact_read(&reader, &handle, &fence, now_ms()?)
        .is_err());
    assert_eq!(custody_at(&f.f.path)?, settled);
    assert_eq!(
        handle_family(&f.f.path)?,
        retained,
        "collection deletes no alias"
    );
    Ok(())
}

#[test]
fn artifacts_prior_handles_migrate_once_and_read_across_restarts() -> TestResult {
    let (migrated, profile, reference, handles, control) =
        migrated_prior_handles("prior-handles", 1..=2)?;
    let path = migrated.path.clone();
    let store = migrated.authority.admission_operation_store();
    let fence = migrated.authority.mutation_fence();
    let reader = reader_of(&migrated, &profile.scope, &control)?;
    for handle in &handles {
        store.prepare_artifact_read(&reader, handle, &fence, now_ms()?)?;
    }
    // Generation 1 is the current profile; its prior alias is reused as is.
    let settled = custody_at(&path)?;
    let retry = store.issue_artifact_handle(
        &reader,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
        &fence,
        now_ms()?,
    )?;
    assert!(retry == handles[0]);
    assert_eq!(custody_at(&path)?, settled);
    drop(store);
    let reopened = restart(migrated)?;
    assert_eq!(
        (custody_at(&path)?.0, handle_family(&path)?),
        (settled.0, (2, vec![1], 1)),
        "a verified baseline never migrates again"
    );
    let store = reopened.authority.admission_operation_store();
    let reader = reader_of(&reopened, &profile.scope, &control)?;
    for handle in &handles {
        store.prepare_artifact_read(
            &reader,
            handle,
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?;
    }
    Ok(())
}

#[test]
fn artifacts_prior_handle_corruption_or_loss_refuses_open_unchanged() -> TestResult {
    for corrupt in [true, false] {
        let (mut migrated, _, _, _, _) = migrated_prior_handles("prior-handle-fault", 1..=1)?;
        let path = migrated.path.clone();
        let directory = migrated._directory.take();
        drop(migrated);
        let db = rusqlite::Connection::open(path.join("admission.db"))?;
        db.execute_batch("PRAGMA foreign_keys=OFF;")?;
        if corrupt {
            db.execute_batch(
                "DROP TRIGGER admission_operation_recovery_history_immutable;
                DROP TRIGGER admission_operation_recovery_identity;
                UPDATE admission_operation_recovery_records SET payload=cast('null' AS blob)
                WHERE record_key GLOB 'knowledge-handle:*';",
            )?;
        } else {
            db.execute_batch(
                "DROP TRIGGER admission_operation_recovery_no_delete;
                DELETE FROM admission_operation_recovery_records
                WHERE record_key GLOB 'knowledge-handle:*';",
            )?;
        }
        db.execute_batch(include_str!(
            "../../../../../chio-store-sqlite/src/admission_operation_recovery.sql"
        ))?;
        db.execute_batch(include_str!(
            "../../../../../chio-store-sqlite/src/recovery_deployment_history.sql"
        ))?;
        drop(db);
        let damaged = (custody_at(&path)?.0, handle_family(&path)?);
        assert!(RecoveryFixture::open(path.clone(), None, false).is_err());
        assert_eq!((custody_at(&path)?.0, handle_family(&path)?), damaged);
        drop(directory);
    }
    Ok(())
}

#[test]
fn artifacts_empty_prior_store_migrates_then_refuses_an_unindexed_later_alias() -> TestResult {
    let prior = PriorFormatHandleStartupGuard::arm();
    let mut f = KnowledgeFixture::new()?;
    let reference = f.publish("prior-empty", b"prior-empty")?;
    let profile = f.profile.clone();
    // The persisted fixture control predates the knowledge grants; keep the
    // original knowledge capability for the restarted store.
    let control = f.f.control.clone();
    assert_eq!(handle_family(&f.f.path)?, (0, vec![], 0));
    let directory = f.f._directory.take();
    let path = f.f.path.clone();
    drop(f);
    drop(prior);
    let mut migrated = RecoveryFixture::open(path.clone(), directory, false)?;
    assert_eq!(
        handle_family(&path)?,
        (0, vec![], 1),
        "an empty inventory still installs its baseline"
    );
    let store = migrated.authority.admission_operation_store();
    let fence = migrated.authority.mutation_fence();
    let reader = reader_of(&migrated, &profile.scope, &control)?;
    // The prior writer bytes after the cut: no restart may grandfather them.
    let late = store.retain_prior_format_handles_fixture(
        &reader,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
        1..=1,
        &fence,
        now_ms()?,
    )?;
    assert!(store
        .prepare_artifact_read(&reader, &late[0], &fence, now_ms()?)
        .is_err());
    drop(store);
    let directory = migrated._directory.take();
    drop(migrated);
    let unindexed = (custody_at(&path)?.0, handle_family(&path)?);
    assert!(RecoveryFixture::open(path.clone(), None, false).is_err());
    assert_eq!((custody_at(&path)?.0, handle_family(&path)?), unindexed);
    drop(directory);
    Ok(())
}

#[test]
fn artifacts_full_handle_index_refuses_new_aliases_without_affecting_another_tenant() -> TestResult
{
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let prior = PriorFormatHandleStartupGuard::arm();
    let mut f = KnowledgeFixture::new()?;
    let other = super::live_capacity::scoped_host(&f, "handle-other-tenant", "handle-other-root")?;
    let full = f.publish("handle-full", b"handle-full")?;
    let input = f.input("handle-other-tenant", b"handle-other-tenant")?;
    let foreign = other
        .runtime
        .publish(&f.f.control, &input, b"handle-other-tenant", None)?;
    // A supported prior-44 version whose census already holds the bound.
    // Generation 1, the current profile, is left as the one new alias.
    let legacy =
        f.f.authority
            .admission_operation_store()
            .retain_prior_format_handles_fixture(
                &f.actor(RecoveryPermission::KnowledgeRead)?,
                &full,
                &recipient,
                2..=HANDLE_INDEX_BOUND + 1,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    let scope = f.profile.scope.clone();
    let control = f.f.control.clone();
    // Retained foreign identity: the deployment and installation the restart
    // must reopen, never reimport or rewrite.
    let foreign_profile = other.profile.clone();
    let foreign_deployment = other.deployment.clone();
    let directory = f.f._directory.take();
    let path = f.f.path.clone();
    drop(other);
    drop(f);
    drop(prior);
    let migrated = RecoveryFixture::open(path.clone(), directory, false)?;
    let store = migrated.authority.admission_operation_store();
    let fence = migrated.authority.mutation_fence();
    let reader = reader_of(&migrated, &scope, &control)?;
    for handle in [&legacy[0], &legacy[legacy.len() - 1]] {
        store.prepare_artifact_read(&reader, handle, &fence, now_ms()?)?;
    }
    let settled = (custody_at(&path)?, handle_family(&path)?);
    assert!(store
        .issue_artifact_handle(&reader, &full, &recipient, &fence, now_ms()?)
        .is_err());
    assert_eq!((custody_at(&path)?, handle_family(&path)?), settled);
    // The foreign tenant does not travel on the home kernel: its reader
    // authenticates through a genuinely reopened foreign kernel bound to the
    // retained native authority, with the current control capability.
    let foreign_host = super::live_capacity::reopen_scoped_host(
        &migrated,
        &control,
        &foreign_deployment,
        &foreign_profile,
    )?;
    let foreign_reader = foreign_host.kernel.authenticate_recovery_actor(
        &foreign_profile.scope,
        &control,
        RecoveryPermission::KnowledgeRead,
    )?;
    let handle =
        store.issue_artifact_handle(&foreign_reader, &foreign, &recipient, &fence, now_ms()?)?;
    store.prepare_artifact_read(&foreign_reader, &handle, &fence, now_ms()?)?;
    Ok(())
}
