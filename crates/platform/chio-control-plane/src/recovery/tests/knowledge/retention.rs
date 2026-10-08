//! Capacity depends on live owners, never an authority-wide tombstone scan.
use super::*;

fn private_seal(
    f: &KnowledgeFixture,
    reference: &ArtifactVersionRefV1,
) -> TestResult<ArtifactBlobSealV1> {
    let handle = f.runtime.handle(
        &f.f.control,
        reference,
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
    record
        .seal
        .ok_or_else(|| "private object seal is absent".into())
}

#[test]
fn artifacts_equal_content_collection_reclaims_only_exact_logical_object() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("equal-custody-first", b"same")?;
    let second = f.publish("equal-custody-second", b"same")?;
    let first_seal = private_seal(&f, &first)?;
    let second_seal = private_seal(&f, &second)?;
    assert_ne!(first_seal.generation, second_seal.generation);
    let before = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(before.tree_bytes, 8);
    assert_eq!(before.tree_blobs, 2);

    f.runtime.collect(&f.f.control, &first)?;

    let after = f.broker.storage_usage(&f.profile.scope.process_id)?;
    assert_eq!(
        after.tree_bytes, 4,
        "retired object must return its own bytes"
    );
    assert_eq!(after.tree_blobs, 1);
    assert!(f.broker.read_private(&first_seal).is_err());
    assert_eq!(f.broker.read_private(&second_seal)?, b"same");
    let second_handle = f.runtime.handle(
        &f.f.control,
        &second,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    assert!(f.runtime.prepare_read(&f.f.control, &second_handle).is_ok());
    Ok(())
}

#[test]
fn artifacts_independent_equal_content_publication_survives_other_object_sweep() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("separate-sweep-first", b"same")?;
    let first_seal = private_seal(&f, &first)?;
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        if stage == crate::knowledge::KnowledgeCutpoint::CollectionRetired {
            Err(KernelError::Internal(
                "retirement acknowledgement lost".into(),
            ))
        } else {
            Ok(())
        }
    }));
    assert!(faulty.collect(&f.f.control, &first).is_err());
    assert_eq!(f.broker.read_private(&first_seal)?, b"same");
    let second = f
        .publish("separate-sweep-second", b"same")
        .map_err(|error| format!("independent object during equal-content sweep: {error}"))?;
    let second_seal = private_seal(&f, &second)?;
    assert_ne!(first_seal.generation, second_seal.generation);

    f.runtime.collect(&f.f.control, &first)?;
    assert!(f.broker.read_private(&first_seal).is_err());
    assert_eq!(f.broker.read_private(&second_seal)?, b"same");
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_bytes,
        4
    );
    Ok(())
}

#[test]
fn artifacts_collected_publications_return_live_capacity() -> TestResult {
    let f = KnowledgeFixture::new()?;
    for ordinal in 0..513 {
        let reference = f
            .publish(&format!("retired-{ordinal}"), b"small-reusable-content")
            .map_err(|error| {
                format!("publication {ordinal} failed after earlier collection: {error}")
            })?;
        f.runtime.collect(&f.f.control, &reference)?;
    }
    let reference = f.publish("after-lifetime-inventory", b"current-content")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let sink = f.sink();
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("after-collection")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &sink,
    )?;
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"current-content".to_vec()]
    );
    Ok(())
}

fn live_publication_count(f: &KnowledgeFixture) -> TestResult<u64> {
    Ok(f.f
        .authority
        .admission_operation_store()
        .inspect_live_publication_count(
            &f.actor(RecoveryPermission::KnowledgeAdmin)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?)
}

#[test]
fn artifacts_certified_publication_preserves_original_live_allocation() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let mut input = f.input("certified-live-allocation", b"classified-content")?;
    input.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new("certified-live-allocation")?,
    };
    let reservation = f.runtime.reserve(&f.f.control, &input)?;
    assert_eq!(reservation.metadata.label, InformationLabel::Top);
    let original = artifact_version_reference(&reservation.metadata)?;
    assert_eq!(live_publication_count(&f)?, 1);
    let signed = certificate(&f, &reservation, restricted_label())?;
    let reference =
        f.runtime
            .publish(&f.f.control, &input, b"classified-content", Some(&signed))?;
    assert_eq!(reference.scope, original.scope);
    assert_eq!(reference.artifact, original.artifact);
    assert_eq!(reference.version, original.version);
    assert_ne!(reference.provenance, original.provenance);
    assert_eq!(f.metadata(&reference)?.label, restricted_label());
    assert_eq!(live_publication_count(&f)?, 1);
    f.runtime.collect(&f.f.control, &reference)?;
    assert_eq!(live_publication_count(&f)?, 0);
    Ok(())
}

#[test]
fn artifacts_metadata_source_strengthening_preserves_original_live_allocation() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("strengthened-live-allocation", b"staged-content")?;
    let retained = Arc::new(AtomicUsize::new(0));
    let observed = retained.clone();
    let interrupted = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == KnowledgeCutpoint::StageRetained {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(KernelError::Internal(
                "staged publication acknowledgment withheld".into(),
            ))
        } else {
            Ok(())
        }
    }));
    assert!(interrupted
        .publish(&f.f.control, &input, b"staged-content", None)
        .is_err());
    assert_eq!(retained.load(Ordering::SeqCst), 1);
    let reservation = f.runtime.reserve(&f.f.control, &input)?;
    assert_eq!(reservation.state, ArtifactPublicationStateV1::Staged);
    assert_eq!(reservation.metadata.label, InformationLabel::bottom());
    let original = artifact_version_reference(&reservation.metadata)?;
    assert_eq!(live_publication_count(&f)?, 1);

    let source = publish_label(
        &f,
        "metadata-strengthening-source",
        b"restricted-observation",
        restricted_label(),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &source,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let sink = f.sink();
    let released = f.runtime.release_into(
        &f.f.control,
        &RequestId::new("metadata-strengthening-observation")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &sink,
    )?;
    assert_eq!(released.state, ArtifactDeliveryStateV1::Delivered);
    let reference = f
        .runtime
        .publish(&f.f.control, &input, b"staged-content", None)?;
    assert_eq!(reference.scope, original.scope);
    assert_eq!(reference.artifact, original.artifact);
    assert_eq!(reference.version, original.version);
    assert_ne!(reference.provenance, original.provenance);
    assert_eq!(f.metadata(&reference)?.label, restricted_label());
    assert_eq!(live_publication_count(&f)?, 2);
    f.runtime.collect(&f.f.control, &reference)?;
    // The independent observed source retains its genuine delivery custody.
    assert_eq!(live_publication_count(&f)?, 1);
    Ok(())
}

#[test]
fn artifacts_live_publication_capacity_keeps_unsealed_and_quarantined_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    assert_eq!(live_publication_count(&f)?, 0);
    let unsealed = f.input("unsealed-capacity-owner", b"not-staged")?;
    f.runtime.reserve(&f.f.control, &unsealed)?;
    assert_eq!(live_publication_count(&f)?, 1);
    f.runtime.abort_publication(&f.f.control, &unsealed)?;
    // No seal or Collected acknowledgment proves that no staged orphan exists.
    assert_eq!(live_publication_count(&f)?, 1);

    let input = f.input("quarantined-capacity-owner", b"quarantined")?;
    let reference = f
        .runtime
        .publish(&f.f.control, &input, b"quarantined", None)?;
    let store = f.f.authority.admission_operation_store();
    store.quarantine_artifact_version(
        &f.actor(RecoveryPermission::KnowledgeAdmin)?,
        &reference,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(live_publication_count(&f)?, 2);
    f.runtime.abort_publication(&f.f.control, &input)?;
    assert_eq!(live_publication_count(&f)?, 1);
    f.runtime.abort_publication(&f.f.control, &input)?;
    assert_eq!(live_publication_count(&f)?, 1);
    assert!(f.runtime.reserve(&f.f.control, &unsealed).is_err());
    Ok(())
}

#[test]
fn artifacts_live_publication_capacity_retires_once_after_exact_collection_acknowledgment(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = f.publish("capacity-dependency", b"dependency")?;
    let mut input = f.input("capacity-dependent-owner", b"derived")?;
    input.dependencies = BoundedList::new(vec![root.clone()])?;
    let derived = f.runtime.publish(&f.f.control, &input, b"derived", None)?;
    let seal = private_seal(&f, &derived)?;
    assert_eq!(live_publication_count(&f)?, 2);
    assert!(f.runtime.collect(&f.f.control, &root).is_err());
    let interrupted = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        if stage == KnowledgeCutpoint::CollectionRetired {
            Err(KernelError::Internal(
                "collection acknowledgment withheld".into(),
            ))
        } else {
            Ok(())
        }
    }));
    assert!(interrupted.collect(&f.f.control, &derived).is_err());
    assert_eq!(live_publication_count(&f)?, 2);
    assert_eq!(f.broker.read_private(&seal)?, b"derived");
    f.runtime.collect(&f.f.control, &derived)?;
    assert_eq!(live_publication_count(&f)?, 1);
    f.f.authority
        .admission_operation_store()
        .finish_artifact_collection(
            &f.actor(RecoveryPermission::KnowledgeAdmin)?,
            &seal,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert_eq!(live_publication_count(&f)?, 1);
    f.runtime.collect(&f.f.control, &root)?;
    assert_eq!(live_publication_count(&f)?, 0);
    Ok(())
}

#[test]
fn artifacts_live_publication_capacity_closes_only_genuinely_collected_staging_orphans(
) -> TestResult {
    for point in [
        KnowledgeCutpoint::BlobStaged,
        KnowledgeCutpoint::StageRetained,
        KnowledgeCutpoint::MetadataCommitted,
    ] {
        let f = KnowledgeFixture::new()?;
        let input = f.input("staging-capacity-owner", b"orphan")?;
        let interrupted = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == point {
                Err(KernelError::Internal(
                    "staging acknowledgment withheld".into(),
                ))
            } else {
                Ok(())
            }
        }));
        assert!(interrupted
            .publish(&f.f.control, &input, b"orphan", None)
            .is_err());
        assert_eq!(live_publication_count(&f)?, 1);
        f.runtime.abort_publication(&f.f.control, &input)?;
        assert_eq!(live_publication_count(&f)?, 0);
        f.runtime.abort_publication(&f.f.control, &input)?;
        assert_eq!(live_publication_count(&f)?, 0);
        assert!(f.runtime.reserve(&f.f.control, &input).is_err());
    }
    Ok(())
}

#[test]
fn artifacts_collection_ignores_unrelated_retired_pin_inventory() -> TestResult {
    let base = RecoveryFixture::new(false)?;
    let scope = base.runtime.scope().clone();
    let digest = chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(&scope)?);
    // These are valid inactive legacy pin tombstones. They pin no reference.
    // The production protected writer seals every row/event/global commit.
    let records = (0..4097)
        .map(|ordinal| RecoveryQuotaFixtureRecord {
            scope: scope.clone(),
            key: format!("knowledge-pin:{digest}:retired-{ordinal}"),
            payload: b"null".to_vec(),
        })
        .collect::<Vec<_>>();
    retain_recovery_quota_fixture_records(
        &base.authority.admission_operation_store(),
        &base.authority.mutation_fence(),
        &records,
    )
    .map_err(|error| format!("retired pins: append4097 authenticated inactive records: {error}"))?;
    let f = KnowledgeFixture::from(base)
        .map_err(|error| format!("retired pins: configure native knowledge fixture: {error}"))?;
    let reference = f
        .publish("unrelated-collection", b"unreferenced-content")
        .map_err(|error| format!("retired pins: publish an unreferenced control: {error}"))?;
    f.runtime
        .collect(&f.f.control, &reference)
        .map_err(|error| {
            format!("retired pins: collect over unrelated inactive inventory: {error}")
        })?;
    assert!(f
        .runtime
        .handle(
            &f.f.control,
            &reference,
            &ArtifactRecipientId::new("agent-root")?
        )
        .is_err());
    Ok(())
}

fn active_reference_owners(
    f: &KnowledgeFixture,
    reference: &ArtifactVersionRefV1,
    owner: &str,
) -> TestResult<usize> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut statement = connection.prepare(
        "SELECT payload FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-reference-owner:*'
           AND json_extract(payload,'$.owner.owner')=?1
           AND json_extract(payload,'$.state')='active'",
    )?;
    let mut rows = statement.query([owner])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        let payload: Vec<u8> = row.get(0)?;
        let retained: serde_json::Value = serde_json::from_slice(&payload)?;
        let selected: ArtifactVersionRefV1 = serde_json::from_value(
            retained
                .get("reference")
                .cloned()
                .ok_or("reference owner has no governed version")?,
        )?;
        if selected == *reference {
            count = count.checked_add(1).ok_or("reference count overflow")?;
        }
    }
    Ok(count)
}

#[test]
fn memory_checkpoint_reference_custody_is_indexed_until_exact_revision_retirement() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish(
        "indexed-checkpoint-material",
        b"retained-checkpoint-material",
    )?;
    let checkpoint = CheckpointId::new("indexed-checkpoint-owner")?;
    assert_eq!(
        active_reference_owners(&f, &reference, "checkpoint_revision")?,
        0
    );
    f.runtime.checkpoint(
        &f.f.control,
        &checkpoint,
        0,
        std::slice::from_ref(&reference),
        &[],
    )?;
    assert_eq!(
        active_reference_owners(&f, &reference, "checkpoint_revision")?,
        1,
        "one genuine saved revision must own its exact governed material"
    );
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    f.runtime
        .retire_checkpoint_revision(&f.f.control, &checkpoint, 1)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "checkpoint_revision")?,
        0
    );
    f.runtime
        .retire_checkpoint_revision(&f.f.control, &checkpoint, 1)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "checkpoint_revision")?,
        0
    );
    f.runtime.collect(&f.f.control, &reference)?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        0
    );
    Ok(())
}

#[test]
fn artifacts_operator_reference_custody_is_indexed_until_its_own_retirement() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("indexed-operator-material", b"operator-retained-material")?;
    let evidence = EvidenceRef::new("indexed-operator-owner")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "operator_pin")?,
        1,
        "the authenticated operator pin must retain its exact governed version"
    );
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(active_reference_owners(&f, &reference, "operator_pin")?, 0);
    f.runtime.collect(&f.f.control, &reference)?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        0
    );
    Ok(())
}

fn reference_readiness_refusal(remove: bool) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish(
        "reference-readiness-integrity",
        b"retained-unreferenced-material",
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    f.runtime.prepare_read(&f.f.control, &handle)?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let key: String = connection.query_row(
        "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-reference-ready:*'",
        [],
        |row| row.get(0),
    )?;
    let retained: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events WHERE record_key=?1",
        [&key],
        |row| row.get(0),
    )?;
    assert_eq!(
        retained, 1,
        "the real installation must have sealed its census"
    );
    if remove {
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger'
             AND name='admission_operation_recovery_no_delete'",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch("DROP TRIGGER admission_operation_recovery_no_delete")?;
        assert_eq!(
            connection.execute(
                "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
                [&key],
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
    } else {
        assert_eq!(
            connection.execute(
                "UPDATE admission_operation_recovery_records SET payload=?2 WHERE record_key=?1",
                rusqlite::params![&key, b"null".as_slice()],
            )?,
            1
        );
    }
    let events: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    assert!(
        f.runtime.collect(&f.f.control, &reference).is_err(),
        "missing or corrupt retained readiness cannot become zero reference custody"
    );
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        events,
        "collection refusal must precede every protected retirement write"
    );
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        1
    );
    Ok(())
}

#[test]
fn artifacts_collection_refuses_missing_current_reference_readiness_with_retained_census(
) -> TestResult {
    reference_readiness_refusal(true)
}

#[test]
fn artifacts_collection_refuses_corrupt_current_reference_readiness_before_retirement() -> TestResult
{
    reference_readiness_refusal(false)
}
