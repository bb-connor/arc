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
    // A collected publication keeps its identity tombstone: reusing the same
    // publication id refuses, while an independent equal-byte logical object
    // remains publishable (covered above by the surviving second object).
    assert!(
        f.publish("equal-custody-first", b"same").is_err(),
        "a collected publication id must stay retired"
    );
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
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
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

#[test]
fn artifacts_collection_ignores_unrelated_retired_pin_inventory() -> TestResult {
    // More distinct retired operator pins than the old authority-wide scan
    // ceiling, all on one unrelated artifact.
    const RETIRED_PINS: usize = 4097;
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
    let f = KnowledgeFixture::new()?;
    let noise = f.publish("retired-pin-noise", b"pinned-then-released-material")?;
    let control = f.publish("retired-pin-control", b"unrelated-control-material")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    for ordinal in 0..RETIRED_PINS {
        let evidence = EvidenceRef::new(&format!("retired-pin-{ordinal}"))?;
        store.pin_artifact(&admin, &noise, &evidence, &fence, now_ms()?)?;
        store.retire_operator_artifact_pin(&admin, &noise, &evidence, &fence, now_ms()?)?;
    }
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let retained_pins: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-pin:operator:v2:*'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        retained_pins > 4096,
        "the retained retired pin history must cross the old scan ceiling"
    );
    assert_eq!(active_reference_owners(&f, &noise, "operator_pin")?, 0);

    f.runtime
        .collect(&f.f.control, &control)
        .map_err(|error| format!("collect an unrelated artifact past retired pins: {error}"))?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        1
    );
    f.runtime
        .collect(&f.f.control, &noise)
        .map_err(|error| format!("collect the pinned artifact after every pin retired: {error}"))?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        0
    );
    f.publish("after-retired-pin-history", b"fresh-material")?;
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
fn memory_checkpoint_reference_quota_refuses_at_tenant_bound_and_reclaims_after_revision_retirement(
) -> TestResult {
    // Store bounds: at most 4096 active reference owners per tenant account
    // and at most 8 governed artifacts per checkpoint revision.
    const TENANT_ACTIVE_OWNERS: u64 = 4096;
    const REVISION_ARTIFACTS: usize = 8;
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
    let f = KnowledgeFixture::new()?;

    #[derive(Debug, PartialEq)]
    struct Snapshot {
        admitted: u64,
        retired: u64,
        active_owners: u64,
        owner_rows: i64,
        head: Vec<u8>,
        events: i64,
        commits: i64,
    }
    let observe = || -> TestResult<Snapshot> {
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let authority = serde_json::to_value(&f.profile.scope.authority_domain)?;
        let tenant = serde_json::to_value(&f.profile.scope.tenant_id)?;
        let census_rows: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-reference-capacity:*'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            census_rows, 1,
            "the single-tenant fixture holds exactly one capacity census"
        );
        let payload: Vec<u8> = connection.query_row(
            "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-reference-capacity:*'",
            [],
            |row| row.get(0),
        )?;
        let retained: serde_json::Value = serde_json::from_slice(&payload)?;
        let account = retained.get("account").ok_or("capacity account")?;
        if account.get("authority_domain") != Some(&authority)
            || account.get("tenant_id") != Some(&tenant)
        {
            return Err("a foreign tenant owns the capacity census".into());
        }
        let admitted = retained
            .get("admitted")
            .and_then(|v| v.as_u64())
            .ok_or("admitted")?;
        let retired = retained
            .get("retired")
            .and_then(|v| v.as_u64())
            .ok_or("retired")?;
        let (active_owners, owner_rows): (i64, i64) = connection.query_row(
            "SELECT count(*) FILTER (WHERE json_extract(payload,'$.state')='active'), count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-reference-owner:*'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut statement = connection.prepare("SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-checkpoint:v2:latest:*'")?;
        let mut rows = statement.query([])?;
        let mut heads = Vec::new();
        while let Some(row) = rows.next()? {
            heads.push(row.get::<_, Vec<u8>>(0)?);
        }
        assert!(
            heads.len() <= 1,
            "the fixture holds at most one checkpoint head"
        );
        let events: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?;
        let commits: i64 =
            connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
                row.get(0)
            })?;
        Ok(Snapshot {
            admitted,
            retired,
            active_owners: u64::try_from(active_owners).map_err(|_| "owner rows")?,
            owner_rows,
            head: heads.into_iter().next().unwrap_or_default(),
            events,
            commits,
        })
    };

    // A publication without dependencies admits no reference owner, so the
    // control stays collectable at any quota saturation.
    let control = f.publish("quota-control", b"unreferenced-quota-control-material")?;
    let material = (0..REVISION_ARTIFACTS)
        .map(|ordinal| {
            f.publish(
                &format!("quota-material-{ordinal}"),
                b"quota-checkpoint-material",
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let start = observe()?;
    assert!(
        start.admitted >= start.retired,
        "the census must not underflow"
    );
    let active_start = start.admitted - start.retired;
    assert!(
        active_start < TENANT_ACTIVE_OWNERS,
        "a fresh fixture must start below the tenant bound"
    );
    assert_eq!(
        start.active_owners, active_start,
        "the census must state the exact live owner inventory"
    );
    assert_eq!(
        active_reference_owners(&f, &control, "checkpoint_revision")?,
        0
    );

    // Real checkpoint revisions fill the tenant quota exactly, each retaining
    // the public maximum of governed artifacts to minimize the save count.
    let checkpoint = CheckpointId::new("quota-bound-owner")?;
    let mut remaining = (TENANT_ACTIVE_OWNERS - active_start) as usize;
    let mut revision = 0_u64;
    let mut first_owners = 0_usize;
    while remaining > 0 {
        let count = remaining.min(REVISION_ARTIFACTS);
        if revision == 0 {
            first_owners = count;
        }
        let saved = f
            .runtime
            .checkpoint(&f.f.control, &checkpoint, revision, &material[..count], &[])
            .map_err(|error| format!("checkpoint save {revision} below the bound: {error}"))?;
        revision += 1;
        assert_eq!(
            saved.revision.get(),
            revision,
            "each save must allocate the exact next revision"
        );
        remaining -= count;
    }
    let full = observe()?;
    assert_eq!(
        (full.admitted - full.retired, full.active_owners),
        (TENANT_ACTIVE_OWNERS, TENANT_ACTIVE_OWNERS),
        "real checkpoint revisions must fill the quota with live owner rows"
    );
    assert!(
        !full.head.is_empty(),
        "the exact latest head must be retained at the bound"
    );
    assert_eq!(
        active_reference_owners(&f, &material[0], "checkpoint_revision")?,
        revision as usize,
        "every saved revision must retain the governed material"
    );

    // The next admission must refuse inside the owning transaction, leaving
    // the census, owner rows, exact head bytes, events and commits untouched.
    let refused = &material[..first_owners];
    assert!(
        f.runtime
            .checkpoint(&f.f.control, &checkpoint, revision, refused, &[])
            .is_err(),
        "the next checkpoint owner must refuse at the exact tenant bound"
    );
    assert_eq!(
        observe()?,
        full,
        "a refused save must leave the protected state untouched"
    );

    // Retiring the earliest exact revision frees only its own owners.
    f.runtime
        .retire_checkpoint_revision(&f.f.control, &checkpoint, 1)
        .map_err(|error| format!("retire the earliest exact revision: {error}"))?;
    let after_retire = observe()?;
    assert_eq!(
        (
            after_retire.admitted,
            after_retire.retired,
            after_retire.active_owners,
            after_retire.owner_rows
        ),
        (
            full.admitted,
            full.retired + first_owners as u64,
            TENANT_ACTIVE_OWNERS - first_owners as u64,
            full.owner_rows
        ),
        "retirement frees exactly its own owners by flipping row state"
    );
    assert_eq!(
        active_reference_owners(&f, &material[0], "checkpoint_revision")?,
        revision as usize - 1,
        "retirement must release only the earliest revision's custody"
    );

    // The exact refused save now succeeds and re-enters the same bound.
    let saved = f
        .runtime
        .checkpoint(&f.f.control, &checkpoint, revision, refused, &[])
        .map_err(|error| format!("retry the refused save after reclamation: {error}"))?;
    assert_eq!(
        saved.revision.get(),
        revision + 1,
        "the reclaimed save must allocate the exact next revision"
    );
    let end = observe()?;
    assert_eq!(
        (
            end.admitted,
            end.admitted - end.retired,
            end.active_owners,
            end.owner_rows
        ),
        (
            after_retire.admitted + first_owners as u64,
            TENANT_ACTIVE_OWNERS,
            TENANT_ACTIVE_OWNERS,
            full.owner_rows + first_owners as i64
        ),
        "the retried save must re-enter the exact bound with reclaimed owners"
    );
    assert!(
        end.admitted > TENANT_ACTIVE_OWNERS,
        "the admitted lifetime crosses the bound: reclamation, not a reset"
    );
    assert_ne!(
        end.head, full.head,
        "the reclaimed revision must replace the retained head bytes"
    );
    assert_eq!(
        active_reference_owners(&f, &material[0], "checkpoint_revision")?,
        revision as usize,
        "the reclaimed revision must retain the governed material again"
    );
    // Collection remains live at the active bound after retained owner history
    // has crossed the old global scan ceiling.
    assert!(end.owner_rows > TENANT_ACTIVE_OWNERS as i64);
    f.runtime
        .collect(&f.f.control, &control)
        .map_err(|error| format!("collect the control at the bound: {error}"))?;
    let after_collect = observe()?;
    assert_eq!(
        (
            after_collect.admitted,
            after_collect.retired,
            after_collect.active_owners,
            after_collect.owner_rows,
            &after_collect.head
        ),
        (
            end.admitted,
            end.retired,
            end.active_owners,
            end.owner_rows,
            &end.head
        ),
        "collecting unreferenced custody must not disturb the tenant quota"
    );
    assert!(
        f.runtime
            .handle(
                &f.f.control,
                &control,
                &ArtifactRecipientId::new("agent-root")?
            )
            .is_err(),
        "collected control material must not remain readable"
    );

    Ok(())
}

pub(super) fn active_reference_owners(
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
        "the real installation must have sealed its readiness activation"
    );
    if remove {
        // Remove only this disposable database's projection, retaining history.
        // Restore its deletion trigger immediately after injecting the fault.
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger'
             AND name='admission_operation_recovery_no_delete'",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF; DROP TRIGGER admission_operation_recovery_no_delete",
        )?;
        assert_eq!(
            connection.execute(
                "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
                [&key],
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
        connection.execute_batch("PRAGMA foreign_keys=ON")?;
    } else {
        // A version advance permits the fixture update, but no corresponding
        // authenticated event exists. Protected reads must reject this row.
        assert_eq!(
            connection.execute(
                "UPDATE admission_operation_recovery_records
                 SET payload=?2, version=version+1 WHERE record_key=?1",
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
    let commits: i64 =
        connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })?;
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
        connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get::<_, i64>(0)
        },)?,
        commits,
        "collection refusal must not advance the authority"
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
fn artifacts_collection_refuses_missing_current_reference_readiness_with_retained_history(
) -> TestResult {
    reference_readiness_refusal(true)
}

#[test]
fn artifacts_collection_refuses_corrupt_current_reference_readiness_before_retirement() -> TestResult
{
    reference_readiness_refusal(false)
}

#[derive(Debug, PartialEq)]
pub(super) struct Custody {
    records: Vec<(String, i64, Vec<u8>)>,
    pub(super) events: i64,
    pub(super) commits: i64,
}

pub(super) fn custody(f: &KnowledgeFixture) -> TestResult<Custody> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut query = connection.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records
         ORDER BY record_key",
    )?;
    let records = query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    Ok(Custody {
        records,
        events: connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?,
        commits: connection.query_row(
            "SELECT count(*) FROM authority_global_commits",
            [],
            |row| row.get(0),
        )?,
    })
}

fn unique_record(custody: &Custody, prefix: &str) -> TestResult<(String, i64, serde_json::Value)> {
    let mut matching = custody
        .records
        .iter()
        .filter(|(key, _, _)| key.starts_with(prefix));
    let (key, version, payload) = matching.next().ok_or("custody record absent")?;
    if matching.next().is_some() {
        return Err("custody record is not unique".into());
    }
    Ok((key.clone(), *version, serde_json::from_slice(payload)?))
}

pub(super) fn census_retired(custody: &Custody) -> TestResult<u64> {
    let (_, _, census) = unique_record(custody, "knowledge-reference-capacity:")?;
    census["retired"]
        .as_u64()
        .ok_or_else(|| "capacity census retired counter".into())
}

pub(super) fn invariant_refusal(
    detail: &str,
) -> Option<chio_kernel::admission_operation::AdmissionOperationStoreError> {
    Some(
        chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
            detail.to_owned(),
        ),
    )
}

#[test]
fn artifacts_operator_pin_retirement_settles_its_exact_terminal_and_refund_once() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("closure-pin-material", b"closure-pin-material")?;
    let unrelated = f.publish("closure-pin-unrelated", b"closure-pin-unrelated")?;
    let evidence = EvidenceRef::new("closure-pin-owner")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
    let before = custody(&f)?;
    let (key, version, pending) = unique_record(&before, "knowledge-pin:operator:v2:")?;
    assert_eq!(
        pending.get("state"),
        None,
        "an admitted operator pin is pending"
    );

    let foreign = ArtifactVersionRefV1 {
        scope: chio_security_types::recovery::RecoveryScopeV1 {
            tenant_id: chio_security_types::recovery::RecoveryTenantId::new(
                "closure-foreign-tenant",
            )?,
            ..reference.scope.clone()
        },
        ..reference.clone()
    };
    for (selected, owner) in [
        (&reference, EvidenceRef::new("closure-pin-other-owner")?),
        (&unrelated, evidence.clone()),
        (&foreign, evidence.clone()),
    ] {
        assert!(store
            .retire_operator_artifact_pin(&admin, selected, &owner, &fence, now_ms()?)
            .is_err());
        assert_eq!(
            custody(&f)?,
            before,
            "a foreign or mismatched owner must neither write nor refund"
        );
    }

    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    let after = custody(&f)?;
    // One terminal plus the existing single-reference refund: bucket, owner
    // leaf, aggregate and capacity census.
    assert_eq!(
        (after.events - before.events, after.commits - before.commits),
        (5, 5)
    );
    assert_eq!(census_retired(&after)?, census_retired(&before)? + 1);
    let (retired_key, retired_version, retired) =
        unique_record(&after, "knowledge-pin:operator:v2:")?;
    assert_eq!((retired_key, retired_version), (key, version + 1));
    assert_eq!(retired["state"], "retired");
    assert_eq!(retired["owner"], pending["owner"]);
    assert_eq!(retired["reference"], pending["reference"]);
    assert_eq!(
        retired["retirement"]["principal"],
        serde_json::to_value(admin.principal())?
    );
    assert_eq!(
        retired["retirement"]["installation_generation"],
        serde_json::to_value(&f.profile.generation)?
    );
    assert_eq!(
        retired["retirement"]["policy"],
        serde_json::to_value(&f.profile.policy)?
    );
    assert_eq!(active_reference_owners(&f, &reference, "operator_pin")?, 0);

    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(
        custody(&f)?,
        after,
        "an exact replay writes, appends and refunds nothing"
    );
    f.runtime.collect(&f.f.control, &reference)?;
    Ok(())
}

#[test]
fn artifacts_operator_pin_closure_refuses_another_writer_and_changed_sources() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("closure-interference-material", b"closure-interference")?;
    let evidence = EvidenceRef::new("closure-interference-owner")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
    let successor = NativeKnowledgeInstallationV1 {
        generation: SafeInteger::new(f.profile.generation.get() + 1)?,
        ..f.profile.clone()
    };
    let before = custody(&f)?;
    for (interference, refusal) in [
        (
            KnowledgeClosureInterference::OtherWriter,
            "knowledge closure changed its physical writer",
        ),
        (
            KnowledgeClosureInterference::SourceAdvanced,
            "knowledge closure has no pending source",
        ),
        (
            KnowledgeClosureInterference::ProfileAdvanced(Box::new(successor)),
            "knowledge closure lost its current installation",
        ),
    ] {
        assert_eq!(
            store
                .attempt_operator_pin_closure_for_test(
                    &admin,
                    &reference,
                    &evidence,
                    interference,
                    &fence,
                    now_ms()?,
                )
                .err(),
            invariant_refusal(refusal)
        );
        assert_eq!(custody(&f)?, before, "{refusal} must roll back completely");
    }
    assert_eq!(active_reference_owners(&f, &reference, "operator_pin")?, 1);
    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(active_reference_owners(&f, &reference, "operator_pin")?, 0);
    Ok(())
}

#[test]
fn artifacts_authenticated_retirement_settles_while_high_wal_refuses_intake() -> TestResult {
    const MIB: u64 = 1024 * 1024;
    let f = KnowledgeFixture::new()?;
    let pinned = f.publish("high-wal-pinned", b"high-wal-pinned")?;
    let material = f.publish("high-wal-checkpoint-material", b"high-wal-checkpoint")?;
    let checkpoint = CheckpointId::new("high-wal-checkpoint")?;
    f.runtime.checkpoint(
        &f.f.control,
        &checkpoint,
        0,
        std::slice::from_ref(&material),
        &[],
    )?;
    let evidence = EvidenceRef::new("high-wal-operator")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    store.pin_artifact(&admin, &pinned, &evidence, &fence, now_ms()?)?;
    let reader = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    reader.execute_batch("BEGIN")?;
    let _: i64 = reader.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    let pressure = grow_recovery_quota_fixture_uncheckpointed_history(&store, &fence, 80 * MIB)?;
    assert!((80 * MIB..128 * MIB).contains(&pressure));
    let before = custody(&f)?;
    assert_eq!(
        store
            .pin_artifact(
                &admin,
                &pinned,
                &EvidenceRef::new("high-wal-fresh-intake")?,
                &fence,
                now_ms()?,
            )
            .err(),
        invariant_refusal("recovery disk headroom exhausted"),
        "fresh typed intake must stop at the physical intake band"
    );
    assert_eq!(custody(&f)?, before);

    store.retire_operator_artifact_pin(&admin, &pinned, &evidence, &fence, now_ms()?)?;
    store.retire_checkpoint_revision(&admin, &checkpoint, 1, &fence, now_ms()?)?;
    let after = custody(&f)?;
    // Each terminal plus its single-reference refund, in the settlement band.
    assert_eq!(
        (after.events - before.events, after.commits - before.commits),
        (10, 10)
    );
    assert_eq!(census_retired(&after)?, census_retired(&before)? + 2);
    assert_eq!(active_reference_owners(&f, &pinned, "operator_pin")?, 0);
    assert_eq!(
        active_reference_owners(&f, &material, "checkpoint_revision")?,
        0
    );
    reader.execute_batch("COMMIT")?;
    Ok(())
}

/// Real uncheckpointed WAL held above the intake band and below the settlement
/// band by a pinned independent reader, as the existing pressure regressions do.
pub(super) struct HighWal {
    reader: rusqlite::Connection,
}

impl HighWal {
    pub(super) fn begin(f: &KnowledgeFixture) -> TestResult<Self> {
        const MIB: u64 = 1024 * 1024;
        let reader = rusqlite::Connection::open_with_flags(
            f.f.path.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        reader.execute_batch("BEGIN")?;
        let _: i64 = reader.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?;
        let pressure = grow_recovery_quota_fixture_uncheckpointed_history(
            &f.f.authority.admission_operation_store(),
            &f.f.authority.mutation_fence(),
            80 * MIB,
        )?;
        assert!((80 * MIB..128 * MIB).contains(&pressure));
        Ok(Self { reader })
    }

    pub(super) fn release(self) -> TestResult {
        self.reader.execute_batch("COMMIT")?;
        Ok(())
    }
}

#[test]
fn artifacts_collection_returns_its_live_slot_once_after_actual_collection_under_high_wal(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("high-wal-collected", b"high-wal-collected")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let unswept = private_seal(&f, &reference)?;
    let pressure = HighWal::begin(&f)?;
    let live = live_publication_count(&f)?;
    let before = custody(&f)?;
    assert!(
        store
            .finish_artifact_collection(&admin, &unswept, &fence, now_ms()?)
            .is_err(),
        "an acknowledgment without its Sweeping barrier refuses"
    );
    assert_eq!(custody(&f)?, before);
    assert_eq!(
        store
            .pin_artifact(
                &admin,
                &reference,
                &EvidenceRef::new("high-wal-collection-intake")?,
                &fence,
                now_ms()?,
            )
            .err(),
        invariant_refusal("recovery disk headroom exhausted"),
        "fresh typed intake must stop at the physical intake band"
    );
    assert_eq!(custody(&f)?, before);

    let seal = store
        .retire_artifact(&admin, &reference, &fence, now_ms()?)?
        .ok_or("a retired sealed publication must owe its physical collection")?;
    let retired = custody(&f)?;
    // The Retired publication and its Sweeping barrier; it has no dependency owners.
    assert_eq!(
        (
            retired.events - before.events,
            retired.commits - before.commits
        ),
        (2, 2)
    );
    assert_eq!(
        live_publication_count(&f)?,
        live,
        "a Retired marker alone must not return a live slot"
    );
    assert!(store
        .retire_artifact(&admin, &reference, &fence, now_ms()?)?
        .is_some_and(|replayed| replayed == seal));
    assert_eq!(custody(&f)?, retired, "retirement replay writes nothing");

    f.broker.collect_private(&seal)?;
    store.finish_artifact_collection(&admin, &seal, &fence, now_ms()?)?;
    let collected = custody(&f)?;
    // The Collected sweep plus the exact lease and tenant capacity successors.
    assert_eq!(
        (
            collected.events - retired.events,
            collected.commits - retired.commits
        ),
        (3, 3)
    );
    assert_eq!(live_publication_count(&f)?, live - 1);
    store.finish_artifact_collection(&admin, &seal, &fence, now_ms()?)?;
    assert_eq!(
        custody(&f)?,
        collected,
        "acknowledgment replay refunds once"
    );
    assert_eq!(live_publication_count(&f)?, live - 1);
    assert!(f.broker.read_private(&seal).is_err());
    pressure.release()
}

#[test]
fn artifacts_publication_retirement_closure_refuses_another_writer_and_changed_sources(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("closure-publication", b"closure-publication")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let successor = NativeKnowledgeInstallationV1 {
        generation: SafeInteger::new(f.profile.generation.get() + 1)?,
        ..f.profile.clone()
    };
    let before = custody(&f)?;
    for (interference, refusal) in [
        (
            KnowledgeClosureInterference::OtherWriter,
            "knowledge closure changed its physical writer",
        ),
        (
            KnowledgeClosureInterference::SourceAdvanced,
            "knowledge closure has no pending source",
        ),
        (
            KnowledgeClosureInterference::ProfileAdvanced(Box::new(successor)),
            "knowledge closure lost its current installation",
        ),
    ] {
        assert_eq!(
            store
                .attempt_publication_retirement_closure_for_test(
                    &admin,
                    &reference,
                    interference,
                    &fence,
                    now_ms()?,
                )
                .err(),
            invariant_refusal(refusal)
        );
        assert_eq!(custody(&f)?, before, "{refusal} must roll back completely");
    }
    assert!(store
        .retire_artifact(&admin, &reference, &fence, now_ms()?)?
        .is_some());
    Ok(())
}

#[test]
fn artifacts_typed_intake_and_collection_settle_while_the_generic_knowledge_pool_is_full(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("pool-collected", b"pool-collected")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    fill_recovery_quota_fixture_intake_bytes(&store, &fence, &f.profile.scope, 48 * 1024 * 1024)?;
    let live = live_publication_count(&f)?;
    // A pin is typed tenant intake charged to its reference account, never to
    // the exhausted generic pool, and its retirement refunds that owner.
    let evidence = EvidenceRef::new("pool-typed-intake")?;
    let owners = active_reference_owners(&f, &reference, "operator_pin")?;
    store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "operator_pin")?,
        owners + 1
    );
    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(
        active_reference_owners(&f, &reference, "operator_pin")?,
        owners
    );
    let before = custody(&f)?;
    let seal = store
        .retire_artifact(&admin, &reference, &fence, now_ms()?)?
        .ok_or("a retired sealed publication must owe its physical collection")?;
    f.broker.collect_private(&seal)?;
    store.finish_artifact_collection(&admin, &seal, &fence, now_ms()?)?;
    let after = custody(&f)?;
    // Retired, Sweeping, Collected, lease and capacity: each owed by the one
    // admitted publication and never refused by the exhausted intake pool.
    assert_eq!(
        (after.events - before.events, after.commits - before.commits),
        (5, 5)
    );
    assert_eq!(live_publication_count(&f)?, live - 1);
    Ok(())
}

/// A bounded file-backed historical blob port for the Store sweep contract.
/// Each retained generation is one real file whose generation is not an
/// object identity; collection deletes exactly that generation's file. It is
/// not native Process custody and qualifies no Process integration.
struct HistoricalBlobs {
    root: std::path::PathBuf,
    generations: std::sync::atomic::AtomicUsize,
}

impl HistoricalBlobs {
    fn new(f: &KnowledgeFixture) -> TestResult<Self> {
        let root = f.f.path.join("historical-blobs");
        std::fs::create_dir(&root)?;
        Ok(Self {
            root,
            generations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Retain one new generation of these bytes for an actual reserved object.
    fn retain(
        &self,
        f: &KnowledgeFixture,
        object: &ArtifactObjectId,
        bytes: &[u8],
    ) -> TestResult<ArtifactBlobSealV1> {
        let ordinal = self
            .generations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let generation = format!("historical-{ordinal:04}");
        std::fs::write(self.root.join(&generation), bytes)?;
        Ok(ArtifactBlobSealV1 {
            object: object.clone(),
            runtime: ProtectedText::new(f.profile.producer_context.as_v1().session_id().as_str())?,
            process: f.profile.scope.process_id.clone(),
            content: knowledge_content_digest(bytes),
            bytes: SafeInteger::new(bytes.len() as u64)?,
            generation: ProtectedText::new(&generation)?,
        })
    }

    fn read(&self, seal: &ArtifactBlobSealV1) -> TestResult<Vec<u8>> {
        let bytes = std::fs::read(self.root.join(seal.generation.as_str()))?;
        if knowledge_content_digest(&bytes) != seal.content {
            return Err("historical blob changed its content".into());
        }
        Ok(bytes)
    }

    /// Physically delete exactly this generation; a second collection fails.
    fn collect(&self, seal: &ArtifactBlobSealV1) -> TestResult {
        self.read(seal)?;
        std::fs::remove_file(self.root.join(seal.generation.as_str()))?;
        Ok(())
    }
}

/// Publish through the actual authenticated Store writers with a historical
/// seal from the file-backed port.
fn publish_historical(
    f: &KnowledgeFixture,
    blobs: &HistoricalBlobs,
    id: &str,
    bytes: &[u8],
) -> TestResult<(ArtifactVersionRefV1, ArtifactBlobSealV1)> {
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    let input = f.input(id, bytes)?;
    let reserved = store.reserve_artifact(&writer, &input, &fence, now_ms()?)?;
    let seal = blobs.retain(f, &reserved.object, bytes)?;
    store.stage_artifact(&writer, &input, &seal, &fence, now_ms()?)?;
    store.commit_artifact_metadata(&writer, &input, None, &fence, now_ms()?)?;
    assert_eq!(blobs.read(&seal)?, bytes);
    let reference = store.finalize_artifact(&writer, &input, &seal, &fence, now_ms()?)?;
    Ok((reference, seal))
}

/// Store sweep-contract regression for historical content-addressed seals.
#[test]
fn artifacts_historical_retirement_replay_after_same_content_collection_writes_nothing(
) -> TestResult {
    let f = KnowledgeFixture::new()?;
    let blobs = HistoricalBlobs::new(&f)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let bytes = b"historical-same-content";
    let collect = |reference: &ArtifactVersionRefV1, seal: &ArtifactBlobSealV1| -> TestResult {
        let live = live_publication_count(&f)?;
        let before = custody(&f)?;
        let swept = store
            .retire_artifact(&admin, reference, &fence, now_ms()?)?
            .ok_or("a retired historical publication must owe its collection")?;
        assert!(swept == *seal, "retirement must sweep its own exact seal");
        let retired = custody(&f)?;
        // Retired publication and its Sweeping barrier; no dependency owners.
        assert_eq!(
            (
                retired.events - before.events,
                retired.commits - before.commits
            ),
            (2, 2)
        );
        assert_eq!(live_publication_count(&f)?, live);
        blobs.collect(seal)?;
        store.finish_artifact_collection(&admin, seal, &fence, now_ms()?)?;
        let collected = custody(&f)?;
        // Collected sweep plus the exact lease and tenant capacity refund.
        assert_eq!(
            (
                collected.events - retired.events,
                collected.commits - retired.commits
            ),
            (3, 3)
        );
        assert_eq!(live_publication_count(&f)?, live - 1);
        assert!(blobs.read(seal).is_err());
        Ok(())
    };

    let (first, first_seal) = publish_historical(&f, &blobs, "historical-a", bytes)?;
    collect(&first, &first_seal)?;
    let (second, second_seal) = publish_historical(&f, &blobs, "historical-b", bytes)?;
    assert!(
        second_seal.content == first_seal.content
            && second_seal.generation != first_seal.generation
    );
    collect(&second, &second_seal)?;

    // The first owner's own acknowledgment is retained in the shared sweep's
    // history, so its replay owes nothing: no write, no seal, no sweep lock.
    let settled = custody(&f)?;
    assert!(store
        .retire_artifact(&admin, &first, &fence, now_ms()?)?
        .is_none());
    assert_eq!(custody(&f)?, settled);

    // A future same-content generation still collects and refunds.
    let (third, third_seal) = publish_historical(&f, &blobs, "historical-c", bytes)?;
    collect(&third, &third_seal)?;
    Ok(())
}

fn generic_pool_events(f: &KnowledgeFixture) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    Ok(connection.query_row(
        &format!(
            "SELECT count(*) FROM admission_operation_recovery_events WHERE {}",
            recovery_quota_fixture_knowledge_pool("record_key")
        ),
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn artifacts_typed_history_never_consumes_generic_installation_capacity() -> TestResult {
    // The unchanged generic Knowledge pool admits at most 57,344 events.
    const POOL_EVENTS: i64 = 57_344;
    const CHURN: usize = 16;
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("generic-pool-churn", b"generic-pool-churn")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    fill_recovery_quota_fixture_intake_events(
        &store,
        &fence,
        &f.profile.scope,
        u64::try_from(POOL_EVENTS - 8)?,
    )?;
    assert_eq!(generic_pool_events(&f)?, POOL_EVENTS - 8);

    // Typed pins with their reference owners and retirements retain history
    // the implicit pool used to charge; none of it is generic intake.
    let before = custody(&f)?;
    for ordinal in 0..CHURN {
        let evidence = EvidenceRef::new(&format!("generic-pool-churn-{ordinal}"))?;
        store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
        store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    }
    let churned = custody(&f)?;
    assert!(churned.events - before.events >= i64::try_from(2 * CHURN)?);
    assert_eq!(
        generic_pool_events(&f)?,
        POOL_EVENTS - 8,
        "typed and reference history is not charged to the generic pool"
    );

    // A successor profile and a new tenant still install.
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    store.configure_knowledge(&profile)?;
    super::live_capacity::scoped_host(&f, "generic-pool-tenant", "generic-pool-root")?;

    // Remaining generic intake still stops at the unchanged quota, writing
    // nothing when it refuses.
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&f.profile.scope)?);
    let mut refusal = None;
    for ordinal in 0..16 {
        let full = custody(&f)?;
        let record = RecoveryQuotaFixtureRecord {
            scope: f.profile.scope.clone(),
            key: format!("knowledge-pin:{scope}:generic-pool-tail-{ordinal}"),
            payload: chio_core::canonical_json_bytes(&"generic pool tail")?,
        };
        if let Err(error) = retain_recovery_quota_fixture_records(&store, &fence, &[record]) {
            assert_eq!(custody(&f)?, full);
            refusal = Some(error);
            break;
        }
    }
    assert_eq!(
        refusal,
        Some(
            chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                "recovery retained resource exhausted".to_owned()
            )
        )
    );
    assert_eq!(generic_pool_events(&f)?, POOL_EVENTS);
    Ok(())
}
