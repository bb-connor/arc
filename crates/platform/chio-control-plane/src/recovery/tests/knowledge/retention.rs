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
