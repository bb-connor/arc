//! Administrative retirement preserves distinct native custody and spent identity.
use super::*;

fn protected_events(f: &KnowledgeFixture) -> TestResult<i64> {
    Ok(
        rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?,
    )
}

#[test]
fn artifacts_operator_pin_retirement_reclaims_ownership_without_reviving_identity() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("retiring-operator-pin", b"governed-reference")?;
    let evidence = EvidenceRef::new("retiring-operator-evidence")?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    store.pin_artifact(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    let before = protected_events(&f)?;
    assert!(store
        .retire_operator_artifact_pin(&reader, &reference, &evidence, &fence, now_ms()?)
        .is_err());
    let mut foreign = reference.clone();
    foreign.scope.tenant_id = RecoveryTenantId::new("foreign-pin-retirement")?;
    assert!(store
        .retire_operator_artifact_pin(&admin, &foreign, &evidence, &fence, now_ms()?)
        .is_err());
    assert_eq!(protected_events(&f)?, before);
    let revoked = super::release_audience::install_actor(
        &f,
        230,
        "revoked-pin-administrator",
        restricted_label(),
        &[RecoveryPermission::KnowledgeAdmin],
    )?;
    let revoked_actor = f.f.kernel.authenticate_recovery_actor(
        &f.profile.scope,
        &revoked,
        RecoveryPermission::KnowledgeAdmin,
    )?;
    f.f.kernel.revoke_capability(&revoked.id)?;
    let before = protected_events(&f)?;
    assert!(store
        .retire_operator_artifact_pin(&revoked_actor, &reference, &evidence, &fence, now_ms()?)
        .is_err());
    assert_eq!(protected_events(&f)?, before);
    store.knowledge_installation(&admin, &fence, now_ms()?)?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        1
    );
    let retired =
        store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?);
    assert!(
        retired.is_ok(),
        "fresh owning Admin must retire its exact native operator pin after controls passed: {retired:?}"
    );
    retired?;
    let retired_events = protected_events(&f)?;
    store.retire_operator_artifact_pin(&admin, &reference, &evidence, &fence, now_ms()?)?;
    assert_eq!(protected_events(&f)?, retired_events);
    f.runtime.collect(&f.f.control, &reference)?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        0
    );
    let other = f.publish("spent-operator-pin-target", b"independent-reference")?;
    let before = protected_events(&f)?;
    assert!(store
        .pin_artifact(&admin, &other, &evidence, &fence, now_ms()?)
        .is_err());
    assert_eq!(protected_events(&f)?, before);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn artifacts_operator_pin_retirement_cannot_release_unknown_native_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let native_reference = f.publish("native-pin-retirement-floor", b"unknown-native-input")?;
    let operator_reference =
        f.publish("operator-pin-retirement-floor", b"operator-only-evidence")?;
    let workflow = f.f.ready().await?;
    f.f.behavior.store(1, Ordering::SeqCst);
    let record = f.f.record(&workflow)?;
    f.f.runtime
        .execute_command(
            &f.f.control,
            &f.f.command(
                "native-pin-retirement-resume",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: record.revision,
                },
            )?,
        )
        .await?;
    let record = f.f.record(&workflow)?;
    assert!(matches!(record.effect, EffectObservationV1::Unknown { .. }));
    let operation = record.native_link.ok_or("unknown native custody absent")?;
    let evidence = EvidenceRef::new(&format!("operation:{}", operation.as_str()))?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    store.pin_artifact(&admin, &operator_reference, &evidence, &fence, now_ms()?)?;
    store.pin_native_artifact_operation(
        &admin,
        &native_reference,
        &operation,
        &fence,
        now_ms()?,
    )?;
    assert!(f.runtime.collect(&f.f.control, &native_reference).is_err());
    let before = protected_events(&f)?;
    assert!(store
        .retire_operator_artifact_pin(&admin, &native_reference, &evidence, &fence, now_ms()?,)
        .is_err());
    assert_eq!(protected_events(&f)?, before);
    let retired = store.retire_operator_artifact_pin(
        &admin,
        &operator_reference,
        &evidence,
        &fence,
        now_ms()?,
    );
    assert!(retired.is_ok(), "operator retirement refused after distinct genuine native ownership was proven: {retired:?}");
    retired?;
    f.runtime.collect(&f.f.control, &operator_reference)?;
    assert!(f.runtime.collect(&f.f.control, &native_reference).is_err());
    assert_eq!(external_count(&f.f.path)?, 1);
    Ok(())
}
