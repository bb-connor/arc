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
    assert_eq!(response.verdict, Verdict::Allow);
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
