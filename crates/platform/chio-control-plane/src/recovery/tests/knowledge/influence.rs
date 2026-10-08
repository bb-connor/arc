//! Influence inherits the same principal, lineage and session scopes as labels.
use super::*;

#[test]
fn native_knowledge_release_matches_its_complete_join_liability_preview() -> TestResult {
    let f = KnowledgeFixture::new()
        .map_err(|error| format!("native join preview fixture configuration: {error}"))?;
    let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        eprintln!("native join preview publication/release stage: {stage:?}");
        Ok(())
    }));
    let bytes = b"native-preview-content";
    let mut input = f.input("native-join-preview", bytes)?;
    input.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new("native-join-preview")?,
    };
    let reservation = runtime
        .reserve(&f.f.control, &input)
        .map_err(|error| format!("native join preview adoption reservation: {error}"))?;
    eprintln!("native join preview adoption reservation committed");
    let proof = certificate(&f, &reservation, restricted_label())
        .map_err(|error| format!("native join preview signed adoption certificate: {error}"))?;
    eprintln!("native join preview adoption certificate signed");
    let reference = runtime
        .publish(&f.f.control, &input, bytes, Some(&proof))
        .map_err(|error| format!("native join preview certified adoption publication: {error}"))?;
    let handle = runtime
        .handle(
            &f.f.control,
            &reference,
            &ArtifactRecipientId::new("agent-root")?,
        )
        .map_err(|error| format!("native join preview recipient handle: {error}"))?;
    let work = NativeInfluenceReadWorkFixture::begin()?;
    let prepared = runtime
        .prepare_read(&f.f.control, &handle)
        .map_err(|error| format!("native join preview prepared read: {error}"))?;
    let released = runtime
        .release_into(
            &f.f.control,
            &RequestId::new("native-join-preview-release")?,
            prepared,
            &f.sink(),
        )
        .map_err(|error| format!("native join preview owning release: {error}"))?;
    assert_eq!(work.knowledge_join_previews(), 1);
    assert_eq!(work.knowledge_join_readbacks(), 1);
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let (roots, globals): (i64, i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'knowledge-join:*'),
                (SELECT count(*) FROM authority_global_commits
                 WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-join:*')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(roots, 1);
    assert_eq!(globals, 1);
    assert_eq!(released.state, ArtifactDeliveryStateV1::Delivered);
    Ok(())
}

#[test]
fn native_influence_read_has_bounded_projection_work_after_many_owned_releases() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = publish_label(
        &f,
        "bounded-influence-source",
        b"externally-authored-bounded-observation",
        restricted_label(),
    )?;
    for sequence in 0..8 {
        let handle = f.runtime.handle(
            &f.f.control,
            &reference,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        f.runtime.release_into(
            &f.f.control,
            &RequestId::new(&format!("bounded-influence-read-{sequence}"))?,
            f.runtime.prepare_read(&f.f.control, &handle)?,
            &f.sink(),
        )?;
    }
    let work = NativeInfluenceReadWorkFixture::begin()?;
    let observed = f
        .f
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(&f.profile.scope, &f.f.authority.mutation_fence(), now_ms()?)?
        .ok_or("owned observations lost influence")?;
    assert!(observed.externally_influenced);
    assert!(observed.unknown);
    assert!(
        work.history_bodies() + work.current_projections() <= 3,
        "native influence framing traversed {} history bodies and {} current projections",
        work.history_bodies(),
        work.current_projections(),
    );
    Ok(())
}

#[test]
fn memory_lineage_influence_survives_a_new_principal_isolation_epoch() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = publish_label(
        &f,
        "lineage-source",
        b"externally-authored-observation",
        restricted_label(),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("lineage-observation")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    let store = f.f.authority.admission_operation_store();
    let first = store
        .observe_knowledge_influence(&f.profile.scope, &f.f.authority.mutation_fence(), now_ms()?)?
        .ok_or("first influence")?;
    assert!(first.externally_influenced);
    assert!(first.unknown);

    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let old = deployment.security_context.as_v1();
    deployment.security_context =
        chio_kernel::SecurityInvocationContext::V1(chio_kernel::SecurityInvocationContextV1::new(
            old.tenant_id().clone(),
            chio_security_types::ports::SessionId::new("second-lineage-session")?,
            PrincipalId::new("second-lineage-principal")?,
            chio_security_types::ports::IsolationEpochId::new("second-lineage-epoch")?,
            old.lineage_root_id().clone(),
            0,
        ));
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let inherited = store
        .observe_knowledge_influence(
            &deployment.scope,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("lineage lost influence across epoch")?;
    assert!(inherited.externally_influenced);
    assert!(inherited.unknown);
    Ok(())
}
