//! Influence inherits the same principal, lineage and session scopes as labels.
use super::*;

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
