use super::*;

pub(super) fn protected_counts(f: &RecoveryFixture) -> TestResult<(i64, i64)> {
    let connection = rusqlite::Connection::open(f.path.join("admission.db"))?;
    Ok(connection.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events),
                (SELECT count(*) FROM authority_global_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

pub(super) fn issue_semantic_maintenance_capability(
    f: &RecoveryFixture,
) -> TestResult<chio_core_types::capability::token::CapabilityToken> {
    let store = f.authority.admission_operation_store();
    let mut profile = f.kernel.recovery_deployment(&f.runtime.scope)?;
    let mut actors = profile.actors.as_slice().to_vec();
    let mut permissions = actors[0].permissions.as_slice().to_vec();
    permissions.push(RecoveryPermission::Maintain);
    permissions.sort();
    permissions.dedup();
    actors[0].permissions = BoundedList::new(permissions)?;
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    store.configure_recovery_deployment(&profile)?;
    let mut maintenance_scope = f.control.scope.clone();
    maintenance_scope.grants.push(ToolGrant {
        server_id: "chio.recovery".into(),
        tool_name: RecoveryPermission::Maintain.wire_name().into(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    });
    Ok(f.kernel
        .issue_capability(&f.control.subject, maintenance_scope, 600)?)
}

#[tokio::test]
async fn native_maintenance_recomputes_semantic_constraints_without_writes() -> TestResult {
    let f = native_fixture("read")?;
    let (runtime, request, p) = prepare(
        &f,
        "read-constraints",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let response = runtime
        .execute_step(&f.process, "root", "read-constraints", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let operation = OperationId::new(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("admission_operation"))
            .and_then(|metadata| metadata.get("operation_id"))
            .and_then(Value::as_str)
            .ok_or("constraint capture operation absent")?,
    )?;
    let expected = chio_semantic_contracts::resolve_semantic_constraints(
        p.invocation.action.registry,
        &p.deployment.body().routes.as_slice()[0],
        &p.package.body().operations.as_slice()[0],
        &p.invocation.action.destination,
        &p.invocation.action.source_label,
        &mut chio_semantic_contracts::VerificationBudget::new(4096)?,
    )?;
    // The ordinary semantic fixture grants Select, not maintenance. Install
    // the independent test maintainer assignment and issue its exact power.
    let store = f.authority.admission_operation_store();
    let maintenance = issue_semantic_maintenance_capability(&f)?;
    let before = protected_counts(&f)?;
    let first = runtime.read_constraints(&maintenance, &operation)?;
    let second = runtime.read_constraints(&maintenance, &operation)?;
    assert_eq!(first, expected);
    assert_eq!(
        chio_core::canonical_json_bytes(&first)?,
        chio_core::canonical_json_bytes(&second)?
    );
    assert_eq!(protected_counts(&f)?, before);

    let fence = f.authority.mutation_fence();
    let actor = f.kernel.authenticate_recovery_actor(
        &f.runtime.scope,
        &maintenance,
        RecoveryPermission::Maintain,
    )?;
    let mut profile = f.kernel.recovery_deployment(&f.runtime.scope)?;
    let original = profile.clone();
    let mut actors = profile.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    store.configure_recovery_deployment(&profile)?;
    let before = protected_counts(&f)?;
    assert!(store
        .read_semantic_constraints(&actor, &operation, &fence, now_ms()?)
        .is_err());
    assert_eq!(protected_counts(&f)?, before);
    store.configure_recovery_deployment(&original)?;
    assert_eq!(
        runtime.read_constraints(&maintenance, &operation)?,
        expected
    );
    let actor = f.kernel.authenticate_recovery_actor(
        &f.runtime.scope,
        &maintenance,
        RecoveryPermission::Maintain,
    )?;
    f.kernel.revoke_capability(&maintenance.id)?;
    let before = protected_counts(&f)?;
    assert!(store
        .read_semantic_constraints(&actor, &operation, &fence, now_ms()?)
        .is_err());
    assert_eq!(protected_counts(&f)?, before);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
