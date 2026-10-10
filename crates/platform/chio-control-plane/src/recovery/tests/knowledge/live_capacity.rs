//! Live publication capacity follows authenticated tenant ownership.
use super::*;

struct ScopedKnowledgeHost {
    runtime: NativeKnowledgeRuntime,
    broker: Arc<chio_process::ProcessArtifactBroker>,
    profile: NativeKnowledgeInstallationV1,
}

fn scoped_host(
    f: &KnowledgeFixture,
    tenant: &str,
    process_id: &str,
) -> TestResult<ScopedKnowledgeHost> {
    let process =
        f.f.process
            .clone()
            .with_security_profile(ProcessSecurityProfile {
                tenant_id: tenant.into(),
                isolation_epoch_id: "native-epoch".into(),
                generation: 1,
            })?;
    process.create_root(
        process_id,
        &f.f.seed.capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 32,
            state: Default::default(),
        },
    )?;
    let context = process.recovery_security_context(process_id)?;
    assert_eq!(context.as_v1().tenant_id().as_str(), tenant);
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    deployment.scope.tenant_id = RecoveryTenantId::new(tenant)?;
    deployment.scope.process_id = ProcessId::new(process_id)?;
    deployment.security_context = context.clone();
    // Every independent root is initialized through the real native source
    // import/hydrate protocol, so its producer context has actual flow rows.
    // Accounts must still aggregate same-tenant roots across native sources.
    let source_path = f.f.path.join(format!("source-{process_id}.db"));
    let source = SqliteSecurityStateStore::open(&source_path)?;
    source.seal_declassification_live_dispatch()?;
    source.join(&FlowJoinRequest {
        key: recovery_flow_key(&context),
        principal_join: InformationLabel::bottom(),
        lineage_join: InformationLabel::bottom(),
        session_join: InformationLabel::bottom(),
        transition_id: RecordId::new("separate-tenant-initial-source")?,
    })?;
    drop(source);
    let source = SqliteSecurityParticipantSource::open(source_path)?;
    let authority = AdmissionIdentifier::try_new("authority", format!("source-{process_id}"))?;
    let time = now_ms()?;
    let expectation =
        store.expect_security_participant_source(&authority, &authority, &source, &fence, time)?;
    store.import_security_participant_source(
        &authority,
        expectation.expectation_id(),
        &source,
        &fence,
        time,
    )?;
    deployment.native_authority = store
        .hydrate_security_participant_state(&authority, expectation.expectation_id(), &fence, time)?
        .admission_binding()?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    // Each imported authority is selected by a real kernel with the same
    // serving store. Reusing kernelA would fail its native binding check before
    // these tests could exercise tenant publication accounting.
    let (mut kernel, _) = open_kernel(&f.f.path, &f.f.authority, &Keypair::from_seed(&[140; 32]))?;
    kernel.register_tool_server(Box::new(PersistentEffectServer::new(
        f.f.path.join("effects.db"),
        f.f.effects.clone(),
        f.f.behavior.clone(),
        f.f.started.clone(),
        f.f.release.clone(),
    )?));
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    let flow = Arc::new(
        NativeFlowResolver::new(
            deployment.native_authority.clone(),
            declassification_registry(&deployment.purpose),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            FlowResolverConfig::new(
                restricted_label(),
                category_labels(),
                BTreeMap::from([(
                    RecordId::new("aggregate")?,
                    deployment.aggregate_issuer.clone(),
                )]),
                60_000,
            )?,
        )?
        .with_captured_lifecycle(),
    );
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(flow);
    kernel.reconcile_durable_admission_startup()?;
    let kernel = Arc::new(kernel);
    let process = ProcessRuntime::open(f.f.path.join("process.db"), kernel.clone())?
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: tenant.into(),
            isolation_epoch_id: "native-epoch".into(),
            generation: 1,
        })?;
    assert_eq!(
        kernel
            .recovery_deployment(&deployment.scope)?
            .native_authority,
        deployment.native_authority
    );
    let mut profile = f.profile.clone();
    profile.scope = deployment.scope.clone();
    profile.native_authority = deployment.native_authority;
    profile.producer_context = context.clone();
    let mut entry = profile.recipients.as_slice()[0].clone();
    entry.recipient.scope = profile.scope.clone();
    entry.recipient.runtime = ProtectedText::new(process.runtime_id())?;
    entry.recipient.principal = context.as_v1().principal_id().clone();
    entry.recipient.lineage = IsolationLineageId::new(context.as_v1().lineage_root_id().as_str())?;
    entry.recipient.isolation_epoch =
        ProtectedText::new(context.as_v1().isolation_epoch_id().as_str())?;
    entry.recipient.context_generation = SafeInteger::new(context.as_v1().context_generation())?;
    entry.context = context;
    profile.recipients = NonEmptyBoundedList::new(vec![entry])?;
    profile.generation = SafeInteger::new(1)?;
    let broker = Arc::new(process.enable_durable_knowledge()?);
    store.configure_knowledge(&profile).map_err(|error| {
        format!("configuring native knowledge account {tenant}/{process_id}: {error}")
    })?;
    let runtime = NativeKnowledgeRuntime::new(
        kernel.clone(),
        Arc::new(store),
        broker.clone(),
        profile.clone(),
        fence,
    )?;
    let actor = kernel.authenticate_recovery_actor(
        &profile.scope,
        &f.f.control,
        RecoveryPermission::KnowledgeRead,
    )?;
    let current =
        f.f.authority
            .admission_operation_store()
            .knowledge_installation(&actor, &f.f.authority.mutation_fence(), now_ms()?)?;
    assert_eq!(current.scope, profile.scope);
    broker.validate_process(&profile.scope.process_id, &profile.producer_context)?;
    Ok(ScopedKnowledgeHost {
        runtime,
        broker,
        profile,
    })
}

#[test]
fn artifacts_live_capacity_is_shared_by_native_processes_of_one_tenant() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let other = scoped_host(
        &f,
        f.profile.scope.tenant_id.as_str(),
        "same-tenant-second-root",
    )?;
    let mut first = None;
    for ordinal in 0..256 {
        let bytes = format!("first-root-{ordinal}");
        let reference = f.publish(&format!("first-live-{ordinal}"), bytes.as_bytes())?;
        if first.is_none() {
            first = Some(reference);
        }
        let bytes = format!("second-root-{ordinal}");
        let input = f.input(&format!("second-live-{ordinal}"), bytes.as_bytes())?;
        other
            .runtime
            .publish(&f.f.control, &input, bytes.as_bytes(), None)?;
    }
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        256
    );
    assert_eq!(
        other
            .broker
            .storage_usage(&other.profile.scope.process_id)?
            .tree_blobs,
        256
    );
    let input = f.input("same-tenant-overflow", b"not-accepted")?;
    assert!(
        other
            .runtime
            .publish(&f.f.control, &input, b"not-accepted", None)
            .is_err(),
        "process IDs must not multiply the tenant's512-live-publication limit"
    );
    let reference = first.ok_or("first publication missing")?;
    f.runtime.collect(&f.f.control, &reference)?;
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        255,
        "this retirement must actually collect its independent immutable object"
    );
    let accepted = other
        .runtime
        .publish(&f.f.control, &input, b"not-accepted", None)
        .map_err(|error| {
            format!("same-tenant publication after exact sibling collection: {error}")
        })?;
    assert_eq!(accepted.scope, other.profile.scope);
    assert_eq!(
        other
            .broker
            .storage_usage(&other.profile.scope.process_id)?
            .tree_blobs,
        257
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn artifacts_foreign_tenant_live_capacity_does_not_close_native_intake() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let other = scoped_host(&f, "independent-knowledge-tenant", "foreign-tenant-root")?;
    let observed =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &other.profile.native_authority,
                &recovery_flow_key(&other.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    let before = observed.snapshot().ok_or("foreign native flow absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    assert_eq!(
        other
            .broker
            .storage_usage(&other.profile.scope.process_id)?
            .tree_blobs,
        0
    );
    for ordinal in 0..512 {
        let bytes = format!("first-tenant-live-{ordinal}");
        f.publish(&format!("full-first-tenant-{ordinal}"), bytes.as_bytes())?;
    }
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        512
    );
    let input = f.input(
        "foreign-tenant-independent-publication",
        b"separate-tenant-content",
    )?;
    let reference = other
        .runtime
        .publish(&f.f.control, &input, b"separate-tenant-content", None)
        .map_err(|error| {
            format!("foreign tenant native publication while first tenant is full: {error}")
        })?;
    assert_eq!(reference.scope, other.profile.scope);
    assert_eq!(
        other
            .broker
            .storage_usage(&other.profile.scope.process_id)?
            .tree_blobs,
        1
    );
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_blobs,
        512
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn knowledge_account_initialization_rolls_back_and_reconfiguration_preserves_custody() -> TestResult
{
    let f = KnowledgeFixture::from_before_activation(
        RecoveryFixture::new(false)?,
        |host, profile, _| {
            let connection = rusqlite::Connection::open(host.path.join("admission.db"))?;
            let before: i64 = connection.query_row(
                "SELECT count(*) FROM authority_global_commits",
                [],
                |row| row.get(0),
            )?;
            let store = host.authority.admission_operation_store();
            store.set_knowledge_account_completion_failure_for_test(true)?;
            let failure = store.configure_knowledge(profile);
            store.set_knowledge_account_completion_failure_for_test(false)?;
            let error = failure.err().ok_or("account writer missed its cut point")?;
            assert!(
                error
                    .to_string()
                    .contains("account initialization interrupted"),
                "wrong refusal: {error}"
            );
            let after: i64 = connection.query_row(
                "SELECT count(*) FROM authority_global_commits",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                after, before,
                "partial account initialization committed custody"
            );
            let remaining: i64 = connection.query_row(
                "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-*'", [], |row| row.get(0),
            )?;
            assert_eq!(remaining, 0);
            Ok(())
        },
    )?;
    let reference = f.publish("account-owned-artifact", b"retained account bytes")?;
    let store = f.f.authority.admission_operation_store();
    // Publication capacity observation is retained administration: it reads
    // the closed tenant counters without supplying any collection grant.
    assert!(store
        .inspect_live_publication_count(
            &f.actor(RecoveryPermission::KnowledgeRead)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    let actor = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let fence = f.f.authority.mutation_fence();
    assert_eq!(
        store.inspect_live_publication_count(&actor, &fence, now_ms()?)?,
        1
    );
    store.configure_knowledge(&f.profile)?;
    let mut next = f.profile.clone();
    next.generation = SafeInteger::new(2)?;
    store.configure_knowledge(&next)?;
    assert_eq!(
        store.inspect_live_publication_count(&actor, &fence, now_ms()?)?,
        1
    );
    let next_runtime = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(store.clone()),
        f.broker.clone(),
        next,
        fence.clone(),
    )?;
    next_runtime.collect(&f.f.control, &reference)?;
    assert_eq!(
        store.inspect_live_publication_count(&actor, &fence, now_ms()?)?,
        0
    );
    Ok(())
}

#[test]
fn knowledge_account_installation_refuses_missing_custody_without_resetting() -> TestResult {
    for pattern in [
        "knowledge-reference-ready:*",
        "knowledge-reference-capacity:*",
        "knowledge-publication-ready:*",
        "knowledge-publication-capacity:*",
        "knowledge-profile:*",
    ] {
        let f = KnowledgeFixture::new()?;
        f.publish("retained-owner", b"must not disappear from accounting")?;
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='admission_operation_recovery_no_delete'", [], |row| row.get(0),
        )?;
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF; DROP TRIGGER admission_operation_recovery_no_delete",
        )?;
        assert_eq!(
            connection.execute(
                "DELETE FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
                [pattern],
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
        let before: i64 =
            connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
                row.get(0)
            })?;
        let store = f.f.authority.admission_operation_store();
        assert!(
            store.configure_knowledge(&f.profile).is_err(),
            "reinitialized {pattern}"
        );
        let after: i64 =
            connection.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
                row.get(0)
            })?;
        assert_eq!(after, before, "refusal changed custody for {pattern}");
        let restored: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
            [pattern],
            |row| row.get(0),
        )?;
        assert_eq!(restored, 0, "refusal restored a lost {pattern}");
    }
    Ok(())
}

#[test]
fn knowledge_account_joins_same_tenant_and_initializes_foreign_tenant_independently() -> TestResult
{
    let f = KnowledgeFixture::new()?;
    f.publish("initial-account-owner", b"first")
        .map_err(|error| format!("publishing the initial account artifact: {error:?}"))?;
    let sibling = scoped_host(&f, f.profile.scope.tenant_id.as_str(), "account-sibling")
        .map_err(|error| format!("opening the sibling account: {error:?}"))?;
    let foreign = scoped_host(&f, "separate-account-tenant", "account-foreign")
        .map_err(|error| format!("opening the foreign account: {error:?}"))?;
    let store = f.f.authority.admission_operation_store();
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let rows: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-reference-ready:*'", [], |row| row.get(0),
    )?;
    assert_eq!(rows, 2, "process creation multiplied tenant accounts");
    for profile in [&sibling.profile, &foreign.profile] {
        store.configure_knowledge(profile)?;
    }
    // The shared runtime enforcement marker keeps one immutable identity:
    // neither the same-tenant sibling nor the separately authorized foreign
    // tenant rewrites its original custody while registering.
    let (markers, marker_version): (i64, i64) = connection.query_row(
        "SELECT count(*), max(version) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-runtime:*'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        (markers, marker_version),
        (1, 1),
        "the runtime enforcement marker must retain its single original custody"
    );
    // Both hosts stay readable through their real public runtime operations.
    for host in [&sibling, &foreign] {
        let input = f.input("account-join-readable", b"readable")?;
        let reference = host
            .runtime
            .publish(&f.f.control, &input, b"readable", None)?;
        let handle = host.runtime.handle(
            &f.f.control,
            &reference,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        let prepared = host
            .runtime
            .prepare_read(&f.f.control, &handle)
            .map_err(|error| format!("reading back the joined account artifact: {error:?}"))?;
        drop(prepared);
    }
    assert_eq!(
        store.inspect_live_publication_count(
            &f.actor(RecoveryPermission::KnowledgeAdmin)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?,
        1
    );
    Ok(())
}
