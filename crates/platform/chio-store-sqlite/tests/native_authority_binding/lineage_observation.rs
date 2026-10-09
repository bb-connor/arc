//! A principal that already holds native flow state begins further lineages
//! through the kernel's own pre-evaluation refresh, keeping every label, while
//! rows that cannot exist without their exact isolation epoch still refuse.
use super::*;
use chio_security_types::ports::{
    FlowJoinRequest, FlowStateKey, FlowStateSnapshot, FlowStateStore, PortErrorKind, PortResult,
};
use chio_security_types::Compartment;

fn taint(name: &str) -> TestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        Default::default(),
        std::collections::BTreeSet::from([Compartment::new(name)?]),
    )?)
}

/// Joins principal and session taint on the first request, nothing after.
struct JoinHook {
    binding: NativeSecurityAuthorityBindingV1,
    first: String,
}

impl SecurityPreDispatchHook for JoinHook {
    fn name(&self) -> &str {
        "lineage-observation-join"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }

    fn prepare_native_admission(
        &self,
        input: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        let internal = |error: Box<dyn std::error::Error>| KernelError::Internal(error.to_string());
        let transition = RecordId::new(format!("lineage-join:{}", input.request.request_id))
            .map_err(|error| internal(error.into()))?;
        let (principal, session) = if input.request.request_id == self.first {
            (
                taint("principal-secret").map_err(internal)?,
                taint("session-secret").map_err(internal)?,
            )
        } else {
            (InformationLabel::bottom(), InformationLabel::bottom())
        };
        authority.join(transition, principal, InformationLabel::bottom(), session)?;
        Ok(())
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

fn context(principal: &str, lineage: &str) -> TestResult<SecurityInvocationContext> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            TenantId::new("native-tenant")?,
            SessionId::new("native-session")?,
            PrincipalId::new(principal)?,
            IsolationEpochId::new("native-epoch")?,
            LineageId::new(lineage)?,
            1,
        ),
    ))
}

#[test]
fn existing_principal_refreshes_a_second_lineage_through_the_kernel() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open()?;
    let selected = initialize(&fixture, &runtime, "lineage-source")?;
    let binding = selected.admission_binding()?;
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    // Every request carries a fresh capability: a new lineage root for the same agent.
    let requests = ["lineage-0", "lineage-1", "lineage-2"]
        .into_iter()
        .map(|id| fixture.request(&runtime, id))
        .collect::<TestResult<Vec<_>>>()?;
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique test kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(JoinHook {
        binding: binding.clone(),
        first: "lineage-0".into(),
    }));
    let principal = requests[0].agent_id.clone();
    let observe = |lineage: &str| -> TestResult<_> {
        let key = FlowStateKey {
            tenant_id: TenantId::new("native-tenant")?,
            principal_id: PrincipalId::new(principal.clone())?,
            lineage_id: LineageId::new(lineage)?,
            session_id: SessionId::new("native-session")?,
            isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
        };
        let reader: &dyn AdmissionOperationStore = &store;
        Ok(reader.observe_native_security_flow(&binding, &key, &fence, now_ms()?)?)
    };
    // Refresh then admit: the hook's join is recorded before the closed dispatch.
    let admit =
        |request: &chio_kernel::ToolCallRequest, id: &str| -> TestResult<(Option<u64>, u64)> {
            let mut request = request.clone();
            request.request_id = id.into();
            let refreshed = runtime
                .kernel
                .refresh_native_security_context(&context(&principal, &request.capability.id)?)?;
            let observed = refreshed.as_v1().flow_state_generation();
            let response = runtime
                .kernel
                .evaluate_tool_call_blocking_with_security_context(&request, &refreshed)?;
            assert_eq!(
                response.reason.as_deref(),
                Some("native security dispatch lifecycle is unsupported"),
                "{response:?}"
            );
            let after = observe(&request.capability.id)?
                .stored_context_generation()
                .ok_or("admission recorded no context")?;
            assert!(observed.is_none_or(|observed| after > observed));
            Ok((observed, after))
        };
    let secrets = [taint("principal-secret")?, taint("session-secret")?];
    let (observed, first) = admit(&requests[0], "lineage-0")?;
    assert_eq!(observed, None);
    let mut previous = first;
    for request in &requests[1..] {
        let lineage = request.capability.id.as_str();
        // The refresh reports no context for the exact new lineage.
        let (observed, generation) = admit(request, &format!("{lineage}-admission"))?;
        assert_eq!(observed, None);
        assert!(generation > previous);
        previous = generation;
        let joined = observe(lineage)?;
        let snapshot = joined.snapshot().ok_or("joined lineage snapshot")?;
        // Principal and session history carry over; nothing resets to bottom.
        for secret in &secrets {
            assert!(secret.flows_to(&snapshot.session_label));
        }
        assert!(secrets[0].flows_to(&snapshot.principal_label));
    }
    // The first lineage re-enters with its own context.
    let (observed, again) = admit(&requests[0], "lineage-0-again")?;
    assert_eq!(observed, Some(first));
    assert!(again > previous);
    Ok(())
}

fn key(lineage: &str, session: &str, epoch: &str) -> TestResult<FlowStateKey> {
    Ok(FlowStateKey {
        tenant_id: TenantId::new("tenant")?,
        principal_id: PrincipalId::new("principal")?,
        lineage_id: LineageId::new(lineage)?,
        session_id: SessionId::new(session)?,
        isolation_epoch_id: IsolationEpochId::new(epoch)?,
    })
}

fn join(
    store: &SqliteSecurityStateStore,
    key: &FlowStateKey,
    transition: &str,
    session: &InformationLabel,
) -> TestResult<FlowStateSnapshot> {
    Ok(FlowStateStore::join(
        store,
        &FlowJoinRequest {
            key: key.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: session.clone(),
            transition_id: RecordId::new(transition)?,
        },
    )?)
}

fn refused(result: PortResult<Option<FlowStateSnapshot>>) -> bool {
    result.is_err_and(|error| error.kind() == PortErrorKind::IntegrityFailure)
}

#[test]
fn session_from_another_lineage_keeps_its_taint_under_an_existing_epoch() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("security.db"))?;
    let only = taint("session-only")?;
    let bottom = InformationLabel::bottom();
    // Session "carried" holds taint its principal lacks, under lineage-0.
    join(
        &store,
        &key("lineage-0", "carried", "epoch")?,
        "join-0",
        &only,
    )?;
    // Another session opens lineage-1, so its exact epoch exists.
    join(
        &store,
        &key("lineage-1", "other", "epoch")?,
        "join-1",
        &bottom,
    )?;
    let carried = key("lineage-1", "carried", "epoch")?;
    let observed = FlowStateStore::load(&store, &carried)?.ok_or("inherited snapshot")?;
    assert!(only.flows_to(&observed.session_label));
    let result = join(&store, &carried, "join-2", &bottom)?;
    assert!(only.flows_to(&result.session_label));
    assert!(result.context_generation > observed.context_generation);
    Ok(())
}

#[test]
fn rows_without_their_isolation_epoch_are_still_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open(&path)?;
    join(
        &store,
        &key("lineage-0", "session", "epoch")?,
        "join-0",
        &InformationLabel::bottom(),
    )?;
    let raw = rusqlite::Connection::open(&path)?;
    // A context under a lineage whose exact epoch does not exist.
    raw.execute(
        "INSERT INTO security_flow_contexts
         (tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation)
         VALUES ('tenant', 'principal', 'lineage-orphan', 'session', 'epoch', 1)",
        [],
    )?;
    assert!(refused(FlowStateStore::load(
        &store,
        &key("lineage-orphan", "session", "epoch")?
    )));
    // A session and membership in an epoch with no epoch row under any lineage.
    raw.execute_batch(
        "INSERT INTO security_session_memberships
         (tenant_id, principal_id, session_id, isolation_epoch_id)
         VALUES ('tenant', 'principal', 'session', 'epoch-orphan');
         INSERT INTO security_session_flow_state
         (tenant_id, principal_id, session_id, isolation_epoch_id, label_json, label_hash, generation)
         SELECT tenant_id, principal_id, 'session', 'epoch-orphan', label_json, label_hash, generation
         FROM security_principal_flow_state WHERE isolation_epoch_id = 'epoch';",
    )?;
    assert!(refused(FlowStateStore::load(
        &store,
        &key("lineage-0", "session", "epoch-orphan")?
    )));
    // A principal label in an epoch with no epoch row under any lineage.
    raw.execute(
        "INSERT INTO security_principal_flow_state
         (tenant_id, principal_id, isolation_epoch_id, label_json, label_hash, generation)
         SELECT tenant_id, principal_id, 'epoch-unrooted', label_json, label_hash, generation
         FROM security_principal_flow_state WHERE isolation_epoch_id = 'epoch'",
        [],
    )?;
    assert!(refused(FlowStateStore::load(
        &store,
        &key("lineage-0", "nobody", "epoch-unrooted")?
    )));
    // A session whose every context is gone, seen from a new lineage.
    join(
        &store,
        &key("lineage-0", "stripped", "epoch")?,
        "join-stripped",
        &InformationLabel::bottom(),
    )?;
    raw.execute(
        "DELETE FROM security_flow_contexts WHERE session_id = 'stripped'",
        [],
    )?;
    assert!(refused(FlowStateStore::load(
        &store,
        &key("lineage-new", "stripped", "epoch")?
    )));
    // A membership without its session label.
    raw.execute(
        "INSERT INTO security_session_memberships
         (tenant_id, principal_id, session_id, isolation_epoch_id)
         VALUES ('tenant', 'principal', 'unlabelled', 'epoch')",
        [],
    )?;
    assert!(refused(FlowStateStore::load(
        &store,
        &key("lineage-1", "unlabelled", "epoch")?
    )));
    Ok(())
}

#[test]
fn missing_principal_label_under_an_existing_epoch_is_refused_by_the_legacy_reader() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open(&path)?;
    join(
        &store,
        &key("lineage-0", "session", "epoch")?,
        "join-0",
        &InformationLabel::bottom(),
    )?;
    rusqlite::Connection::open(&path)?.execute("DELETE FROM security_principal_flow_state", [])?;
    // The epoch and the session survive under lineage-0; the principal row does not.
    for session in ["session", "fresh"] {
        assert!(
            refused(FlowStateStore::load(
                &store,
                &key("lineage-1", session, "epoch")?
            )),
            "{session}"
        );
    }
    Ok(())
}

#[test]
fn missing_principal_label_edited_out_of_band_is_refused_by_the_serving_owner() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open()?;
    let selected = initialize(&fixture, &runtime, "missing-principal-source")?;
    let binding = selected.admission_binding()?;
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let request = fixture.request(&runtime, "missing-principal-0")?;
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique test kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(JoinHook {
        binding: binding.clone(),
        first: String::new(),
    }));
    let first = runtime
        .kernel
        .refresh_native_security_context(&context(&request.agent_id, &request.capability.id)?)?;
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &first)?;
    assert_eq!(
        response.reason.as_deref(),
        Some("native security dispatch lifecycle is unsupported"),
        "{response:?}"
    );
    {
        let raw = rusqlite::Connection::open(fixture.database())?;
        let triggers = raw
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger'
                 AND tbl_name = 'security_participant_state_principal_flow_state'
                 AND name GLOB '*_delete'",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for trigger in triggers {
            raw.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
        }
        raw.execute(
            "DELETE FROM security_participant_state_principal_flow_state WHERE principal_id = ?1",
            [request.agent_id.as_str()],
        )?;
    }
    let key = FlowStateKey {
        tenant_id: TenantId::new("native-tenant")?,
        principal_id: PrincipalId::new(request.agent_id.clone())?,
        lineage_id: LineageId::new("second-lineage-root")?,
        session_id: SessionId::new("native-session")?,
        isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
    };
    let reader: &dyn AdmissionOperationStore = &store;
    let refused = reader
        .observe_native_security_flow(&binding, &key, &fence, now_ms()?)
        .err()
        .ok_or("a missing principal label was observed as absent")?;
    // An out-of-band edit is refused before any flow read; the in-process
    // snapshot rule is covered by the library test of the same name.
    assert!(
        refused
            .to_string()
            .contains("authority database changed outside its serving-owner connection"),
        "{refused}"
    );
    Ok(())
}
