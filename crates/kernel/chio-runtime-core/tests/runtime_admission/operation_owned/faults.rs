use super::*;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionOperationId, AdmissionOperationStore,
};
use chio_kernel::{KernelError, RuntimeAdmissionDecision, RuntimeParticipantClaimAuthority};

#[derive(Clone)]
pub(super) enum Fault {
    NoClaim,
    Deny,
    Panic,
    SecondClaim,
    SourceBarrier,
    Park(Arc<AtomicU64>),
}

pub(super) struct FaultHook {
    inner: ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>,
    source_path: std::path::PathBuf,
    fault: Fault,
}

impl FaultHook {
    pub(super) fn new(
        inner: ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>,
        source_path: std::path::PathBuf,
        fault: Fault,
    ) -> Self {
        Self {
            inner,
            source_path,
            fault,
        }
    }
}

impl RuntimeAdmissionHook for FaultHook {
    fn name(&self) -> &str {
        "owned-runtime-fault-test"
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn enforces_swarm_authority(&self) -> bool {
        self.inner.enforces_swarm_authority()
    }
    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if let Fault::Park(polls) = &self.fault {
            polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    }
    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        self.inner.runtime_participant_binding()
    }
    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("an owned profile must never fall back to legacy evaluation");
    }
    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        panic!("operation custody must never invoke legacy metadata release");
    }
    fn evaluate_operation_owned(
        &self,
        context: &RuntimeAdmissionContext<'_>,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        if matches!(self.fault, Fault::NoClaim) {
            return Ok(RuntimeAdmissionDecision::allow(None));
        }
        let decision = self.inner.evaluate_operation_owned(context, authority)?;
        assert!(
            decision.allowed,
            "fault must follow a real successful claim: {decision:?}"
        );
        match self.fault {
            Fault::NoClaim => unreachable!(),
            Fault::Deny => Ok(RuntimeAdmissionDecision::deny(
                "injected post-claim denial",
                None,
            )),
            Fault::Panic => panic!("injected verifier panic after confirmed claim"),
            Fault::SecondClaim => {
                assert!(authority
                    .claim(AdmissionDigest::try_new("plan", "e".repeat(64))?, vec![])
                    .is_err());
                Ok(decision)
            }
            Fault::SourceBarrier => {
                let raw = rusqlite::Connection::open(&self.source_path).map_err(|error| {
                    KernelError::Internal(format!("fixture source open: {error}"))
                })?;
                raw.execute_batch("DROP TRIGGER runtime_replay_source_lease_no_insert")
                    .map_err(|error| {
                        KernelError::Internal(format!("fixture barrier removal: {error}"))
                    })?;
                Ok(decision)
            }
            Fault::Park(_) => Ok(decision),
        }
    }
    fn revalidate_operation_owned_before_dispatch(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), KernelError> {
        self.inner
            .revalidate_operation_owned_before_dispatch(context, source)
    }
}

pub(super) fn history(
    fixture: &Fixture,
) -> TestResult<
    Vec<chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimHistoryV1>,
> {
    let raw = rusqlite::Connection::open(fixture._directory.path().join("authority.sqlite3"))?;
    let operation_id: String =
        raw.query_row("SELECT operation_id FROM admission_operations", [], |row| {
            row.get(0)
        })?;
    let (_, history) = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_history(
            &AdmissionOperationId::from_persisted(operation_id)?,
            &fixture.authority.mutation_fence(),
            NOW,
        )?
        .ok_or("operation history")?;
    Ok(history)
}

#[test]
fn owned_allow_without_claim_or_after_second_attempt_never_dispatches() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for fault in [Fault::NoClaim, Fault::SecondClaim] {
        let fixture = Fixture::new(true)?;
        let kernel = fixture.kernel(
            FaultHook {
                inner: fixture.hook()?,
                fault: fault.clone(),
                source_path: fixture._directory.path().join("runtime.sqlite3"),
            },
            true,
            false,
        )?;
        let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let history = history(&fixture)?;
        assert_eq!(
            history.len(),
            usize::from(matches!(fault, Fault::SecondClaim))
        );
        assert!(history.iter().all(
            |entry| entry.disposition == RuntimeParticipantDisposition::ReleasedBeforeDispatch
        ));
    }
    Ok(())
}

#[test]
fn owned_denial_panic_and_changed_source_release_exact_physical_claim() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for fault in [Fault::Deny, Fault::Panic, Fault::SourceBarrier] {
        let removes_barrier = matches!(fault, Fault::SourceBarrier);
        let fixture = Fixture::new(true)?;
        let kernel = fixture.kernel(
            FaultHook {
                inner: fixture.hook()?,
                fault,
                source_path: fixture._directory.path().join("runtime.sqlite3"),
            },
            true,
            false,
        )?;
        let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let history = history(&fixture)?;
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch
        );
        if removes_barrier {
            let raw =
                rusqlite::Connection::open(fixture._directory.path().join("runtime.sqlite3"))?;
            let count: i64 = raw.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'trigger' AND name = 'runtime_replay_source_lease_no_insert'",
                [], |row| row.get(0),
            )?;
            assert_eq!(
                count, 0,
                "the fixture must actually remove the source barrier"
            );
        }
        // A monotonic trust-floor update is not replay custody and is not rolled back.
        assert!(fixture
            .source
            .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
            .is_some());
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    }
    Ok(())
}

#[test]
fn real_trust_floor_write_failure_denies_and_releases_the_prior_claim() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let raw = rusqlite::Connection::open(fixture._directory.path().join("runtime.sqlite3"))?;
    raw.execute_batch("CREATE TRIGGER injected_floor_failure BEFORE INSERT ON runtime_trust_floors BEGIN SELECT RAISE(ABORT, 'injected trust floor write failure'); END;")?;
    let kernel = fixture.kernel(fixture.hook()?, true, false)?;
    let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let history = history(&fixture)?;
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    assert!(fixture
        .source
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .is_none());
    Ok(())
}

#[test]
fn dropping_an_owned_dispatch_before_readiness_releases_custody_and_budget() -> TestResult {
    use std::future::Future;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let polls = Arc::new(AtomicU64::new(0));
    let kernel = fixture.kernel(
        FaultHook {
            inner: fixture.hook()?,
            fault: Fault::Park(polls.clone()),
            source_path: fixture._directory.path().join("runtime.sqlite3"),
        },
        true,
        false,
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut invocation = Box::pin(kernel.evaluate_tool_call(&fixture.request));
            std::future::poll_fn(|cx| {
                let result = invocation.as_mut().poll(cx);
                assert!(
                    result.is_pending(),
                    "parked invocation unexpectedly finished: {result:?}"
                );
                if polls.load(Ordering::SeqCst) > 0 {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            drop(invocation);
        });
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let history = history(&fixture)?;
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    let store = fixture.authority.admission_operation_store();
    let operation =
        AdmissionOperationStore::load_by_operation_id(&store, history[0].reference.operation_id())?
            .ok_or("dropped operation")?;
    assert_eq!(
        operation.state(),
        chio_kernel::admission_operation::AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    Ok(())
}
