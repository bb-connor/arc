//! Pre-dispatch exit table. Each row pins the response and the store state one
//! pre-dispatch exit leaves behind. A future dropped at a pre-dispatch await
//! must leave the same store state as the early return at that await.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RUNTIME_DENIAL: &str = "runtime admission refused the exit-table call";
const REVALIDATION_DENIAL: &str = "runtime state changed before the exit-table dispatch";
const REVALIDATION_DENIAL_REASON: &str =
    "guard denied the request: runtime state changed before the exit-table dispatch";
const GUARD_DENIAL_REASON: &str =
    "guard denied the request: guard \"exit-table-deny\" denied the request";
const READINESS_TIMEOUT: &str = "runtime admission readiness timed out after 20ms";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Root,
    Nested,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exit {
    GuardDenied,
    DroppedAtGuard,
    RuntimeDenied,
    ReadinessTimedOut,
    DroppedAtReadiness,
    RevalidationDenied,
    LeaseDenied,
}

impl Exit {
    fn drops(self) -> bool {
        matches!(self, Self::DroppedAtGuard | Self::DroppedAtReadiness)
    }

    fn hook_step(self) -> HookStep {
        match self {
            Self::GuardDenied | Self::DroppedAtGuard | Self::LeaseDenied => HookStep::Allow,
            Self::RuntimeDenied => HookStep::DenyAdmission,
            Self::ReadinessTimedOut | Self::DroppedAtReadiness => HookStep::ParkReadiness,
            Self::RevalidationDenied => HookStep::DenyRevalidation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookStep {
    Allow,
    DenyAdmission,
    ParkReadiness,
    DenyRevalidation,
}

struct ExitTableHook {
    step: HookStep,
    parked: Arc<tokio::sync::Notify>,
    releases: Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for ExitTableHook {
    fn name(&self) -> &str {
        "pre-dispatch-exit-table"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let metadata = Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "adm-exit-table",
                "accepted": true,
                "reserved_destructive_lease_id": "lease-exit-table",
                "failure_code": null
            }
        }));
        Ok(if self.step == HookStep::DenyAdmission {
            RuntimeAdmissionDecision::deny(RUNTIME_DENIAL, metadata)
        } else {
            RuntimeAdmissionDecision::allow(metadata)
        })
    }

    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if self.step == HookStep::ParkReadiness {
            self.parked.notify_one();
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        self.step == HookStep::DenyRevalidation
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        if self.step == HookStep::DenyRevalidation {
            return Err(KernelError::GuardDenied(REVALIDATION_DENIAL.to_owned()));
        }
        Ok(())
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct DenyEveryCall;

impl Guard for DenyEveryCall {
    fn name(&self) -> &str {
        "exit-table-deny"
    }

    fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::deny(Vec::new()))
    }
}

/// Holds its blocking guard thread until the test releases it, so the
/// evaluation future is parked at the guard await when it is dropped.
struct ParkingGuard {
    parked: Arc<tokio::sync::Notify>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Guard for ParkingGuard {
    fn name(&self) -> &str {
        "exit-table-parking"
    }

    fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.parked.notify_one();
        let release = self
            .release
            .lock()
            .map_err(|_| KernelError::Internal("exit-table guard lock poisoned".into()))?;
        let _ = release.recv_timeout(Duration::from_secs(10));
        Ok(GuardDecision::allow())
    }
}

/// Everything a row needs besides its kernel: the parking signal, the guard
/// release, and the runtime release counter.
struct RowControl {
    parked: Arc<tokio::sync::Notify>,
    release_guard: Option<std::sync::mpsc::Sender<()>>,
    releases: Arc<AtomicU64>,
}

fn install_exit(kernel: &mut ChioKernel, exit: Exit) -> TestResult<RowControl> {
    let parked = Arc::new(tokio::sync::Notify::new());
    let releases = Arc::new(AtomicU64::new(0));
    let mut release_guard = None;
    match exit {
        Exit::GuardDenied => kernel.add_guard(Box::new(DenyEveryCall)),
        Exit::DroppedAtGuard => {
            let (sender, receiver) = std::sync::mpsc::channel();
            kernel.config.deadlines.always_offload_guards = true;
            kernel.add_guard(Box::new(ParkingGuard {
                parked: parked.clone(),
                release: Mutex::new(receiver),
            }));
            release_guard = Some(sender);
        }
        Exit::ReadinessTimedOut => {
            kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(20))?;
        }
        Exit::RuntimeDenied
        | Exit::DroppedAtReadiness
        | Exit::RevalidationDenied
        | Exit::LeaseDenied => {}
    }
    kernel.set_runtime_admission_hook(Arc::new(ExitTableHook {
        step: exit.hook_step(),
        parked: parked.clone(),
        releases: releases.clone(),
    }));
    Ok(RowControl {
        parked,
        release_guard,
        releases,
    })
}

/// Run one evaluation to its response, or drop it once it parks at the
/// row's pre-dispatch await. `None` means the future was dropped.
async fn drive(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    path: Path,
    exit: Exit,
    control: &RowControl,
) -> TestResult<Option<ToolCallResponse>> {
    let mut client = NoopNestedFlowClient;
    let parent = match path {
        Path::Root => None,
        Path::Nested => {
            let session = kernel.open_session(request.agent_id.clone(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent = make_operation_context(&session, "exit-table-parent", &request.agent_id);
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            Some(parent)
        }
    };
    let mut evaluation: Pin<Box<dyn std::future::Future<Output = _> + '_>> = match &parent {
        None => Box::pin(kernel.evaluate_tool_call(request)),
        Some(parent) => Box::pin(kernel.evaluate_tool_call_with_nested_flow_client_async(
            parent,
            request,
            &mut client,
            None,
        )),
    };
    if !exit.drops() {
        return Ok(Some(evaluation.await?));
    }
    tokio::select! {
        biased;
        result = &mut evaluation => {
            return Err(format!("{exit:?} evaluation finished before parking: {result:?}").into());
        }
        () = control.parked.notified() => {}
    }
    drop(evaluation);
    Ok(None)
}

/// Store state a durable pre-dispatch exit leaves behind.
#[derive(Debug, PartialEq, Eq)]
struct DurableStore {
    operation: AdmissionOperationState,
    open_holds: usize,
    runtime_releases: u64,
    tool_invocations: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct DurableRow {
    response: Option<(Verdict, String)>,
    store: DurableStore,
}

fn response_summary(response: Option<ToolCallResponse>) -> TestResult<Option<(Verdict, String)>> {
    response
        .map(|response| {
            if !response.receipt.verify_signature()? {
                return Err("exit-table receipt signature did not verify".into());
            }
            Ok((response.verdict, response.reason.unwrap_or_default()))
        })
        .transpose()
}

async fn run_durable_row(path: Path, exit: Exit) -> TestResult<DurableRow> {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(4);
    let (mut kernel, request, store, invocations) =
        durable_admission::durable_admission_fixture_with_grants(
            &format!("exit-table-durable-{path:?}-{exit:?}"),
            vec![grant],
        );
    let control = install_exit(&mut kernel, exit)?;
    let response = drive(&kernel, &request, path, exit, &control).await?;
    let row = DurableRow {
        response: response_summary(response)?,
        store: DurableStore {
            operation: store.operation().state(),
            open_holds: store.budget_store().count_open_holds()?,
            runtime_releases: control.releases.load(Ordering::SeqCst),
            tool_invocations: invocations.load(Ordering::SeqCst),
        },
    };
    if let Some(release) = control.release_guard.as_ref() {
        let _ = release.send(());
    }
    Ok(row)
}

fn compensated(runtime_releases: u64) -> DurableStore {
    DurableStore {
        operation: AdmissionOperationState::CompensatedBeforeDispatch,
        open_holds: 0,
        runtime_releases,
        tool_invocations: 0,
    }
}

fn denied(reason: &str) -> Option<(Verdict, String)> {
    Some((Verdict::Deny, reason.to_owned()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_pre_dispatch_exits_leave_their_recorded_store_state() -> TestResult {
    for path in [Path::Root, Path::Nested] {
        let table = [
            (
                Exit::GuardDenied,
                DurableRow {
                    response: denied(GUARD_DENIAL_REASON),
                    store: compensated(0),
                },
            ),
            (
                Exit::DroppedAtGuard,
                DurableRow {
                    response: None,
                    store: compensated(0),
                },
            ),
            (
                Exit::RuntimeDenied,
                DurableRow {
                    response: denied(RUNTIME_DENIAL),
                    store: compensated(1),
                },
            ),
            (
                Exit::ReadinessTimedOut,
                DurableRow {
                    response: denied(READINESS_TIMEOUT),
                    store: compensated(1),
                },
            ),
            (
                Exit::DroppedAtReadiness,
                DurableRow {
                    response: None,
                    store: compensated(1),
                },
            ),
            (
                Exit::RevalidationDenied,
                DurableRow {
                    response: denied(REVALIDATION_DENIAL_REASON),
                    store: compensated(1),
                },
            ),
        ];
        for (exit, expected) in table {
            let row = run_durable_row(path, exit).await?;
            assert_eq!(row, expected, "{path:?} {exit:?}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_durable_future_dropped_at_a_pre_dispatch_await_compensates_like_its_early_return(
) -> TestResult {
    for path in [Path::Root, Path::Nested] {
        for (dropped, returned) in [
            (Exit::DroppedAtGuard, Exit::GuardDenied),
            (Exit::DroppedAtReadiness, Exit::ReadinessTimedOut),
        ] {
            let dropped_row = run_durable_row(path, dropped).await?;
            let returned_row = run_durable_row(path, returned).await?;
            assert_eq!(dropped_row.response, None, "{path:?} {dropped:?}");
            assert!(returned_row.response.is_some(), "{path:?} {returned:?}");
            assert_eq!(
                dropped_row.store, returned_row.store,
                "{path:?} {dropped:?}"
            );
        }
    }
    Ok(())
}

/// Store state an ephemeral pre-dispatch exit leaves behind: the invocation
/// slot, the sibling-share lease and the runtime reservation.
#[derive(Debug, PartialEq, Eq)]
struct EphemeralStore {
    invocations_used: u32,
    sibling_share_released: bool,
    runtime_releases: u64,
    receipts: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct EphemeralRow {
    response: Option<(Verdict, String)>,
    store: EphemeralStore,
}

async fn run_ephemeral_row(path: Path, exit: Exit) -> TestResult<EphemeralRow> {
    let SiblingSumInvocationFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path: _path,
    } = make_sibling_sum_invocation_fixture(&format!("exit-table-ephemeral-{path:?}-{exit:?}"));
    let control = install_exit(&mut kernel, exit)?;
    // The lease row evaluates the second sibling while the first holds its
    // share, so its sibling-sum admission fails after the budget mutation.
    let (evaluated, evaluated_kp) = if exit == Exit::LeaseDenied {
        kernel
            .admit_capability_budget(&child_a)
            .map_err(std::io::Error::other)?;
        (&child_b, &child_b_kp)
    } else {
        (&child_a, &child_a_kp)
    };
    let mut request = make_request("exit-table-ephemeral", evaluated, "compute", "limited-srv");
    request.agent_id = evaluated_kp.public_key().to_hex();
    let receipts_before = kernel.receipt_log().len();
    let response = drive(&kernel, &request, path, exit, &control).await?;
    let receipts = kernel.receipt_log().len() - receipts_before;
    let invocations_used = kernel
        .with_budget_store(|store| Ok(store.get_usage(&evaluated.id, 0)?))?
        .map_or(0, |usage| usage.invocation_count);
    let row = EphemeralRow {
        response: response_summary(response)?,
        store: EphemeralStore {
            invocations_used,
            sibling_share_released: kernel.admit_capability_budget(&child_b).is_ok(),
            runtime_releases: control.releases.load(Ordering::SeqCst),
            receipts,
        },
    };
    if let Some(release) = control.release_guard.as_ref() {
        let _ = release.send(());
    }
    Ok(row)
}

fn released(receipts: usize) -> EphemeralStore {
    EphemeralStore {
        invocations_used: 0,
        sibling_share_released: true,
        runtime_releases: 1,
        receipts,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_pre_dispatch_exits_release_slot_lease_and_runtime_hold() -> TestResult {
    for path in [Path::Root, Path::Nested] {
        let table = [
            (
                Exit::ReadinessTimedOut,
                EphemeralRow {
                    response: denied(READINESS_TIMEOUT),
                    store: released(1),
                },
            ),
            (
                Exit::DroppedAtReadiness,
                EphemeralRow {
                    response: None,
                    store: released(0),
                },
            ),
            (
                Exit::RevalidationDenied,
                EphemeralRow {
                    response: denied(REVALIDATION_DENIAL_REASON),
                    store: released(1),
                },
            ),
            (
                // The failed admission acquired no lease, so cleanup must not
                // release the share the other sibling still holds.
                Exit::LeaseDenied,
                EphemeralRow {
                    response: denied(&format!(
                        "sibling-sum budget admission failed: child \
                         cap-exit-table-ephemeral-{path:?}-LeaseDenied-child-b share 4000 bps \
                         + sibling sum 4000 bps > parent share 5000 bps"
                    )),
                    store: EphemeralStore {
                        sibling_share_released: false,
                        ..released(1)
                    },
                },
            ),
        ];
        for (exit, expected) in table {
            let row = run_ephemeral_row(path, exit).await?;
            assert_eq!(row, expected, "{path:?} {exit:?}");
        }
    }
    Ok(())
}

/// The strict-nonce reserve-for-caller preflight has its own readiness await.
async fn run_preflight_row(exit: Exit) -> TestResult<EphemeralRow> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
    let control = install_exit(&mut kernel, exit)?;
    let agent = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(4);
    let cap = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request("exit-table-preflight", &cap, "read_file", "srv-a");
    let receipts_before = kernel.receipt_log().len();
    let mut evaluation = Box::pin(kernel.authorize_tool_call_reserving(&request));
    let response = if exit.drops() {
        tokio::select! {
            biased;
            result = &mut evaluation => {
                return Err(format!("{exit:?} preflight finished before parking: {result:?}").into());
            }
            () = control.parked.notified() => {}
        }
        drop(evaluation);
        None
    } else {
        Some(evaluation.await?)
    };
    let receipts = kernel.receipt_log().len() - receipts_before;
    let invocations_used = kernel
        .with_budget_store(|store| Ok(store.get_usage(&cap.id, 0)?))?
        .map_or(0, |usage| usage.invocation_count);
    Ok(EphemeralRow {
        response: response_summary(response)?,
        store: EphemeralStore {
            invocations_used,
            sibling_share_released: true,
            runtime_releases: control.releases.load(Ordering::SeqCst),
            receipts,
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserve_for_caller_preflight_drop_compensates_like_its_readiness_exit() -> TestResult {
    let returned = run_preflight_row(Exit::ReadinessTimedOut).await?;
    assert_eq!(
        returned,
        EphemeralRow {
            response: denied(READINESS_TIMEOUT),
            store: released(1),
        }
    );
    let dropped = run_preflight_row(Exit::DroppedAtReadiness).await?;
    assert_eq!(
        dropped,
        EphemeralRow {
            response: None,
            store: released(0),
        }
    );
    Ok(())
}
