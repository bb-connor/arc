use super::*;
use chio_security_types::clock::{ClockError, ClockReading, FixedClock};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

struct AdvancingClock(AtomicU64);

impl Clock for AdvancingClock {
    fn read(&self) -> std::result::Result<ClockReading, ClockError> {
        FixedClock::new(self.0.load(Ordering::SeqCst)).read()
    }
}

struct ExpiringTool {
    clock: Arc<AdvancingClock>,
    return_at: u64,
    calls: Arc<AtomicUsize>,
    bad_output: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for ExpiringTool {
    fn server_id(&self) -> &str {
        "research"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["analyze".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.0.store(self.return_at, Ordering::SeqCst);
        Ok(json!({"count": if self.bad_output { 99 } else { 2 }}))
    }
}

#[test]
fn dispatch_expiry_during_execution_does_not_change_the_output_contract() -> Result {
    for bad_output in [false, true] {
        let dir = tempfile::tempdir()?;
        let store = DelegationStore::open(dir.path().join("allocation.db"))?;
        let start = now()?;
        let expires = start + 120;
        let mut contract = slot("leaf", 2, 60, 2)?;
        contract.contract.expires_at = expires;
        store.create_root(contract)?;
        let clock = Arc::new(AdvancingClock(AtomicU64::new(start)));
        let (mut kernel, _) = open_with_clock(dir.path(), 3, bad_output, Some(clock.clone()))?;
        let calls = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(ExpiringTool {
            clock: clock.clone(),
            return_at: expires + 1,
            calls: calls.clone(),
            bad_output,
        }));
        let mut call = request(&kernel, "leaf", 2, "expires-during-execution", 20)?;
        choose(&store, &call, 2, 3, 0, 20)?;
        seal(&store, &mut call, 20)?;
        clock.0.store(now()?, Ordering::SeqCst);
        let response = kernel.evaluate_tool_call_blocking(&call)?;
        assert_eq!(
            response.verdict,
            if bad_output {
                Verdict::Deny
            } else {
                Verdict::Allow
            }
        );
        assert_eq!(response.output.is_some(), !bad_output);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(kernel);
        let (kernel, replay_calls) = open_with_clock(dir.path(), 3, bad_output, Some(clock))?;
        let replay = kernel.evaluate_tool_call_blocking(&call)?;
        assert_eq!(
            serde_json::to_value(&replay.receipt)?,
            serde_json::to_value(&response.receipt)?
        );
        assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
        let rail = rusqlite::Connection::open(dir.path().join("bank.db"))?;
        let (count, state, charge): (i64, String, i64) =
            rail.query_row("SELECT COUNT(*),state,charged FROM holds", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        assert_eq!(count, 1);
        assert_eq!(state, if bad_output { "released" } else { "captured" });
        assert_eq!(charge, if bad_output { 0 } else { 20 });
    }
    Ok(())
}

#[test]
fn accepted_output_replays_after_dispatch_permit_expiry() -> Result {
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("allocation.db"))?;
    let start = now()?;
    let expires = start + 120;
    let mut contract = slot("leaf", 2, 60, 2)?;
    contract.contract.expires_at = expires;
    store.create_root(contract)?;
    let clock = Arc::new(AdvancingClock(AtomicU64::new(start)));
    let (kernel, calls) = open_with_clock(dir.path(), 3, false, Some(clock.clone()))?;
    let mut call = request(&kernel, "leaf", 2, "accepted-before-expiry", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    clock.0.store(now()?, Ordering::SeqCst);
    let response = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(kernel);
    clock.0.store(expires + 1, Ordering::SeqCst);
    let (kernel, replay_calls) = open_with_clock(dir.path(), 3, false, Some(clock))?;
    let replay = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(
        serde_json::to_value(&replay.receipt)?,
        serde_json::to_value(&response.receipt)?
    );
    assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

struct OrdinaryOutputGuard(Arc<AtomicBool>);

struct ExactOrdinaryOutputGuard(Arc<AtomicBool>);
impl Guard for ExactOrdinaryOutputGuard {
    fn name(&self) -> &str {
        "exact-ordinary-output-lifecycle"
    }
    fn evaluate(&self, _: &GuardContext<'_>) -> std::result::Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
    fn requires_exact_released_output(&self, _: &GuardContext<'_>) -> bool {
        true
    }
    fn validate_output_before_release(
        &self,
        ctx: &GuardContext<'_>,
        output: &ToolServerOutput,
    ) -> std::result::Result<(), KernelError> {
        OrdinaryOutputGuard(self.0.clone()).validate_output_before_release(ctx, output)
    }
}

struct PreserveOutput;
impl chio_kernel::post_invocation::PostInvocationHook for PreserveOutput {
    fn name(&self) -> &str {
        "preserve-output-lifecycle"
    }
    fn inspect(
        &self,
        _: &chio_kernel::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> chio_kernel::post_invocation::PostInvocationVerdict {
        chio_kernel::post_invocation::PostInvocationVerdict::Allow
    }
    fn durable_identity(
        &self,
    ) -> std::result::Result<Option<chio_kernel::post_invocation::PostInvocationHookIdentity>, String>
    {
        chio_kernel::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "preserve-output",
            "1",
            "identity",
            &json!({}),
        )
        .map(Some)
    }
}

impl Guard for OrdinaryOutputGuard {
    fn name(&self) -> &str {
        "ordinary-output-lifecycle"
    }
    fn evaluate(&self, _: &GuardContext<'_>) -> std::result::Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        _: &ToolServerOutput,
    ) -> std::result::Result<(), KernelError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KernelError::GuardDenied("ordinary output withheld".into()))
        }
    }
}

#[test]
fn ordinary_output_rejection_retains_exposure_without_wedging_restart() -> Result {
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("allocation.db"))?;
    store.create_root(slot("first", 2, 60, 2)?)?;
    store.create_root(slot("second", 2, 60, 2)?)?;
    let (mut kernel, calls) = open(dir.path(), 3, false)?;
    let allowed = Arc::new(AtomicBool::new(false));
    kernel.add_guard(Box::new(OrdinaryOutputGuard(allowed.clone())));
    let mut call = request(&kernel, "first", 2, "ordinary-denial", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    assert!(matches!(kernel.evaluate_tool_call_blocking(&call),
        Err(KernelError::GuardDenied(reason)) if reason.contains("ordinary output withheld")));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(kernel);

    let (kernel, new_calls) = open_configured(
        dir.path(),
        3,
        false,
        None,
        delegated_work::DelegatedWorkLayout::Arguments,
        |kernel| kernel.add_guard(Box::new(OrdinaryOutputGuard(allowed.clone()))),
    )
    .map_err(|error| format!("restart after ordinary rejection: {error}"))?;
    let replay = kernel
        .evaluate_tool_call_blocking(&call)
        .map_err(|error| format!("replay after ordinary rejection: {error}"))?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert_eq!(new_calls.load(Ordering::SeqCst), 0);
    allowed.store(true, Ordering::SeqCst);
    let mut next = request(&kernel, "second", 2, "after-ordinary-denial", 20)?;
    choose(&store, &next, 2, 3, 0, 20)?;
    seal(&store, &mut next, 20)?;
    let response = kernel.evaluate_tool_call_blocking(&next)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(new_calls.load(Ordering::SeqCst), 1);
    let rail = rusqlite::Connection::open(dir.path().join("bank.db"))?;
    let retained: i64 =
        rail.query_row("SELECT COUNT(*) FROM holds WHERE state='held'", [], |r| {
            r.get(0)
        })?;
    let captured: i64 = rail.query_row(
        "SELECT COUNT(*) FROM holds WHERE state='captured'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!((retained, captured), (1, 1));
    Ok(())
}

#[test]
fn post_transform_output_denial_does_not_block_unrelated_startup() -> Result {
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("allocation.db"))?;
    store.create_root(slot("first", 2, 60, 2)?)?;
    store.create_root(slot("second", 2, 60, 2)?)?;
    let allowed = Arc::new(AtomicBool::new(false));
    let configure = |kernel: &mut chio_kernel::ChioKernel| {
        kernel.add_guard(Box::new(ExactOrdinaryOutputGuard(allowed.clone())));
        kernel.add_post_invocation_hook(Box::new(PreserveOutput));
    };
    let (kernel, calls) = open_configured(
        dir.path(),
        3,
        false,
        None,
        delegated_work::DelegatedWorkLayout::Arguments,
        configure,
    )?;
    let mut call = request(&kernel, "first", 2, "exact-denial", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&call),
        Err(KernelError::GuardDenied(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(kernel);
    let (kernel, calls) = open_configured(
        dir.path(),
        3,
        false,
        None,
        delegated_work::DelegatedWorkLayout::Arguments,
        configure,
    )?;
    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&call),
        Err(KernelError::GuardDenied(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    allowed.store(true, Ordering::SeqCst);
    let mut next = request(&kernel, "second", 2, "after-exact-denial", 20)?;
    choose(&store, &next, 2, 3, 0, 20)?;
    seal(&store, &mut next, 20)?;
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&next)?.verdict,
        Verdict::Allow
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let rail = rusqlite::Connection::open(dir.path().join("bank.db"))?;
    let retained: i64 =
        rail.query_row("SELECT COUNT(*) FROM holds WHERE state='held'", [], |row| {
            row.get(0)
        })?;
    assert_eq!(retained, 1, "withheld output retained its original hold");
    Ok(())
}
