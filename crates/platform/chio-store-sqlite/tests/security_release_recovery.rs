//! Final security release must remain authoritative across durable replay.
#[path = "security_release_recovery/checkpoint_faults.rs"]
mod checkpoint_faults;
#[cfg(unix)]
#[path = "security_release_recovery/crash.rs"]
mod crash;
#[path = "security_release_recovery/integrity.rs"]
mod integrity;
#[path = "security_release_recovery/nested.rs"]
mod nested;
#[path = "security_release_recovery/output.rs"]
mod output;
#[path = "security_release_recovery/serialization.rs"]
mod serialization;
#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

use chio_kernel::{
    KernelError, SecurityDispatchOutcomeHandle, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchContext, SecurityPreDispatchHook,
    SecurityPreDispatchPolicy, SecurityRequestLifecyclePermit, ToolCallRequest, ToolCallResponse,
};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use support::*;

struct ReleaseHook {
    allowed: bool,
    releases: Arc<AtomicUsize>,
}

struct ReleasePermit {
    allowed: bool,
    releases: Arc<AtomicUsize>,
}

impl SecurityRequestLifecyclePermit for ReleasePermit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        if self.allowed {
            Ok(())
        } else {
            Err(KernelError::GuardDenied("release authority refused".into()))
        }
    }
}

impl SecurityPreDispatchHook for ReleaseHook {
    fn name(&self) -> &str {
        "durable-release-contract"
    }

    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(Some(Box::new(ReleasePermit {
            allowed: self.allowed,
            releases: self.releases.clone(),
        })))
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

fn open(fixture: &Fixture, hook: Arc<ReleaseHook>, reconcile: bool) -> TestResult<Runtime> {
    let mut runtime = fixture.open_with_reconcile(false)?;
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique fixture kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(hook);
    if reconcile {
        kernel.reconcile_durable_admission_startup()?;
    }
    Ok(runtime)
}

fn context(request: &ToolCallRequest) -> TestResult<SecurityInvocationContext> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            TenantId::new("release-tenant")?,
            SessionId::new("release-session")?,
            PrincipalId::new(request.agent_id.clone())?,
            IsolationEpochId::new("release-epoch")?,
            LineageId::new(request.capability.id.as_str())?,
            1,
        ),
    ))
}

fn assert_withheld(result: Result<ToolCallResponse, KernelError>) {
    assert!(
        matches!(
            result,
            Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
        ),
        "unreleased security authority must withhold output, got {result:?}"
    );
}

fn release_failure_replay(restart: bool) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let hook = Arc::new(ReleaseHook {
        allowed: false,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let mut runtime = open(&fixture, hook.clone(), true)?;
    let request = fixture.request(&runtime, "unreleased-durable-output")?;
    let security_context = context(&request)?;
    assert_withheld(
        runtime
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &security_context),
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    let original_operation = operation_state(&fixture, &request.request_id)?
        .ok_or("retained operation after release failure")?
        .0;
    assert_eq!(
        operation_state(&fixture, &request.request_id)?
            .ok_or("pending operation")?
            .1,
        "finalizing"
    );
    if restart {
        drop(runtime);
        runtime = open(&fixture, hook.clone(), false)?;
        assert!(matches!(
            runtime.kernel.reconcile_durable_admission_startup(),
            Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
        ));
    }
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(
        operation_state(&fixture, &request.request_id)?
            .ok_or("same retained operation")?
            .0,
        original_operation
    );
    assert_eq!(
        hook.releases.load(Ordering::SeqCst),
        1,
        "recovery must not consume a fresh owner"
    );
    if restart {
        assert!(
            replay.is_err(),
            "unresolved recovery must not publish serving readiness"
        );
    } else {
        assert_withheld(replay);
    }
    Ok(())
}

#[test]
fn final_release_failure_cannot_be_bypassed_by_terminal_retry() -> TestResult {
    release_failure_replay(false)
}

#[test]
fn final_release_failure_cannot_be_bypassed_after_restart() -> TestResult {
    release_failure_replay(true)
}

#[test]
fn successful_release_is_checkpointed_before_completion_and_replayed_after_restart() -> TestResult {
    use chio_kernel::tool_outcome::ToolOutcomeStore;
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let hook = Arc::new(ReleaseHook {
        allowed: true,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let runtime = open(&fixture, hook.clone(), true)?;
    let request = fixture.request(&runtime, "released-durable-output")?;
    let security_context = context(&request)?;
    let first = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context)?;
    assert_eq!(first.verdict, chio_kernel::Verdict::Allow);
    assert!(first.output.is_some());
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    let (operation, state) =
        operation_state(&fixture, &request.request_id)?.ok_or("completed operation")?;
    assert_eq!(state, "completed");
    let operation_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation)?;
    let checkpoint = runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation_id)?
        .ok_or("durable checkpoint")?;
    assert_eq!(checkpoint.operation_id(), &operation_id);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context)?;
    assert_eq!(replay.receipt.id, first.receipt.id);
    drop(runtime);
    let runtime = open(&fixture, hook.clone(), true)?;
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context)?;
    assert_eq!(replay.verdict, chio_kernel::Verdict::Allow);
    assert_eq!(replay.receipt.id, first.receipt.id);
    assert_eq!(
        runtime
            .authority
            .tool_outcome_store()
            .lookup_security_release(&operation_id)?,
        Some(checkpoint)
    );
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}
