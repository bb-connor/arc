//! A live release owner must be able to enter the same fenced mutation domain.
use super::*;
use chio_kernel::admission_operation::AdmissionMutationSequencer;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use std::sync::mpsc;
use std::time::Duration;

type ReleaseAction = Arc<dyn Fn() -> Result<(), KernelError> + Send + Sync>;

struct Hook(ReleaseAction);
struct Permit(ReleaseAction);

impl SecurityRequestLifecyclePermit for Permit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        (self.0)()
    }
}

impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        "sequenced-release"
    }

    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(Some(Box::new(Permit(self.0.clone()))))
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

fn run_sequence(nested: bool, asynchronous: bool) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open_with_reconcile(false)?;
    let sequencer = AdmissionMutationSequencer::for_fence(&runtime.authority.mutation_fence())?;
    // A worker makes the regression bounded even when finalization incorrectly
    // holds this lock. Join it after evaluation, on both the red and green path.
    let (started, waiting) = mpsc::channel();
    let (acquired, done) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || -> Result<(), String> {
        waiting
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| error.to_string())?;
        let guard = sequencer.lock().map_err(|error| error.to_string())?;
        drop(guard);
        let _ = acquired.send(());
        Ok(())
    });
    let done = std::sync::Mutex::new(done);
    let releases = Arc::new(AtomicUsize::new(0));
    let release_count = releases.clone();
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook(Arc::new(move || {
        release_count.fetch_add(1, Ordering::SeqCst);
        started
            .send(())
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        done.lock()
            .map_err(|_| KernelError::Internal("lock probe poisoned".into()))?
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| KernelError::Internal("release was called under mutation lock".into()))
    }))));
    kernel.reconcile_durable_admission_startup()?;
    let request = fixture.request(&runtime, "sequenced-security-release")?;
    let security_context = context(&request)?;
    let result = evaluate(
        &mut runtime,
        &request,
        &security_context,
        nested,
        asynchronous,
    );
    worker.join().map_err(|_| "lock probe panicked")??;
    let response = result??;
    assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
    assert!(response.output.is_some());
    assert!(response.receipt.verify_signature()?);
    let (operation, state) =
        operation_state(&fixture, &request.request_id)?.ok_or("completed operation")?;
    assert_eq!(state, "completed");
    let operation =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation)?;
    assert!(runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .is_some());
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}

pub(super) fn evaluate(
    runtime: &mut Runtime,
    request: &ToolCallRequest,
    security_context: &SecurityInvocationContext,
    nested: bool,
    asynchronous: bool,
) -> TestResult<Result<ToolCallResponse, KernelError>> {
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if !nested {
        return Ok(if asynchronous {
            executor.block_on(
                runtime
                    .kernel
                    .evaluate_tool_call_with_security_context(request, security_context),
            )
        } else {
            runtime
                .kernel
                .evaluate_tool_call_blocking_with_security_context(request, security_context)
        });
    }
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    let session = kernel.open_session_with_id(
        chio_core::session::SessionId::new(security_context.as_v1().session_id().as_str()),
        request.agent_id.clone(),
        Vec::new(),
    )?;
    kernel.activate_session(&session)?;
    kernel.set_security_invocation_context_authority(Arc::new(nested::ContextAuthority(
        security_context.clone(),
    )));
    let parent = chio_core::session::OperationContext::new(
        session,
        chio_core::session::RequestId::new(&request.request_id),
        request.agent_id.clone(),
    );
    let operation = chio_core::session::ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    Ok(if asynchronous {
        executor.block_on(
            kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
                &parent,
                &operation,
                &mut nested::Client,
            ),
        )
    } else {
        kernel.evaluate_tool_call_operation_with_nested_flow_client(
            &parent,
            &operation,
            &mut nested::Client,
        )
    })
}

#[test]
fn live_release_callback_can_enter_the_original_mutation_sequence() -> TestResult {
    for asynchronous in [false, true] {
        run_sequence(false, asynchronous)?;
    }
    Ok(())
}

#[test]
fn nested_live_release_callback_can_enter_the_original_mutation_sequence() -> TestResult {
    for asynchronous in [false, true] {
        run_sequence(true, asynchronous)?;
    }
    Ok(())
}
