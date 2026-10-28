use super::*;

struct AttemptRecordingGuard {
    name: &'static str,
    observed: Arc<Mutex<Vec<(String, std::thread::ThreadId)>>>,
}

impl Guard for AttemptRecordingGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn evidence_declaration(&self) -> crate::GuardEvidenceDeclaration {
        crate::GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let identity = context.invocation_attempt_id().ok_or_else(|| {
            KernelError::GuardDenied("kernel guard attempt is missing".to_owned())
        })?;
        self.observed
            .lock()
            .map_err(|_| KernelError::GuardDenied("attempt observer lock failed".to_owned()))?
            .push((identity.to_owned(), std::thread::current().id()));
        Ok(GuardDecision::allow())
    }
}

enum Transport {
    Inline,
    TimerlessOffload,
    PipelineOffload,
    PerGuardOffload,
}

fn assert_attempt_transport(transport: Transport) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.deadlines.always_offload_guards = !matches!(transport, Transport::Inline);
    if matches!(
        transport,
        Transport::PipelineOffload | Transport::PerGuardOffload
    ) {
        config.deadlines.guard_pipeline_budget_ms = 200;
    }
    if matches!(transport, Transport::PerGuardOffload) {
        for name in ["attempt-a", "attempt-b"] {
            config
                .deadlines
                .per_guard_budget_ms
                .insert(name.to_owned(), 100);
        }
    }
    let mut kernel = make_kernel(config);
    let observed = Arc::new(Mutex::new(Vec::new()));
    for name in ["attempt-a", "attempt-b"] {
        kernel.add_guard(Box::new(AttemptRecordingGuard {
            name,
            observed: observed.clone(),
        }));
    }
    let agent = make_keypair();
    let scope = make_scope(vec![make_grant("attempt-server", "read")]);
    let cap = make_capability(&kernel, &agent, scope.clone(), 300);
    let request = make_request("attempt-request", &cap, "read", "attempt-server");
    let attempt = GuardInvocationAttempt::fresh();
    let calling_thread = std::thread::current().id();
    let mut runtime = tokio::runtime::Builder::new_current_thread();
    if !matches!(transport, Transport::TimerlessOffload) {
        runtime.enable_all();
    }
    runtime
        .build()?
        .block_on(kernel.run_guards_within_budget(&request, &scope, None, Some(0), None, &attempt))
        .map_err(|error| error.error)?;

    let observed = observed.lock().map_err(|_| "attempt observer poisoned")?;
    assert_eq!(observed.len(), 2);
    for (identity, thread) in observed.iter() {
        assert_eq!(identity, attempt.as_str());
        if matches!(transport, Transport::Inline) {
            assert_eq!(*thread, calling_thread);
        } else {
            assert_ne!(*thread, calling_thread);
        }
    }
    Ok(())
}

#[test]
fn kernel_attempt_identity_survives_inline_guards() -> Result<(), Box<dyn std::error::Error>> {
    assert_attempt_transport(Transport::Inline)
}

#[test]
fn kernel_attempt_identity_survives_timerless_offload() -> Result<(), Box<dyn std::error::Error>> {
    assert_attempt_transport(Transport::TimerlessOffload)
}

#[test]
fn kernel_attempt_identity_survives_pipeline_offload() -> Result<(), Box<dyn std::error::Error>> {
    assert_attempt_transport(Transport::PipelineOffload)
}

#[test]
fn kernel_attempt_identity_survives_per_guard_offload() -> Result<(), Box<dyn std::error::Error>> {
    assert_attempt_transport(Transport::PerGuardOffload)
}

#[test]
fn actual_admitted_operation_owns_guard_identity_and_replay_dispatches_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, request, _store, invocations) =
        crate::kernel::tests::durable_admission::durable_admission_fixture("attempt-owned-request");
    let observed = Arc::new(Mutex::new(Vec::new()));
    kernel.add_guard(Box::new(AttemptRecordingGuard {
        name: "owned-attempt",
        observed: observed.clone(),
    }));

    let first = kernel.evaluate_tool_call_blocking(&request)?;
    let replay = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(first.verdict, Verdict::Allow);
    assert_eq!(replay.verdict, Verdict::Allow);
    assert!(first.output.is_some());
    assert!(replay.output.is_some());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let observed = observed.lock().map_err(|_| "attempt observer poisoned")?;
    assert_eq!(observed.len(), 1);
    assert!(observed
        .first()
        .is_some_and(|(identity, _)| identity.starts_with("admission-operation:")));
    Ok(())
}
