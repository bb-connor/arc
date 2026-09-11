//! Exercise the same security owner checks through nested dispatch.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "security_dispatch/credentials.rs"]
mod credentials;
#[path = "security_dispatch/legacy_nonce.rs"]
mod legacy_nonce;

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Acquire,
    Commit,
    WrongOwner,
    Record,
    Release,
    Reject,
}

struct Hook(Fault);
struct Recorder(Fault);
struct Permit(Fault);

impl SecurityRequestLifecyclePermit for Permit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        assert!(!matches!(self.0, Fault::Release), "release callback fault");
        Ok(())
    }
}

impl SecurityDispatchOutcomeRecorder for Recorder {
    fn record(&mut self, _: SecurityDispatchOutcome) -> Result<(), KernelError> {
        assert!(!matches!(self.0, Fault::Record), "record callback fault");
        Ok(())
    }
}

impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        panic!("security diagnostics must not call hook code");
    }

    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        assert!(
            !matches!(self.0, Fault::Acquire),
            "acquisition callback fault"
        );
        Ok(Some(Box::new(Permit(self.0))))
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        assert!(!matches!(self.0, Fault::Commit), "commit callback fault");
        if matches!(self.0, Fault::Reject) {
            return Err(KernelError::GuardDenied("rejected".into()));
        }
        let commitment = if matches!(self.0, Fault::WrongOwner) {
            chio_security_types::ports::RecordId::new("another-dispatch")
                .map_err(|error| KernelError::Internal(error.to_string()))?
        } else {
            context.dispatch_commitment_id.clone()
        };
        Ok(Some(SecurityDispatchOutcomeHandle::new(
            &SecurityPreDispatchContext {
                dispatch_commitment_id: &commitment,
                ..*context
            },
            Box::new(Recorder(self.0)),
        )))
    }
}

struct Server(Arc<AtomicU64>);

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "security-dispatch-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["inspect".into()]
    }
    fn tool_is_read_only(&self, _: &str) -> bool {
        true
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"private_output": true}))
    }
}

#[test]
fn nested_security_callbacks_preserve_the_effect_boundary() -> TestResult {
    for fault in [
        Fault::None,
        Fault::Acquire,
        Fault::Commit,
        Fault::WrongOwner,
        Fault::Record,
        Fault::Release,
    ] {
        let mut kernel = make_kernel(make_config());
        let invocations = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(Server(invocations.clone())));
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook(fault)));
        let agent = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent,
            make_scope(vec![make_grant("security-dispatch-server", "inspect")]),
            300,
        );
        let request = make_request(
            "security-nested",
            &cap,
            "inspect",
            "security-dispatch-server",
        );
        let session = kernel.open_session(request.agent_id.clone(), vec![])?;
        kernel.activate_session(&session)?;
        let parent = make_operation_context(&session, "security-parent", &request.agent_id);
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-security-test")?,
            chio_security_types::ports::SessionId::new(session.as_str())?,
            chio_security_types::PrincipalId::new(request.agent_id.clone())?,
            chio_security_types::ports::IsolationEpochId::new("security-test-epoch")?,
            chio_security_types::ports::LineageId::new(cap.id.clone())?,
            1,
        ));
        let result = kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
            Some(&context),
        );
        match fault {
            Fault::None => assert_eq!(result?.verdict, Verdict::Allow),
            Fault::Record | Fault::Release => assert!(
                matches!(
                    result,
                    Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
                ),
                "{fault:?}: {result:?}"
            ),
            _ => assert_eq!(result?.verdict, Verdict::Deny, "{fault:?}"),
        }
        let dispatched = matches!(fault, Fault::None | Fault::Record | Fault::Release);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            u64::from(dispatched),
            "{fault:?}"
        );
    }
    Ok(())
}

/// Enable warning field evaluation without introducing a subscriber dependency.
struct EnabledWarnings;
impl tracing::Subscriber for EnabledWarnings {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn rejection_with_warning_logging_does_not_call_hook_name() -> TestResult {
    let mut kernel = make_kernel(make_config());
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook(Fault::Reject)));
    let agent = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("srv", "tool")]),
        300,
    );
    let request = make_request("security-logging", &cap, "tool", "srv");
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("tenant")?,
        chio_security_types::ports::SessionId::new("session")?,
        chio_security_types::PrincipalId::new(request.agent_id.clone())?,
        chio_security_types::ports::IsolationEpochId::new("epoch")?,
        chio_security_types::ports::LineageId::new(cap.id.clone())?,
        1,
    ));
    let result = tracing::subscriber::with_default(EnabledWarnings, || {
        kernel.run_security_pre_dispatch_hook(&request, Some(&context), None)
    });
    assert!(result.is_err());
    Ok(())
}
