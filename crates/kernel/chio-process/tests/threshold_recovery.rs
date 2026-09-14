//! Reuse the real SQLite collection fixture rather than model approval authority.
extern crate chio_core_types as chio_core;
#[path = "../../../platform/chio-store-sqlite/tests/threshold_kernel_lifecycle/support.rs"]
mod support;

use chio_kernel::{
    KernelError, NestedFlowBridge, ToolServerConnection, ToolServerStreamResult, Verdict,
};
use chio_process::{ProcessLimits, ProcessRuntime};
use std::sync::{atomic::Ordering, Arc};
use support::{canonical, now, Fixture, TestResult};

struct UnknownRead(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for UnknownRead {
    fn server_id(&self) -> &str {
        "collector-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
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
        Err(KernelError::GuardDenied("stream-only fixture".into()))
    }
    async fn invoke_stream(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "outcome unavailable after dispatch".into(),
            elicitations: Vec::new(),
        })
    }
}

#[test]
fn collected_threshold_artifacts_are_bound_on_original_process_call_and_recover_once() -> TestResult
{
    // The SQLite budget clock is physical; hold the admission/collector clock
    // later within the 300-second proposal window to avoid testing clock races.
    let _clock;
    let fixture = Fixture::new()?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let request_bytes;
    {
        let mut native = fixture.open()?;
        let kernel = Arc::get_mut(&mut native.kernel).ok_or("unique kernel")?;
        kernel.configure_durable_admission(
            chio_kernel::admission_operation::DurableAdmissionMode::All,
            false,
        )?;
        kernel.register_tool_server(Box::new(UnknownRead(fixture.invocations.clone())));
        let process = ProcessRuntime::open(
            fixture.directory.path().join("process.db"),
            native.kernel.clone(),
        )?;
        let mut request = fixture.request(&native, "approval-process")?;
        // Diagnostic opt-in preserves the separate physical-clock regression;
        // this test's normal oracle is retained artifact identity.
        _clock = std::env::var_os("CHIO_PROCESS_TEST_PHYSICAL_APPROVAL_CLOCK")
            .is_none()
            .then(|| {
                chio_kernel::scope_fixed_runtime_for_current_thread(
                    now() + 60,
                    Vec::<String>::new(),
                )
            });
        process.create_root(
            "root",
            &request.capability,
            ProcessLimits {
                max_processes: 1,
                max_depth: 0,
                max_calls: 1,
                state: Default::default(),
            },
        )?;
        request.request_id = process.request_id("root", "read")?;
        let pending = executor.block_on(native.kernel.evaluate_tool_call(&request))?;
        assert_eq!(
            pending.verdict,
            Verdict::PendingApproval,
            "{:?}",
            pending.reason
        );
        let Some(chio_kernel::ToolCallOutput::Value(value)) = pending.output else {
            return Err("missing pending proposal".into());
        };
        let proposal: chio_core::capability::governance::ThresholdApprovalProposal =
            serde_json::from_value(value)?;
        let collector = fixture.collector(&native, true)?;
        collector.create_proposal(proposal.clone(), now())?;
        collector.submit_token(
            &proposal.body.proposal_id,
            fixture.vote(&proposal, &fixture.reviewer)?,
            now(),
        )?;
        let delivered = collector.deliver(&proposal.body.proposal_id, now())?;
        request.threshold_approval_proposal = Some(delivered.proposal);
        request.approval_tokens = delivered.tokens;
        request_bytes = canonical(&request)?;
        std::fs::write(
            fixture.directory.path().join("original-request.json"),
            &request_bytes,
        )?;
        let first = executor.block_on(process.invoke("root", "read", &request));
        if first.as_ref().err().is_some_and(|error| {
            error
                .to_string()
                .contains("trusted operation time regressed")
        }) {
            let connection = rusqlite::Connection::open(fixture.database())?;
            let stored: (String, i64) = connection.query_row(
                "SELECT state, updated_at_unix_ms FROM admission_operations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            eprintln!(
                "physical-clock diagnostic: invocations={}, retained={stored:?}",
                fixture.invocations.load(Ordering::SeqCst)
            );
        }
        assert!(
            matches!(
                first,
                Err(chio_process::ProcessError::Kernel(
                    KernelError::UrlElicitationsRequired { .. }
                ))
            ),
            "{first:?}"
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    }
    let mut native = fixture.open()?;
    let kernel = Arc::get_mut(&mut native.kernel).ok_or("unique restarted kernel")?;
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    kernel.register_tool_server(Box::new(UnknownRead(fixture.invocations.clone())));
    let process = ProcessRuntime::open(
        fixture.directory.path().join("process.db"),
        native.kernel.clone(),
    )?;
    let original = std::fs::read(fixture.directory.path().join("original-request.json"))?;
    assert_eq!(original, request_bytes);
    let request = serde_json::from_slice(&original)?;
    let response = executor.block_on(process.invoke("root", "read", &request))?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(response.request_id, process.request_id("root", "read")?);
    assert!(response.receipt.verify_signature()?);
    let metadata = response.receipt.metadata.as_ref().ok_or("metadata")?;
    assert_eq!(metadata["chio_process"]["attempt"], 1);
    assert_eq!(
        metadata["admission_operation"]["projected_state"],
        "outcome_unknown_after_dispatch"
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(canonical(&request)?, request_bytes);
    Ok(())
}
