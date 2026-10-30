//! Reuse the real SQLite collection fixture rather than model approval authority.
extern crate chio_core_types as chio_core;
// Other integration targets use the remaining shared fixture helpers.
#[allow(dead_code)]
#[path = "../../../platform/chio-store-sqlite/tests/threshold_kernel_lifecycle/support.rs"]
mod support;

use chio_kernel::{
    KernelError, NestedFlowBridge, ToolServerConnection, ToolServerStreamResult, Verdict,
};
use chio_process::{ProcessLimits, ProcessRuntime};
use std::sync::{atomic::Ordering, Arc};
use support::{canonical, now, operation_state, Fixture, TestResult};

#[derive(Debug, PartialEq)]
struct RetainedSnapshot {
    rows: Vec<Vec<rusqlite::types::Value>>,
    anchor: Vec<u8>,
}

fn retained_snapshot(fixture: &Fixture) -> TestResult<RetainedSnapshot> {
    let connection = rusqlite::Connection::open(fixture.database())?;
    let mut rows = Vec::new();
    for table in ["admission_operations", "admission_operation_commit_meta"] {
        let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
        let columns = statement.column_count();
        rows.extend(
            statement
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })?
                .collect::<rusqlite::Result<Vec<Vec<rusqlite::types::Value>>>>()?,
        );
    }
    let store: String =
        connection.query_row("SELECT store_uuid FROM chio_serving_owner", [], |row| {
            row.get(0)
        })?;
    Ok(RetainedSnapshot {
        rows,
        anchor: std::fs::read(
            fixture
                .directory
                .path()
                .join("locks")
                .join(format!("{store}.lock")),
        )?,
    })
}

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

fn launch(id: char) -> TestResult<[(String, chio_process::ProcessLaunchReceipt); 1]> {
    Ok([(
        "collector-server".into(),
        chio_process::ProcessLaunchReceipt::new(id.to_string().repeat(64), "d".repeat(64))?,
    )])
}

#[test]
fn collected_threshold_artifacts_are_bound_on_original_process_call_and_recover_once() -> TestResult
{
    threshold_recovery(false)
}

#[test]
fn collected_threshold_artifacts_recover_within_controlled_authority_window() -> TestResult {
    threshold_recovery(true)
}

fn threshold_recovery(controlled_clock: bool) -> TestResult {
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
        )?
        .with_launch_receipts(launch('a')?)?;
        let mut request = fixture.request(&native, "approval-process")?;
        _clock = controlled_clock.then(|| chio_test_support::clock::scope_unix_secs(now() + 60));
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
        let pending = executor.block_on(process.invoke("root", "read", &request))?;
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
        // A relaunched host resumes the pending call and dispatches it under
        // its own launch.
        drop(process);
        let process = ProcessRuntime::open(
            fixture.directory.path().join("process.db"),
            native.kernel.clone(),
        )?
        .with_launch_receipts(launch('b')?)?;
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
                &first,
                Err(chio_process::ProcessError::Kernel(
                    KernelError::UrlElicitationsRequired { message, elicitations }
                )) if message == "outcome unavailable after dispatch" && elicitations.is_empty()
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
    )?
    .with_launch_receipts(launch('c')?)?;
    let original = std::fs::read(fixture.directory.path().join("original-request.json"))?;
    assert_eq!(original, request_bytes);
    let request = serde_json::from_slice(&original)?;
    let before = retained_snapshot(&fixture)?;
    let response = executor.block_on(process.invoke("root", "read", &request))?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(response.request_id, process.request_id("root", "read")?);
    assert!(response.receipt.verify_integrity_embedded_key()?);
    let metadata = response.receipt.metadata.as_ref().ok_or("metadata")?;
    assert_eq!(metadata["chio_process"]["attempt"], 1);
    assert_eq!(
        metadata["admission_operation"]["projected_state"],
        "outcome_unknown_after_dispatch"
    );
    // The resumed dispatch failed inside its live evaluation under launch b.
    assert_eq!(
        metadata["native_launch"],
        serde_json::to_value(&launch('b')?[0].1)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(canonical(&request)?, request_bytes);
    assert_eq!(retained_snapshot(&fixture)?, before);
    assert_eq!(process.process("root")?.tree_calls, 1);
    Ok(())
}

struct CompletingWrite(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for CompletingWrite {
    fn server_id(&self) -> &str {
        "collector-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"written": true}))
    }
}

#[test]
fn pending_threshold_approval_resumes_on_the_same_process_key() -> TestResult {
    let fixture = Fixture::new()?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut native = fixture.open()?;
    let kernel = Arc::get_mut(&mut native.kernel).ok_or("unique kernel")?;
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    kernel.register_tool_server(Box::new(CompletingWrite(fixture.invocations.clone())));
    let process = ProcessRuntime::open(
        fixture.directory.path().join("process.db"),
        native.kernel.clone(),
    )?;
    let mut request = fixture.request(&native, "approval-resume")?;
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
    request.request_id = process.request_id("root", "write")?;
    let pending = executor.block_on(process.invoke("root", "write", &request))?;
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
    let pending_state = operation_state(&fixture, &request.request_id)?;
    let collector = fixture.collector(&native, true)?;
    collector.create_proposal(proposal.clone(), now())?;
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        now(),
    )?;
    let delivered = collector.deliver(&proposal.body.proposal_id, now())?;
    let mut approved = request.clone();
    approved.threshold_approval_proposal = Some(delivered.proposal.clone());
    approved.approval_tokens = delivered.tokens.clone();

    let mut changed = approved.clone();
    changed.arguments["record"] = serde_json::json!("substituted");
    let conflict = executor.block_on(process.invoke("root", "write", &changed));
    assert!(
        matches!(conflict, Err(chio_process::ProcessError::Conflict)),
        "{conflict:?}"
    );

    let mut forged = approved.clone();
    forged.approval_tokens =
        vec![fixture.vote(&delivered.proposal, &chio_core::crypto::Keypair::generate())?];
    let forged_result = executor.block_on(process.invoke("root", "write", &forged));
    assert!(
        matches!(
            &forged_result,
            Err(chio_process::ProcessError::Kernel(KernelError::GovernedTransactionDenied(reason)))
                if reason == "threshold approval verification denied: approval token signer is not valid"
        ),
        "{forged_result:?}"
    );
    let mut other_proposal = delivered.proposal.clone();
    other_proposal.body.proposal_id.push_str("-other");
    let mut mismatched = approved.clone();
    mismatched.approval_tokens = vec![fixture.vote(&other_proposal, &fixture.reviewer)?];
    let mismatched_result = executor.block_on(process.invoke("root", "write", &mismatched));
    assert!(
        matches!(
            &mismatched_result,
            Err(chio_process::ProcessError::Kernel(KernelError::GovernedTransactionDenied(reason)))
                if reason == "threshold approval verification denied: approval token binding or validity is invalid"
        ),
        "{mismatched_result:?}"
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operation_state(&fixture, &request.request_id)?,
        pending_state
    );

    let completed = executor.block_on(process.invoke("root", "write", &approved))?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let replayed = executor.block_on(process.invoke("root", "write", &approved))?;
    assert_eq!(
        canonical(&replayed.receipt)?,
        canonical(&completed.receipt)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(process.process("root")?.tree_calls, 1);
    Ok(())
}

struct ParkedWrite(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for ParkedWrite {
    fn server_id(&self) -> &str {
        "collector-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
        Ok(serde_json::json!({}))
    }
}

/// A pending call admitted under launch a and resumed by a relaunched host
/// dispatches under launch b. Recovery with no live caller names launch b,
/// which the dispatch commitment recorded.
#[test]
fn recovery_after_a_relaunched_dispatch_names_the_dispatching_launch() -> TestResult {
    use std::future::Future;
    let fixture = Fixture::new()?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let journal = fixture.directory.path().join("process.db");
    let mut request;
    let delivered;
    {
        let mut native = fixture.open()?;
        let kernel = Arc::get_mut(&mut native.kernel).ok_or("unique kernel")?;
        kernel.configure_durable_admission(
            chio_kernel::admission_operation::DurableAdmissionMode::All,
            false,
        )?;
        kernel.register_tool_server(Box::new(ParkedWrite(fixture.invocations.clone())));
        let process = ProcessRuntime::open(&journal, native.kernel.clone())?
            .with_launch_receipts(launch('a')?)?;
        request = fixture.request(&native, "approval-relaunch")?;
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
        request.request_id = process.request_id("root", "write")?;
        let pending = executor.block_on(process.invoke("root", "write", &request))?;
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
        delivered = collector.deliver(&proposal.body.proposal_id, now())?;
        drop(process);

        let relaunched = ProcessRuntime::open(&journal, native.kernel.clone())?
            .with_launch_receipts(launch('b')?)?;
        let mut approved = request.clone();
        approved.threshold_approval_proposal = Some(delivered.proposal.clone());
        approved.approval_tokens = delivered.tokens.clone();
        let mut dispatch = Box::pin(relaunched.invoke("root", "write", &approved));
        let _entered = executor.enter();
        if let std::task::Poll::Ready(result) = dispatch
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            return Err(format!("relaunched dispatch finished: {result:?}").into());
        }
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        drop(dispatch);
    }

    let mut native = fixture.open()?;
    let kernel = Arc::get_mut(&mut native.kernel).ok_or("unique restarted kernel")?;
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    kernel.register_tool_server(Box::new(ParkedWrite(fixture.invocations.clone())));
    native.kernel.reconcile_durable_admission_startup()?;
    let process = ProcessRuntime::open(&journal, native.kernel.clone())?
        .with_launch_receipts(launch('c')?)?;
    let mut approved = request.clone();
    approved.threshold_approval_proposal = Some(delivered.proposal);
    approved.approval_tokens = delivered.tokens;
    let response = executor.block_on(process.invoke("root", "write", &approved))?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    let metadata = response.receipt.metadata.as_ref().ok_or("metadata")?;
    assert_eq!(
        metadata["admission_operation"]["projected_state"],
        "outcome_unknown_after_dispatch"
    );
    assert_eq!(
        metadata["native_launch"],
        serde_json::to_value(&launch('b')?[0].1)?
    );
    assert_eq!(
        metadata["admission_operation"]["retained_dispatch_commit"]["dispatch_launch"]
            ["native_launch"],
        serde_json::to_value(&launch('b')?[0].1)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
