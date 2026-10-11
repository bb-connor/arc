#[cfg(feature = "pq")]
#[path = "payload_maintenance_tests/signing.rs"]
mod signing;

use super::*;

#[path = "payload_maintenance_tests/migration.rs"]
mod migration;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};
use chio_core::crypto::sha256_hex;
use chio_kernel::admission_operation::{
    AdmissionOperationState, AdmissionOperationStore, AdmissionReceiptMetadataV1,
    ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::{
    KernelConfig, KernelError, NestedFlowBridge, ReceiptStore, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use rusqlite::{Connection, OpenFlags};

type TestResult = Result<(), Box<dyn Error>>;

struct MaintenanceTool {
    calls: Arc<AtomicU64>,
}

pub(crate) struct CountedPostReturnHook(pub(crate) Arc<AtomicU64>);

impl chio_kernel::post_invocation::PostInvocationHook for CountedPostReturnHook {
    fn name(&self) -> &str {
        "payload-maintenance-counted-hook"
    }
    fn inspect(
        &self,
        _: &chio_kernel::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> chio_kernel::post_invocation::PostInvocationVerdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        chio_kernel::post_invocation::PostInvocationVerdict::Allow
    }
    fn durable_identity(
        &self,
    ) -> Result<Option<chio_kernel::post_invocation::PostInvocationHookIdentity>, String> {
        chio_kernel::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "payload-maintenance-counted-hook",
            "1.0.0",
            "counted-allow-v1",
            &(),
        )
        .map(Some)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MaintenanceTool {
    fn server_id(&self) -> &str {
        "maintenance-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"result": arguments}))
    }
}

pub(crate) fn configured_kernel(
    runtime: &DurableAdmissionRuntime,
    calls: Arc<AtomicU64>,
) -> Result<ChioKernel, CliError> {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: runtime.kernel_keypair(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"payload-maintenance-test-policy"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        chio_test_support::clock::clock(),
    );
    runtime.attach(&mut kernel)?;
    kernel.set_governed_approval_policy(
        "payload-maintenance-test-tenant".into(),
        vec![runtime.kernel_keypair().public_key()],
    )?;
    kernel.register_tool_server(Box::new(MaintenanceTool { calls }));
    Ok(kernel)
}

pub(crate) fn request_with_credentials(
    kernel: &ChioKernel,
    approver: &Keypair,
    request_id: &str,
) -> Result<ToolCallRequest, Box<dyn Error>> {
    request_with_constraints(kernel, approver, request_id, Vec::new())
}

fn request_with_constraints(
    kernel: &ChioKernel,
    approver: &Keypair,
    request_id: &str,
    constraints: Vec<Constraint>,
) -> Result<ToolCallRequest, Box<dyn Error>> {
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "maintenance-server".into(),
                tool_name: "mutate".into(),
                operations: vec![Operation::Invoke],
                constraints,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let now = chio_test_support::clock::unix_seconds();
    let arguments = serde_json::json!({"record": "retained-material"});
    let intent = GovernedTransactionIntent {
        id: format!("intent-{request_id}"),
        server_id: "maintenance-server".into(),
        tool_name: "mutate".into(),
        purpose: "retained credential fixture".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: capability.id.clone(),
            parameters_hash: chio_core::sha256(&canonical_json_bytes(&arguments)?),
        },
    };
    let mut request = ToolCallRequest {
        request_id: request_id.into(),
        agent_id: agent.public_key().to_hex(),
        dpop_proof: Some(DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.into(),
                replay_authority: None,
                capability_id: capability.id.clone(),
                tool_server: "maintenance-server".into(),
                tool_name: "mutate".into(),
                action_hash: sha256_hex(&canonical_json_bytes(
                    &serde_json::json!({"record": "retained-material"}),
                )?),
                nonce: format!("DURABLE_TRANSIENT_PROOF_CANARY-{request_id}"),
                issued_at: now,
                agent_key: agent.public_key(),
            },
            &agent,
        )?),
        approval_token: None,
        capability,
        server_id: "maintenance-server".into(),
        tool_name: "mutate".into(),
        arguments,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let bound_intent = kernel.bind_tool_approval_intent(&request)?;
    request.approval_token = Some(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("DURABLE_TRANSIENT_APPROVAL_CANARY-{request_id}"),
            approver: approver.public_key(),
            subject: agent.public_key(),
            governed_intent_hash: bound_intent.binding_hash()?,
            request_id: request_id.into(),
            threshold_proposal_hash: None,
            issued_at: now,
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )?);
    request.governed_intent = Some(bound_intent);
    Ok(request)
}

pub(crate) fn receipt_operation(
    receipt: &chio_core::receipt::body::ChioReceipt,
) -> Result<AdmissionReceiptMetadataV1, Box<dyn Error>> {
    Ok(serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .ok_or("missing admission metadata")?,
    )?)
}

pub(crate) fn raw_payload_present(path: &Path, digest: &str) -> Result<bool, Box<dyn Error>> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection.query_row(
        "SELECT canonical_bytes IS NOT NULL FROM tool_outcome_blobs WHERE digest = ?1",
        [digest],
        |row| row.get(0),
    )?)
}

fn test_maintenance_config() -> TerminalPayloadMaintenanceConfig {
    TerminalPayloadMaintenanceConfig {
        terminal_raw_payload_ttl: Duration::from_secs(10),
        interval: Duration::from_millis(10),
        page_limits: chio_store_sqlite::ToolOutcomeCompactionLimits::default(),
    }
}

fn wait_for_health(
    runtime: &DurableAdmissionRuntime,
    accept: impl Fn(&TerminalPayloadMaintenanceHealth) -> bool,
) -> Result<TerminalPayloadMaintenanceHealth, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let health = runtime.terminal_payload_maintenance_health();
        if accept(&health) {
            return Ok(health);
        }
        if Instant::now() >= deadline {
            return Err(format!("maintenance health condition did not arrive: {health:?}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn durable_payload_maintenance_new_raw_requests_omit_transient_canaries() -> TestResult {
    let directory = private_tempdir()?;
    let database = directory.path().join("credential.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&runtime, calls.clone())?;
    let request = request_with_credentials(
        &kernel,
        &runtime.kernel_keypair(),
        "credential-minimization",
    )?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let operation = receipt_operation(&response.receipt)?;
    let authority = runtime
        .local_authority_store()
        .ok_or("missing local authority")?;
    let raw = authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(&operation.operation_id)?
        .ok_or("missing raw envelope")?;
    let request_json = raw
        .to_persisted()
        .request_canonical_json
        .ok_or("missing raw request")?;
    assert!(!request_json.contains("DURABLE_TRANSIENT_PROOF_CANARY"));
    assert!(!request_json.contains("DURABLE_TRANSIENT_APPROVAL_CANARY"));
    let retained: ToolCallRequest = serde_json::from_str(&request_json)?;
    assert_eq!(
        canonical_json_bytes(&retained.capability)?,
        canonical_json_bytes(&request.capability)?
    );
    assert_eq!(retained.arguments, request.arguments);
    Ok(())
}

#[test]
fn durable_payload_maintenance_tick_compacts_terminal_bytes_and_replay_survives_restart(
) -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let hooks = Arc::new(AtomicU64::new(0));
    let mut kernel = configured_kernel(&runtime, calls.clone())?;
    kernel.add_post_invocation_hook(Box::new(CountedPostReturnHook(hooks.clone())));
    let request =
        request_with_credentials(&kernel, &runtime.kernel_keypair(), "terminal-maintenance")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    let operation = receipt_operation(&response.receipt)?;
    let authority = runtime
        .local_authority_store()
        .ok_or("missing local authority")?;
    let outcomes = authority.tool_outcome_store();
    let before = outcomes
        .lookup_by_operation(&operation.operation_id)?
        .ok_or("missing outcome")?;
    let digest = before.raw_output_digest().as_str().to_owned();
    assert!(raw_payload_present(&database, &digest)?);
    assert_eq!(
        authority
            .admission_operation_store()
            .load_by_operation_id(&operation.operation_id)?
            .ok_or("missing operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    runtime.start_terminal_payload_maintenance(test_maintenance_config())?;
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let deadline = Instant::now() + Duration::from_secs(2);
    while raw_payload_present(&database, &digest)? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !raw_payload_present(&database, &digest)?,
        "an owned maintenance tick must erase terminal raw bytes after the explicit TTL"
    );
    assert_eq!(
        outcomes.lookup_by_operation(&operation.operation_id)?,
        Some(before)
    );
    assert_eq!(
        canonical_json_bytes(
            &authority
                .admission_operation_store()
                .load_chio_receipt(&response.receipt.id)?
                .ok_or("missing retained receipt")?
        )?,
        canonical_json_bytes(&response.receipt)?
    );
    drop(outcomes);
    drop(authority);
    drop(kernel);
    drop(runtime);
    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let mut recovered = configured_kernel(&reopened, calls.clone())?;
    recovered.add_post_invocation_hook(Box::new(CountedPostReturnHook(hooks.clone())));
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        hooks.load(Ordering::SeqCst),
        1,
        "compacted replay must not rerun hooks"
    );
    Ok(())
}

#[test]
fn durable_payload_maintenance_holds_denied_after_delivery_and_cold_replay_keeps_refusal(
) -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("denied-maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&runtime, calls.clone())?;
    let request = request_with_constraints(
        &kernel,
        &runtime.kernel_keypair(),
        "denied-after-delivery-maintenance",
        vec![Constraint::OutputDigestSha256("d".repeat(64))],
    )?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let metadata = receipt_operation(&response.receipt)?;
    let authority = runtime
        .local_authority_store()
        .ok_or("missing local authority")?;
    let operation = authority
        .admission_operation_store()
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or("missing denied admission")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    let outcome = authority
        .tool_outcome_store()
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing denied outcome")?;
    let digest = outcome.raw_output_digest().as_str().to_owned();
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    runtime.start_terminal_payload_maintenance(test_maintenance_config())?;
    let health = wait_for_health(&runtime, |health| health.retained_non_completed > 0)?;
    assert_eq!(health.retained_non_completed, 1);
    assert_eq!(
        health.lifecycle,
        TerminalPayloadMaintenanceLifecycle::Degraded
    );
    assert!(
        raw_payload_present(&database, &digest)?,
        "maintenance must retain denied-after-delivery raw bytes required by original refusal replay: {health:?}"
    );
    runtime.shutdown_terminal_payload_maintenance()?;
    drop(authority);
    drop(kernel);
    drop(runtime);
    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let recovered = configured_kernel(&reopened, calls.clone())?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, response.verdict);
    assert_eq!(replay.reason, response.reason);
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "denial replay must not invoke"
    );
    Ok(())
}

#[test]
fn durable_payload_maintenance_missing_configuration_retains_terminal_bytes() -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("disabled-maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let kernel = configured_kernel(&runtime, Arc::new(AtomicU64::new(0)))?;
    let request =
        request_with_credentials(&kernel, &runtime.kernel_keypair(), "disabled-maintenance")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let operation = receipt_operation(&response.receipt)?;
    let outcome = runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .tool_outcome_store()
        .lookup_by_operation(&operation.operation_id)?
        .ok_or("missing outcome")?;
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    std::thread::sleep(Duration::from_millis(30));
    let health = runtime.terminal_payload_maintenance_health();
    assert_eq!(
        health.lifecycle,
        TerminalPayloadMaintenanceLifecycle::MissingConfiguration
    );
    assert!(!health.worker_running);
    assert_eq!(health.ticks_attempted, 0);
    assert_eq!(health.compacted, 0);
    assert!(raw_payload_present(
        &database,
        outcome.raw_output_digest().as_str()
    )?);
    Ok(())
}

#[test]
fn durable_payload_maintenance_budget_failures_remain_visible_after_join() -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    for (name, sql_steps, bytes, reason) in [
        ("sql", 1, 16_777_216, "SQL work budget"),
        ("bytes", 2_000_000, 1, "payload byte budget"),
    ] {
        let directory = private_tempdir()?;
        let database = directory.path().join(format!("{name}-maintenance.db"));
        let runtime =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
        let kernel = configured_kernel(&runtime, Arc::new(AtomicU64::new(0)))?;
        let request = request_with_credentials(&kernel, &runtime.kernel_keypair(), name)?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let operation = receipt_operation(&response.receipt)?;
        let outcome = runtime
            .local_authority_store()
            .ok_or("missing authority")?
            .tool_outcome_store()
            .lookup_by_operation(&operation.operation_id)?
            .ok_or("missing outcome")?;
        let advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
        let mut config = test_maintenance_config();
        config.page_limits.max_sql_steps = sql_steps;
        config.page_limits.max_payload_bytes = bytes;
        runtime.start_terminal_payload_maintenance(config)?;
        let health = wait_for_health(&runtime, |health| health.failures > 0)?;
        assert_eq!(
            health.lifecycle,
            TerminalPayloadMaintenanceLifecycle::Degraded
        );
        assert!(health
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains(reason)));
        assert_eq!(health.compacted, 0);
        assert!(raw_payload_present(
            &database,
            outcome.raw_output_digest().as_str()
        )?);
        let stopped = runtime.shutdown_terminal_payload_maintenance()?;
        assert!(stopped.worker_joined);
        assert!(!stopped.worker_running);
        assert!(stopped
            .last_failure
            .as_deref()
            .is_some_and(|error| error.contains(reason)));
        assert!(stopped.failures > 0);
        drop(kernel);
        drop(runtime);
        drop(advanced);
    }
    Ok(())
}

#[test]
fn durable_payload_maintenance_stale_fence_stops_without_erasure() -> TestResult {
    let directory = private_tempdir()?;
    let database = directory.path().join("fenced-maintenance.db");
    let mut runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let kernel = configured_kernel(&runtime, Arc::new(AtomicU64::new(0)))?;
    let request =
        request_with_credentials(&kernel, &runtime.kernel_keypair(), "fenced-maintenance")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let operation = receipt_operation(&response.receipt)?;
    let outcome = runtime
        .local_authority_store()
        .ok_or("missing authority")?
        .tool_outcome_store()
        .lookup_by_operation(&operation.operation_id)?
        .ok_or("missing outcome")?;
    runtime.fence.owner_epoch = runtime
        .fence
        .owner_epoch
        .checked_add(1)
        .ok_or("epoch overflow")?;
    runtime.start_terminal_payload_maintenance(test_maintenance_config())?;
    let health = wait_for_health(&runtime, |health| {
        health.lifecycle == TerminalPayloadMaintenanceLifecycle::Fenced
    })?;
    assert_eq!(health.compacted, 0);
    assert!(raw_payload_present(
        &database,
        outcome.raw_output_digest().as_str()
    )?);
    assert!(matches!(
        runtime.shutdown_terminal_payload_maintenance(),
        Err(TerminalPayloadMaintenanceError::Store(
            chio_kernel::tool_outcome::ToolOutcomeStoreError::Fenced
        ))
    ));
    let stopped = runtime.terminal_payload_maintenance_health();
    assert!(stopped.worker_joined);
    assert!(!stopped.worker_running);
    assert_eq!(
        stopped.lifecycle,
        TerminalPayloadMaintenanceLifecycle::Fenced
    );
    assert!(stopped.last_failure.is_some());
    Ok(())
}

#[test]
fn durable_payload_maintenance_production_ticks_obey_row_budget() -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("paged-maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&runtime, calls.clone())?;
    let mut digests = Vec::new();
    for name in ["page-a", "page-b", "page-c"] {
        let request = request_with_credentials(&kernel, &runtime.kernel_keypair(), name)?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let operation = receipt_operation(&response.receipt)?;
        let outcome = runtime
            .local_authority_store()
            .ok_or("missing authority")?
            .tool_outcome_store()
            .lookup_by_operation(&operation.operation_id)?
            .ok_or("missing outcome")?;
        digests.push(outcome.raw_output_digest().as_str().to_owned());
    }
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let mut config = test_maintenance_config();
    config.page_limits.max_rows = 1;
    runtime.start_terminal_payload_maintenance(config)?;
    let health = wait_for_health(&runtime, |health| {
        if let Some(page) = &health.last_page {
            assert!(page.inspected <= 1);
            assert!(page.compacted <= 1);
        }
        health.compacted >= 3
    })?;
    assert_eq!(health.compacted, 3);
    assert_eq!(health.failures, 0);
    assert!(health.ticks_completed >= 3);
    for digest in digests {
        assert!(!raw_payload_present(&database, &digest)?);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    runtime.shutdown_terminal_payload_maintenance()?;
    Ok(())
}

#[test]
fn durable_payload_maintenance_clones_share_worker_and_drop_joins_before_reopen() -> TestResult {
    let directory = private_tempdir()?;
    let database = directory.path().join("owned-maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let cloned = runtime.clone();
    runtime.start_terminal_payload_maintenance(test_maintenance_config())?;
    wait_for_health(&runtime, |health| health.ticks_completed > 0)?;
    assert!(matches!(
        cloned.start_terminal_payload_maintenance(test_maintenance_config()),
        Err(TerminalPayloadMaintenanceError::AlreadyRunning)
    ));
    drop(runtime);
    assert!(cloned.terminal_payload_maintenance_health().worker_running);
    drop(cloned);
    // There is no settling delay here: the last runtime owner must join its
    // thread and retire the same authority before reopening is permitted.
    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    assert_eq!(
        reopened.terminal_payload_maintenance_health().lifecycle,
        TerminalPayloadMaintenanceLifecycle::MissingConfiguration
    );
    Ok(())
}
