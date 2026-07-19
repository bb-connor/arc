use std::sync::Arc;

use chio_cage::{verify_signed_cage_receipt, CageEnforcementFailureCode, CageEnforcementState};
use chio_control_plane::security::{
    EnterpriseCompositionCoordinator, EnterpriseCompositionMutation,
    EnterpriseCompositionObservation,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::{
    BlockingToolServerAdapter, BlockingToolServerConnection, ChioKernel, KernelConfig,
    MemoryBudgetConfig, ReceiptStore, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use tempfile::TempDir;

const SERVER_ID: &str = "enterprise-composition";
const TOOL_NAME: &str = "invoke";

struct InvocationResult {
    verdict: Verdict,
    reason: Option<String>,
    released_output: bool,
    observation: EnterpriseCompositionObservation,
}

fn config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "b".repeat(64),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn invoke(
    root: &TempDir,
    label: &str,
    mutation: EnterpriseCompositionMutation,
) -> InvocationResult {
    let invocation_directory = root.path().join(label);
    std::fs::create_dir_all(&invocation_directory)
        .unwrap_or_else(|error| panic!("create invocation directory: {error}"));
    let invocation_directory = std::fs::canonicalize(&invocation_directory)
        .unwrap_or_else(|error| panic!("canonicalize invocation directory: {error}"));
    let receipt_path = invocation_directory.join("receipts.sqlite");
    let store = Arc::new(
        SqliteReceiptStore::open(&receipt_path)
            .unwrap_or_else(|error| panic!("open receipt store: {error}")),
    );
    let keypair = Keypair::from_seed(&[81; 32]);
    let signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(keypair.clone()));
    let mut kernel = ChioKernel::new(config(keypair.clone()));
    kernel
        .set_receipt_store_handle(store.clone() as Arc<dyn ReceiptStore>)
        .unwrap_or_else(|error| panic!("install receipt store: {error}"));
    let subject = Keypair::from_seed(&[82; 32]);
    let mut capability = kernel
        .issue_capability(&subject.public_key(), scope(), 300)
        .unwrap_or_else(|error| panic!("issue enterprise capability: {error}"));
    let coordinator = Arc::new(
        EnterpriseCompositionCoordinator::new(
            invocation_directory.join("broker"),
            capability.id.clone(),
            mutation,
            store.clone() as Arc<dyn ReceiptStore>,
            signer,
            keypair.public_key(),
        )
        .unwrap_or_else(|error| panic!("construct composition coordinator: {error}")),
    );
    let adapter = BlockingToolServerAdapter::new(
        coordinator.clone() as Arc<dyn BlockingToolServerConnection>
    )
    .unwrap_or_else(|error| panic!("construct blocking tool adapter: {error}"));
    kernel.register_tool_server(Box::new(adapter));
    if mutation == EnterpriseCompositionMutation::CapabilityValidation {
        capability.id.push_str("-tampered");
    }
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: format!("enterprise-composition-{label}"),
            capability: capability.clone(),
            tool_name: TOOL_NAME.to_string(),
            server_id: SERVER_ID.to_string(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({"operation": "enterprise-composition"}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap_or_else(|error| panic!("evaluate enterprise invocation: {error}"));
    assert!(response
        .receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("verify outer receipt: {error}")));
    let reopened = SqliteReceiptStore::open(&receipt_path)
        .unwrap_or_else(|error| panic!("reopen receipt store: {error}"));
    let outer = reopened
        .load_chio_receipt(&response.receipt.id)
        .unwrap_or_else(|error| panic!("reload outer receipt: {error}"))
        .unwrap_or_else(|| panic!("outer receipt is missing"));
    assert_eq!(
        canonical_json_bytes(&outer)
            .unwrap_or_else(|error| panic!("encode reloaded outer receipt: {error}")),
        canonical_json_bytes(&response.receipt)
            .unwrap_or_else(|error| panic!("encode outer receipt: {error}"))
    );
    let observation = coordinator
        .observation()
        .unwrap_or_else(|error| panic!("read composition observation: {error}"));
    let mut observed_cage_failure_code = None;
    for receipt_id in &observation.native_receipt_ids {
        let native = reopened
            .load_chio_receipt(receipt_id)
            .unwrap_or_else(|error| panic!("reload native receipt: {error}"))
            .unwrap_or_else(|| panic!("native receipt {receipt_id} is missing"));
        assert!(native
            .verify_signature()
            .unwrap_or_else(|error| panic!("verify native receipt: {error}")));
        if let Ok(cage) = verify_signed_cage_receipt(&native) {
            observed_cage_failure_code =
                cage.enforcement_record.failure.map(|failure| failure.code);
        }
    }
    assert_eq!(observed_cage_failure_code, observation.cage_failure_code);
    if let Some(unpersisted) = &observation.unpersisted_signed_receipt {
        assert!(unpersisted
            .verify_signature()
            .unwrap_or_else(|error| panic!("verify unpersisted receipt: {error}")));
        let cage = verify_signed_cage_receipt(unpersisted)
            .unwrap_or_else(|error| panic!("verify unpersisted cage receipt: {error}"));
        assert_eq!(
            cage.enforcement_record.state,
            CageEnforcementState::FullyEnforced
        );
        assert!(cage.enforcement_record.fully_enforced.is_some());
        assert!(cage.enforcement_record.failure.is_none());
        assert!(reopened
            .load_chio_receipt(&unpersisted.id)
            .unwrap_or_else(|error| panic!("query unpersisted receipt: {error}"))
            .is_none());
    }
    InvocationResult {
        verdict: response.verdict,
        reason: response.reason,
        released_output: response.output.is_some(),
        observation,
    }
}

#[test]
fn enterprise_invocation_composes_all_controls_and_mutations_fail_closed() {
    let root = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));

    let success = invoke(&root, "success", EnterpriseCompositionMutation::None);
    assert_eq!(
        success.verdict,
        Verdict::Allow,
        "nominal enterprise composition denied: {:?}",
        success.reason
    );
    assert!(success.released_output);
    assert_eq!(success.observation.invocation_count, 1);
    assert_eq!(success.observation.broker_dispatch_count, 1);
    assert_eq!(success.observation.native_receipt_ids.len(), 2);
    assert!(success.observation.broker_terminal_receipt_id.is_some());
    assert!(success.observation.broker_terminal_was_reloaded);
    assert!(success.observation.broker_terminal_replay_equal);

    let capability = invoke(
        &root,
        "capability",
        EnterpriseCompositionMutation::CapabilityValidation,
    );
    assert_eq!(capability.verdict, Verdict::Deny);
    assert!(!capability.released_output);
    assert_eq!(capability.observation.invocation_count, 0);
    assert_eq!(capability.observation.broker_dispatch_count, 0);
    assert!(capability.observation.broker_terminal_receipt_id.is_none());
    assert!(capability.observation.native_receipt_ids.is_empty());

    let broker = invoke(
        &root,
        "broker",
        EnterpriseCompositionMutation::BrokerExecution,
    );
    assert_eq!(broker.verdict, Verdict::Deny);
    assert!(!broker.released_output);
    assert_eq!(broker.observation.invocation_count, 1);
    assert_eq!(broker.observation.broker_dispatch_count, 0);
    assert_eq!(broker.observation.native_receipt_ids.len(), 1);
    assert!(broker.observation.broker_terminal_receipt_id.is_some());
    assert!(broker.observation.broker_terminal_was_reloaded);
    assert!(broker.observation.broker_terminal_replay_equal);

    let cage = invoke(
        &root,
        "cage",
        EnterpriseCompositionMutation::CageEnforcement,
    );
    assert_eq!(cage.verdict, Verdict::Deny);
    assert!(!cage.released_output);
    assert_eq!(cage.observation.invocation_count, 1);
    assert_eq!(cage.observation.broker_dispatch_count, 0);
    assert_eq!(cage.observation.native_receipt_ids.len(), 2);
    assert!(cage.observation.broker_terminal_receipt_id.is_some());
    assert!(cage.observation.broker_terminal_was_reloaded);
    assert!(cage.observation.broker_terminal_replay_equal);
    assert_eq!(
        cage.observation.cage_failure_code,
        Some(CageEnforcementFailureCode::UnsupportedKernel)
    );

    let persistence = invoke(
        &root,
        "persistence",
        EnterpriseCompositionMutation::ReceiptPersistence,
    );
    assert_eq!(persistence.verdict, Verdict::Deny);
    assert!(!persistence.released_output);
    assert_eq!(persistence.observation.invocation_count, 1);
    assert_eq!(persistence.observation.broker_dispatch_count, 1);
    assert!(persistence.observation.native_receipt_ids.is_empty());
    assert!(persistence.observation.broker_terminal_receipt_id.is_some());
    assert!(persistence.observation.broker_terminal_was_reloaded);
    assert!(persistence.observation.broker_terminal_replay_equal);
    assert!(persistence.observation.unpersisted_signed_receipt.is_some());
}
