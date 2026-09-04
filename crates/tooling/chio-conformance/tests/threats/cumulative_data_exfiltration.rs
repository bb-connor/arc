//! Threat test for threat ID `cumulative_data_exfiltration`.
//!
//! Coverage strategy: seed the session journal with cumulative read/write
//! totals and assert `DataFlowGuard` denies once the configured total ceiling
//! has been reached.
//!
//! Revert-to-prove-it-fails recipe: flip the `max_bytes_total`
//! `Ok(Verdict::Deny)` branch in `crates/guards/chio-guards/src/data_flow.rs`
//! to `Ok(Verdict::Allow)`. The deny-arm assertion below fails when
//! the production guard stops denying once the cumulative ceiling is
//! reached.
//!
//! Targeted mutation recipe: replace the `>=` comparison for
//! `max_bytes_total` with `<`. The over-limit request is then admitted and the
//! deny assertion MUST fail. The below-limit positive control MUST remain
//! admitted.

use std::sync::Arc;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{DataFlowConfig, DataFlowGuard};
use chio_http_session::{RecordParams, SessionJournal};
use chio_kernel::{Guard, GuardContext, GuardDecision, ToolCallRequest, Verdict};

fn request_fixture() -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let body = CapabilityTokenBody {
        id: "cap-data-flow".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = match CapabilityToken::sign(body, &kp) {
        Ok(token) => token,
        Err(error) => panic!("capability fixture must sign: {error}"),
    };
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-data-flow".to_string();
    let request = ToolCallRequest {
        request_id: "req-data-flow".to_string(),
        capability: token,
        tool_name: "export_records".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    (request, scope, agent_id, server_id)
}

fn guard_ctx<'a>(
    request: &'a ToolCallRequest,
    scope: &'a ChioScope,
    agent_id: &'a String,
    server_id: &'a String,
) -> GuardContext<'a> {
    GuardContext {
        request,
        scope,
        agent_id,
        server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
        security_context: None,
    }
}

fn verdict(result: Result<GuardDecision, chio_kernel::KernelError>) -> Verdict {
    match result {
        Ok(decision) => decision.verdict,
        Err(error) => panic!("guard evaluation must not error: {error}"),
    }
}

fn journal_with_flow(session_id: &str, bytes_read: u64, bytes_written: u64) -> Arc<SessionJournal> {
    let journal = Arc::new(SessionJournal::new(session_id.to_string()));
    if let Err(error) = journal.record(RecordParams {
        tool_name: "export_records".to_string(),
        server_id: "srv-data-flow".to_string(),
        agent_id: "agent-a".to_string(),
        bytes_read,
        bytes_written,
        delegation_depth: 0,
        allowed: true,
    }) {
        panic!("journal fixture must record: {error}");
    }
    journal
}

#[test]
fn threat_cumulative_data_exfiltration_is_covered() {
    // covers: cumulative_data_exfiltration
    let (request, scope, agent_id, server_id) = request_fixture();
    let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);

    let below_limit = DataFlowGuard::new(
        journal_with_flow("sess-below-exfil-limit", 400, 500),
        DataFlowConfig {
            max_bytes_read: None,
            max_bytes_written: None,
            max_bytes_total: Some(1_000),
        },
    );
    assert_eq!(verdict(below_limit.evaluate(&ctx)), Verdict::Allow);

    let over_limit = DataFlowGuard::new(
        journal_with_flow("sess-over-exfil-limit", 700, 500),
        DataFlowConfig {
            max_bytes_read: None,
            max_bytes_written: None,
            max_bytes_total: Some(1_000),
        },
    );
    assert_eq!(verdict(over_limit.evaluate(&ctx)), Verdict::Deny);
}
