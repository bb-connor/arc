//! Threat test for threat ID `behavioral_sequence_attack`.
//!
//! Coverage strategy: record a dangerous predecessor in the session journal
//! and assert `BehavioralSequenceGuard` denies the configured forbidden
//! transition.
//!
//! Revert-to-prove-it-fails recipe: flip the forbidden-transition deny
//! branch in `crates/guards/chio-guards/src/behavioral_sequence.rs` to return
//! `Verdict::Allow` (or remove the predecessor lookup). The deny-arm
//! assertion below fails when the production guard stops denying the
//! configured forbidden transition.
//!
//! Targeted mutation recipe: replace the `last_tool == from` predicate in the
//! forbidden-transition check with `last_tool != from`. The dangerous edge is
//! then admitted and the deny assertion MUST fail. A different successor from
//! the same predecessor MUST remain admitted.

use std::sync::Arc;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{BehavioralSequenceGuard, SequencePolicy};
use chio_http_session::{RecordParams, SessionJournal};
use chio_kernel::{Guard, GuardContext, GuardDecision, ToolCallRequest, Verdict};

fn request_for(tool_name: &str) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let body = CapabilityTokenBody {
        id: "cap-sequence".to_string(),
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
    let server_id = "srv-sequence".to_string();
    let request = ToolCallRequest {
        request_id: format!("req-{tool_name}"),
        capability: token,
        tool_name: tool_name.to_string(),
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

#[test]
fn threat_behavioral_sequence_attack_is_covered() {
    // covers: behavioral_sequence_attack
    let journal = Arc::new(SessionJournal::new("sess-sequence".to_string()));
    if let Err(error) = journal.record(RecordParams {
        tool_name: "shell_exec".to_string(),
        server_id: "srv-sequence".to_string(),
        agent_id: "agent-a".to_string(),
        bytes_read: 0,
        bytes_written: 0,
        delegation_depth: 0,
        allowed: true,
    }) {
        panic!("journal fixture must record: {error}");
    }

    let guard = BehavioralSequenceGuard::new(
        journal,
        SequencePolicy {
            forbidden_transitions: vec![("shell_exec".to_string(), "write_file".to_string())],
            ..SequencePolicy::default()
        },
    );
    let (benign_request, benign_scope, benign_agent_id, benign_server_id) =
        request_for("read_file");
    let benign_ctx = guard_ctx(
        &benign_request,
        &benign_scope,
        &benign_agent_id,
        &benign_server_id,
    );
    assert_eq!(verdict(guard.evaluate(&benign_ctx)), Verdict::Allow);

    let (dangerous_request, dangerous_scope, dangerous_agent_id, dangerous_server_id) =
        request_for("write_file");
    let dangerous_ctx = guard_ctx(
        &dangerous_request,
        &dangerous_scope,
        &dangerous_agent_id,
        &dangerous_server_id,
    );
    assert_eq!(verdict(guard.evaluate(&dangerous_ctx)), Verdict::Deny);
}
