extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use chio_core_types::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{PublicKey, Signature, SigningAlgorithm, SigningBackend};
use chio_core_types::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use serde_json::Value;

use crate::capability_verify::CapabilityError;
use crate::clock::FixedClock;
use crate::evaluate::EvaluateInput;
use crate::guard::PortableToolCallRequest;
use crate::normalized::{NormalizedOperation, NormalizedScope, NormalizedToolGrant};
use crate::receipts::ReceiptSigningError;
use crate::scope::resolve_matching_grants;
use crate::{evaluate, sign_receipt, verify_capability, Verdict};

fn public_key(seed: u8) -> PublicKey {
    let mut bytes = [seed; 65];
    bytes[0] = 0x04;
    PublicKey::from_p256_sec1(&bytes)
        .unwrap_or_else(|_| unreachable!("deterministic P-256 key fixture is well-formed"))
}

fn p384_public_key(seed: u8) -> PublicKey {
    let mut bytes = [seed; 97];
    bytes[0] = 0x04;
    PublicKey::from_p384_sec1(&bytes)
        .unwrap_or_else(|_| unreachable!("deterministic P-384 key fixture is well-formed"))
}

fn grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn unsigned_capability(ttl: u64) -> CapabilityToken {
    CapabilityToken {
        id: "cap-public-kani".to_string(),
        issuer: public_key(7),
        subject: public_key(9),
        scope: ChioScope {
            grants: vec![grant("s", "r")],
            ..ChioScope::default()
        },
        issued_at: 10,
        expires_at: 10 + ttl,
        delegation_chain: vec![],
        algorithm: None,
        signature: Signature::from_bytes(&[0; 64]),
    }
}

fn path_arguments(path: &str) -> Value {
    Value::String(path.to_string())
}

fn request(_capability: &CapabilityToken, tool: &str) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: "req-public-kani".to_string(),
        tool_name: tool.to_string(),
        server_id: "s".to_string(),
        agent_id: "agent-public-kani".to_string(),
        arguments: path_arguments("/app/src/main.rs"),
    }
}

fn assume_single_unconstrained_invoke_grant(scope: &ChioScope) {
    kani::assume(scope.grants.len() == 1);
    let grant = &scope.grants[0];
    kani::assume(grant.constraints.is_empty());
    kani::assume(grant.operations.len() == 1);
    kani::assume(grant.operations[0] == Operation::Invoke);
}

fn assume_single_normalized_tool_grant(scope: &NormalizedScope) {
    kani::assume(scope.grants.len() == 1);
    kani::assume(scope.resource_grants.is_empty());
    kani::assume(scope.prompt_grants.is_empty());
    let grant = &scope.grants[0];
    kani::assume(grant.constraints.is_empty());
    kani::assume(grant.operations.len() == 1);
    kani::assume(grant.max_cost_per_invocation.is_none());
    kani::assume(grant.max_total_cost.is_none());
}

#[kani::proof]
fn public_verify_capability_rejects_untrusted_issuer_before_signature() {
    let capability = unsigned_capability(100);
    let clock = FixedClock::new(11);
    let result = verify_capability(&capability, &[], &clock);

    assert!(matches!(result, Err(CapabilityError::UntrustedIssuer)));
    core::mem::forget(capability);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_widened_child() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_value_widened_child() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(100),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(false),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_identity_mismatch() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "other".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_resolve_matching_grants_rejects_out_of_scope_request() {
    let scope = ChioScope {
        grants: vec![grant("s", "r")],
        ..ChioScope::default()
    };
    assume_single_unconstrained_invoke_grant(&scope);
    let arguments = Value::Null;
    let matches = match resolve_matching_grants(&scope, "w", "s", &arguments) {
        Ok(matches) => matches,
        Err(_) => {
            core::mem::forget(arguments);
            core::mem::forget(scope);
            kani::assume(false);
            unreachable!("unconstrained grants do not fail during matching");
        }
    };

    assert!(matches.is_empty());
    core::mem::forget(matches);
    core::mem::forget(arguments);
    core::mem::forget(scope);
}

#[kani::proof]
fn public_resolve_matching_grants_preserves_wildcard_matching() {
    let scope = ChioScope {
        grants: vec![grant("*", "*")],
        ..ChioScope::default()
    };
    assume_single_unconstrained_invoke_grant(&scope);
    let arguments = Value::Null;
    let matches = match resolve_matching_grants(&scope, "w", "s", &arguments) {
        Ok(matches) => matches,
        Err(_) => {
            core::mem::forget(arguments);
            core::mem::forget(scope);
            kani::assume(false);
            unreachable!("unconstrained wildcard grants do not fail");
        }
    };

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].specificity, (0, 0, 0));
    core::mem::forget(matches);
    core::mem::forget(arguments);
    core::mem::forget(scope);
}

#[kani::proof]
fn public_evaluate_rejects_untrusted_issuer_before_dispatch() {
    let capability = unsigned_capability(100);
    let request = request(&capability, "r");
    let clock = FixedClock::new(11);
    let guards: [&dyn crate::Guard; 0] = [];
    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &[],
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert_eq!(verdict.verdict, Verdict::Deny);
    core::mem::forget(request);
    core::mem::forget(capability);
}

struct DeterministicBackend {
    public_key: PublicKey,
}

impl SigningBackend for DeterministicBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        let _ = message;
        Ok(Signature::from_bytes(&[0; 64]))
    }
}

fn receipt_body(kernel_key: PublicKey) -> ChioReceiptBody {
    let action = ToolCallAction {
        parameters: Value::Null,
        parameter_hash: "h".to_string(),
    };
    ChioReceiptBody {
        id: "rcpt-public-kani".to_string(),
        timestamp: 1,
        capability_id: "cap-public-kani".to_string(),
        tool_server: "s".to_string(),
        tool_name: "r".to_string(),
        action,
        decision: Decision::Deny {
            reason: "test".to_string(),
            guard: "kani".to_string(),
        },
        content_hash: "h".to_string(),
        policy_hash: "policy".to_string(),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
    }
}

#[kani::proof]
fn public_sign_receipt_rejects_kernel_key_mismatch_before_signing() {
    let backend = DeterministicBackend {
        public_key: public_key(12),
    };
    let body = receipt_body(p384_public_key(11));

    let result = sign_receipt(body, &backend);
    let rejected = matches!(&result, Err(ReceiptSigningError::KernelKeyMismatch));
    core::mem::forget(result);
    core::mem::forget(backend);
    assert!(rejected);
}

#[kani::proof]
fn public_sign_receipt_accepts_matching_kernel_key() {
    let key = public_key(12);
    let backend = DeterministicBackend {
        public_key: key.clone(),
    };
    let body = receipt_body(key);

    let receipt =
        sign_receipt(body, &backend).unwrap_or_else(|_| unreachable!("matching key signs"));
    assert_eq!(receipt.id, "rcpt-public-kani");
    assert_eq!(receipt.algorithm, Some(SigningAlgorithm::Ed25519));
    assert_eq!(receipt.signature, Signature::from_bytes(&[0; 64]));
    core::mem::forget(receipt);
    core::mem::forget(backend);
}
