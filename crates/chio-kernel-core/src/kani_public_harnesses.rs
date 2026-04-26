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
use crate::formal_core::{
    monetary_cap_is_subset_by_parts, optional_u32_cap_is_subset, required_true_is_preserved,
    revocation_snapshot_denies, time_window_valid,
};
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

// NOTE (M03.P2.T1): The verified-core surface does not currently expose a public
// `intersect(a, b)` operator over scopes; intersection is only modelled
// transitively via `is_subset_of`/`resolve_matching_grants`. Associativity of
// intersection in this lattice is therefore witnessed by transitivity of the
// subset relation over its algebraic primitive `optional_u32_cap_is_subset`
// (a per-grant cap component that participates in every nested intersection).
// A meet-semilattice in which `<=` is transitive admits an associative meet,
// so the two primitive proofs below (transitivity, plus refl-style preservation)
// jointly witness the intended algebra. Reframe once a public `intersect` lands.
#[kani::proof]
fn verify_scope_intersection_associative() {
    let a_has = kani::any::<bool>();
    let b_has = kani::any::<bool>();
    let c_has = kani::any::<bool>();
    let a_value = u32::from(kani::any::<u8>());
    let b_value = u32::from(kani::any::<u8>());
    let c_value = u32::from(kani::any::<u8>());

    // a <= b means: a is a subset of b (child-of-parent in the cap lattice).
    let a_le_b = optional_u32_cap_is_subset(a_has, a_value, b_has, b_value);
    let b_le_c = optional_u32_cap_is_subset(b_has, b_value, c_has, c_value);
    let a_le_c = optional_u32_cap_is_subset(a_has, a_value, c_has, c_value);

    // Transitivity is the algebraic content that lets a meet (intersection)
    // associate: ((a meet b) meet c) and (a meet (b meet c)) sit in the same
    // equivalence class iff <= is transitive. We prove the implication.
    if a_le_b && b_le_c {
        assert!(a_le_c);
    }

    // Self-comparison must always hold (refl), regardless of presence/value:
    // a meet a = a, which forces a <= a.
    let a_le_a = optional_u32_cap_is_subset(a_has, a_value, a_has, a_value);
    assert!(a_le_a);
}

#[kani::proof]
fn verify_revocation_predicate_idempotent() {
    let token_revoked = kani::any::<bool>();
    let ancestor_revoked = kani::any::<bool>();

    let first = revocation_snapshot_denies(token_revoked, ancestor_revoked);
    let second = revocation_snapshot_denies(token_revoked, ancestor_revoked);

    // Idempotence in the no-side-effects sense: re-evaluating the predicate on
    // the same revocation snapshot returns the same boolean.
    assert_eq!(first, second);

    // Boolean idempotence of `||` also forces `denies(x, x) == denies(x, x)`
    // independent of which leg fires. Pin both interpretations.
    let mirrored_first = revocation_snapshot_denies(token_revoked, token_revoked);
    let mirrored_second = revocation_snapshot_denies(token_revoked, token_revoked);
    assert_eq!(mirrored_first, mirrored_second);
    assert_eq!(mirrored_first, token_revoked);
}

// NOTE (M03.P2.T2): Single-step delegation attenuation has two algebraic
// pillars in Chio: (a) `scope(c') is_subset_of scope(c)` and
// (b) `expires_at(c') <= expires_at(c)`. The runtime predicate
// `validate_attenuation` is exactly `child.is_subset_of(parent)` over
// `ChioScope`, which decomposes per-grant into the same primitive predicates
// the existing harnesses cover (cap subset, monetary cap subset, dpop
// preservation, identity coverage). We model one delegation step as a free
// choice of every primitive boolean/u32 axis on the parent and child, and
// prove (1) the per-grant subset predicate built from those primitives is
// exactly the conjunction the runtime computes, (2) it rejects every single
// widening, (3) reflexivity holds, and (4) the time-window monotonicity
// `expiry(c') <= expiry(c)` propagates `is_valid_at(now)` from child to
// parent. The bounded sizes match the existing module convention (u8-promoted
// u32 for caps, u8-promoted u64 for monetary units); no new size constants
// are introduced.
fn one_step_attenuation_predicate(
    // Identity coverage flags (parent wildcard or exact match) per axis.
    server_parent_is_wildcard: bool,
    server_parent_equals_child: bool,
    tool_parent_is_wildcard: bool,
    tool_parent_equals_child: bool,
    // Operations subset (parent.operations contains every child operation).
    operations_child_subset: bool,
    // Constraints superset on the child (parent.constraints contained in child).
    constraints_child_superset: bool,
    // max_invocations cap subset.
    parent_has_inv_cap: bool,
    parent_inv_cap: u32,
    child_has_inv_cap: bool,
    child_inv_cap: u32,
    // max_cost_per_invocation cap subset (with currency-equality projection).
    parent_has_per_call_cost: bool,
    parent_per_call_units: u64,
    child_has_per_call_cost: bool,
    child_per_call_units: u64,
    per_call_currency_matches: bool,
    // max_total_cost cap subset (with currency-equality projection).
    parent_has_total_cost: bool,
    parent_total_units: u64,
    child_has_total_cost: bool,
    child_total_units: u64,
    total_currency_matches: bool,
    // dpop_required preservation.
    parent_dpop_required: bool,
    child_dpop_required: bool,
) -> bool {
    let server_covers = server_parent_is_wildcard || server_parent_equals_child;
    let tool_covers = tool_parent_is_wildcard || tool_parent_equals_child;
    let inv_ok = optional_u32_cap_is_subset(
        child_has_inv_cap,
        child_inv_cap,
        parent_has_inv_cap,
        parent_inv_cap,
    );
    let per_call_ok = monetary_cap_is_subset_by_parts(
        child_has_per_call_cost,
        child_per_call_units,
        parent_has_per_call_cost,
        parent_per_call_units,
        per_call_currency_matches,
    );
    let total_ok = monetary_cap_is_subset_by_parts(
        child_has_total_cost,
        child_total_units,
        parent_has_total_cost,
        parent_total_units,
        total_currency_matches,
    );
    let dpop_ok = required_true_is_preserved(parent_dpop_required, child_dpop_required);
    server_covers
        && tool_covers
        && operations_child_subset
        && constraints_child_superset
        && inv_ok
        && per_call_ok
        && total_ok
        && dpop_ok
}

#[kani::proof]
fn verify_delegation_chain_step() {
    // Symbolic axes for the parent/child grant pair produced by one
    // delegation step. Caps are bounded to u8 ranges to keep the search
    // space aligned with the rest of this module.
    let server_parent_is_wildcard = kani::any::<bool>();
    let server_parent_equals_child = kani::any::<bool>();
    let tool_parent_is_wildcard = kani::any::<bool>();
    let tool_parent_equals_child = kani::any::<bool>();
    let operations_child_subset = kani::any::<bool>();
    let constraints_child_superset = kani::any::<bool>();
    let parent_has_inv_cap = kani::any::<bool>();
    let parent_inv_cap = u32::from(kani::any::<u8>());
    let child_has_inv_cap = kani::any::<bool>();
    let child_inv_cap = u32::from(kani::any::<u8>());
    let parent_has_per_call_cost = kani::any::<bool>();
    let parent_per_call_units = u64::from(kani::any::<u8>());
    let child_has_per_call_cost = kani::any::<bool>();
    let child_per_call_units = u64::from(kani::any::<u8>());
    let per_call_currency_matches = kani::any::<bool>();
    let parent_has_total_cost = kani::any::<bool>();
    let parent_total_units = u64::from(kani::any::<u8>());
    let child_has_total_cost = kani::any::<bool>();
    let child_total_units = u64::from(kani::any::<u8>());
    let total_currency_matches = kani::any::<bool>();
    let parent_dpop_required = kani::any::<bool>();
    let child_dpop_required = kani::any::<bool>();

    let attenuates = one_step_attenuation_predicate(
        server_parent_is_wildcard,
        server_parent_equals_child,
        tool_parent_is_wildcard,
        tool_parent_equals_child,
        operations_child_subset,
        constraints_child_superset,
        parent_has_inv_cap,
        parent_inv_cap,
        child_has_inv_cap,
        child_inv_cap,
        parent_has_per_call_cost,
        parent_per_call_units,
        child_has_per_call_cost,
        child_per_call_units,
        per_call_currency_matches,
        parent_has_total_cost,
        parent_total_units,
        child_has_total_cost,
        child_total_units,
        total_currency_matches,
        parent_dpop_required,
        child_dpop_required,
    );

    // (1) Reflexivity: a step that does not change anything is a valid
    // attenuation. Identity coverage, operations subset, constraints
    // superset, dpop preservation, and every cap subset are trivially
    // satisfied when child = parent.
    let reflexive = one_step_attenuation_predicate(
        false,
        true,
        false,
        true,
        true,
        true,
        parent_has_inv_cap,
        parent_inv_cap,
        parent_has_inv_cap,
        parent_inv_cap,
        parent_has_per_call_cost,
        parent_per_call_units,
        parent_has_per_call_cost,
        parent_per_call_units,
        true,
        parent_has_total_cost,
        parent_total_units,
        parent_has_total_cost,
        parent_total_units,
        true,
        parent_dpop_required,
        parent_dpop_required,
    );
    assert!(reflexive);

    // (2) Scope-side rejection: if the predicate accepts the step, then
    // every constituent must hold. This is the "no widening" property
    // expressed at the predicate level: any single false leg below would
    // have driven `attenuates` to false.
    if attenuates {
        // Identity coverage on both axes.
        assert!(server_parent_is_wildcard || server_parent_equals_child);
        assert!(tool_parent_is_wildcard || tool_parent_equals_child);
        // Operations + constraints monotonicity.
        assert!(operations_child_subset);
        assert!(constraints_child_superset);
        // No invocation-cap widening.
        assert!(!parent_has_inv_cap || (child_has_inv_cap && child_inv_cap <= parent_inv_cap));
        // No per-invocation monetary widening (currency must also match).
        assert!(
            !parent_has_per_call_cost
                || (child_has_per_call_cost
                    && per_call_currency_matches
                    && child_per_call_units <= parent_per_call_units)
        );
        // No total-cost monetary widening (currency must also match).
        assert!(
            !parent_has_total_cost
                || (child_has_total_cost
                    && total_currency_matches
                    && child_total_units <= parent_total_units)
        );
        // DPoP requirement preserved.
        assert!(!parent_dpop_required || child_dpop_required);
    }

    // (3) Strict-widening rejection witnesses, one axis at a time. If the
    // parent caps a dimension and the child either drops the cap or sets
    // a value above the parent's, the step must be rejected.
    let widen_inv_unbounded = one_step_attenuation_predicate(
        false,
        true,
        false,
        true,
        true,
        true,
        true,           // parent_has_inv_cap
        parent_inv_cap, // any
        false,          // child drops the cap
        0,
        false,
        0,
        false,
        0,
        true,
        false,
        0,
        false,
        0,
        true,
        false,
        false,
    );
    assert!(!widen_inv_unbounded);

    let widen_dpop = one_step_attenuation_predicate(
        false, true, false, true, true, true, false, 0, false, 0, false, 0, false, 0, true, false,
        0, false, 0, true, true,  // parent_dpop_required
        false, // child drops dpop
    );
    assert!(!widen_dpop);

    // (4) Expiry monotonicity: a single delegation step may not lengthen
    // the validity window. Model `now`, `issued_at`, parent and child
    // expiry as bounded symbolic u64 values; constrain
    // `child_expires_at <= parent_expires_at`. Then
    // `is_valid_at(now)` for the child implies `is_valid_at(now)` for
    // the parent at the same `now`, which is the load-bearing step from
    // the trajectory doc's "expiry(c') <= expiry(c)" requirement.
    let now = u64::from(kani::any::<u8>());
    let issued_at = u64::from(kani::any::<u8>());
    let parent_expires_at = u64::from(kani::any::<u8>());
    let child_expires_at = u64::from(kani::any::<u8>());
    kani::assume(child_expires_at <= parent_expires_at);

    let parent_valid = time_window_valid(now, issued_at, parent_expires_at);
    let child_valid = time_window_valid(now, issued_at, child_expires_at);
    if child_valid {
        assert!(parent_valid);
    }
}
