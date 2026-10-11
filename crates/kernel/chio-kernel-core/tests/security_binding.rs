//! Portable evaluation has no authoritative security-context bridge.
use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core_types::{
    capability::{
        attenuation::scope_hash,
        caveat::{CapabilitySecurityBinding, CAPABILITY_SECURITY_BINDING_SCHEMA},
        crypto_floor::CapabilityCryptoFloor,
        features::CapabilityNegotiation,
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair, PublicKey,
};
use chio_kernel_core::{
    evaluate, evaluate_with_crypto_floor, evaluate_with_crypto_floor_and_budgets,
    evaluate_with_full_floor, evaluate_with_full_floor_and_evidence,
    evaluate_with_full_floor_and_root, verify_capability_full_with_evidence,
    CapabilityEvidenceContext, CapabilityFeatureContext, EvaluateInput, EvaluationVerdict,
    FixedClock, Guard, GuardContext, KernelCoreError, NoopBudgetRegistry, PortableToolCallRequest,
    Verdict,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn body(issuer: &Keypair) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "portable-security-binding".into(),
        issuer: issuer.public_key(),
        subject: issuer.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "workload-server-a".into(),
                tool_name: "inspect".into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: 90,
        expires_at: 110,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

fn bound_token(issuer: &Keypair) -> Result<CapabilityToken> {
    let binding = CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.into(),
        tenant_id: "tenant-a".into(),
        lineage_id: "lineage-a".into(),
        session_id: "session-a".into(),
        principal_id: issuer.public_key().to_hex(),
        isolation_epoch_id: "epoch-a".into(),
        context_generation: 1,
        workload_id: "workload-a".into(),
        server_id: "workload-server-a".into(),
        workload_signer_public_key: issuer.public_key().to_hex(),
    };
    let token = CapabilityToken::sign_with_security_binding(body(issuer), binding.clone(), issuer)?;
    assert!(token.verify_signature()?);
    assert_eq!(token.security_binding()?, Some(binding));
    token.validate_time(100)?;
    Ok(token)
}

#[derive(Default)]
struct CountingGuard(AtomicUsize);

impl Guard for CountingGuard {
    fn name(&self) -> &str {
        "counting-allow"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> std::result::Result<Verdict, KernelCoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Verdict::Allow)
    }
}

fn evaluate_public_entries(
    issuer: &Keypair,
    token: &CapabilityToken,
    guard: &CountingGuard,
) -> Result<Vec<(&'static str, EvaluationVerdict)>> {
    let request = PortableToolCallRequest {
        request_id: "portable-context-projection".into(),
        tool_name: "inspect".into(),
        server_id: "workload-server-a".into(),
        agent_id: issuer.public_key().to_hex(),
        arguments: serde_json::json!({}),
    };
    let clock = FixedClock::new(100);
    let trusted = [issuer.public_key()];
    let guards: [&dyn Guard; 1] = [guard];
    let input = || EvaluateInput {
        request: &request,
        capability: token,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    };
    let peer = CapabilityNegotiation::default();
    let root_hash = scope_hash(&token.scope)?;
    let resolver = |_: &PublicKey| Some(root_hash.clone());
    let floor = CapabilityCryptoFloor::AllowClassical;
    let mut budgets = NoopBudgetRegistry;
    Ok(vec![
        ("evaluate", evaluate(input())),
        ("crypto_floor", evaluate_with_crypto_floor(input(), floor)),
        (
            "crypto_floor_and_budgets",
            evaluate_with_crypto_floor_and_budgets(input(), floor, &mut budgets),
        ),
        (
            "full_floor",
            evaluate_with_full_floor(input(), floor, &peer, &resolver, &mut budgets),
        ),
        (
            "full_floor_and_root",
            evaluate_with_full_floor_and_root(input(), floor, &peer, None, &resolver, &mut budgets),
        ),
        (
            "full_floor_and_evidence",
            evaluate_with_full_floor_and_evidence(
                input(),
                floor,
                CapabilityEvidenceContext {
                    features: CapabilityFeatureContext {
                        peer: &peer,
                        direct_root: None,
                    },
                    ancestors: &[],
                },
                &resolver,
                &mut budgets,
            ),
        ),
    ])
}

#[test]
fn security_binding_projection_denies_all_portable_evaluators_before_guards() -> Result {
    let issuer = Keypair::from_seed(&[43; 32]);
    let token = bound_token(&issuer)?;
    let guard = CountingGuard::default();
    let evaluations = evaluate_public_entries(&issuer, &token, &guard)?;
    let unexpected = evaluations
        .iter()
        .filter(|(_, result)| {
            !result.is_deny()
                || !result
                    .reason
                    .as_ref()
                    .is_some_and(|reason| reason.contains("security context"))
                || result.matched_grant_index.is_some()
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "context-bound capabilities escaped: {unexpected:?}"
    );
    assert_eq!(guard.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn security_binding_projection_preserves_unbound_portable_evaluation() -> Result {
    let issuer = Keypair::from_seed(&[43; 32]);
    let token = CapabilityToken::sign(body(&issuer), &issuer)?;
    assert!(token.verify_signature()?);
    assert!(token.security_binding()?.is_none());
    let guard = CountingGuard::default();
    for (entry, result) in evaluate_public_entries(&issuer, &token, &guard)? {
        assert!(result.is_allow(), "{entry}: {result:?}");
        assert_eq!(result.matched_grant_index, Some(0));
        assert!(result.verified.is_some());
    }
    assert_eq!(guard.0.load(Ordering::SeqCst), 6);
    Ok(())
}

#[test]
fn security_binding_projection_preserves_verification_for_context_aware_native_admission() -> Result
{
    let issuer = Keypair::from_seed(&[43; 32]);
    let token = bound_token(&issuer)?;
    let peer = CapabilityNegotiation::default();
    let root_hash = scope_hash(&token.scope)?;
    let resolver = |_: &PublicKey| Some(root_hash.clone());
    // Native admission retains the original token and independently verifies its
    // authoritative context. This pure cryptographic result is not an Allow.
    let verified = verify_capability_full_with_evidence(
        &token,
        &[issuer.public_key()],
        &FixedClock::new(100),
        CapabilityCryptoFloor::AllowClassical,
        CapabilityEvidenceContext {
            features: CapabilityFeatureContext {
                peer: &peer,
                direct_root: None,
            },
            ancestors: &[],
        },
        &resolver,
        &mut NoopBudgetRegistry,
    )
    .map_err(|error| format!("native pre-admission verification regressed: {error:?}"))?;
    assert_eq!(verified.id(), token.id);
    Ok(())
}
