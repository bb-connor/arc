use super::*;
use crate::recovery::{AuthenticatedRecoveryActor, RecoveryPermission};
use chio_core::capability::aggregate_invocation::{
    AggregateInvocationBudget, AggregateInvocationScope,
};
use chio_core::capability::attenuation::{
    compute_attenuation_witness, scope_hash, Attenuation, AttenuationProof,
};
use chio_core::capability::caveat::{Caveat, CaveatKind};
use chio_core::capability::scope::{ChioScope, Operation};
use chio_core::capability::token::{
    CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
};
use chio_security_types::clock::FixedClock;
use chio_security_types::recovery::{
    AuthorityDomainId, ProcessId, RecoveryScopeV1, RecoveryTenantId,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The single authority time for every token, delegation and verification
/// built by `recovery_kernel` fixtures.
const FIXTURE_NOW: u64 = 1_700_000_000;

fn recovery_scope(fence: &StoreMutationFence) -> RecoveryScopeV1 {
    RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new(&fence.store_uuid).expect("authority domain"),
        tenant_id: RecoveryTenantId::new("tenant").expect("tenant"),
        process_id: ProcessId::new("process:primary").expect("process"),
    }
}

/// A kernel trusting `issuer` whose durable store holds no recovery
/// deployments, so a capability that passes every actor gate reaches the
/// unsupported deployment refusal. Its authority clock reads `FIXTURE_NOW`.
fn recovery_kernel(issuer: &Keypair) -> ChioKernel {
    let mut config = make_config();
    config.keypair = issuer.clone();
    let mut kernel =
        ChioKernel::new_with_clock(config, std::sync::Arc::new(FixedClock::new(FIXTURE_NOW)));
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store, fence)
        .expect("qualified admission store");
    kernel
}

fn inspect_scope() -> ChioScope {
    make_scope(vec![make_grant("chio.recovery", "inspect")])
}

fn token_body(
    issuer: &Keypair,
    subject: &Keypair,
    id: &str,
    scope: ChioScope,
) -> CapabilityTokenBody {
    let now = FIXTURE_NOW;
    CapabilityTokenBody {
        id: id.into(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: now.saturating_sub(1),
        expires_at: now + 300,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

fn authenticate(
    kernel: &ChioKernel,
    token: &CapabilityToken,
) -> Result<AuthenticatedRecoveryActor, KernelError> {
    kernel.authenticate_recovery_actor(
        &recovery_scope(&admission_test_fence()),
        token,
        RecoveryPermission::Inspect,
    )
}

/// The full capability verifier accepts `token`.
fn verified(kernel: &ChioKernel, token: &CapabilityToken) -> TestResult {
    kernel
        .verify_capability_full_pre_admit_typed(token, None, FIXTURE_NOW)
        .map_err(|error| format!("verifier refused the fixture: {}", error.deny_reason()))?;
    Ok(())
}

/// The verifier accepts `token` and the recovery field gate then denies it.
fn verified_then_denied(kernel: &ChioKernel, token: &CapabilityToken) -> TestResult {
    verified(kernel, token)?;
    match authenticate(kernel, token) {
        Err(KernelError::RecoveryAuthorityDenied) => Ok(()),
        other => Err(format!("expected the recovery authority refusal, got {other:?}").into()),
    }
}

/// The verifier accepts `token` and every actor gate passes it on to the
/// deployment stage.
fn reaches_the_deployment_stage(kernel: &ChioKernel, token: &CapabilityToken) -> TestResult {
    verified(kernel, token)?;
    match authenticate(kernel, token) {
        Err(KernelError::DurableAdmission(reason))
            if reason == "native recovery profile is unsupported" =>
        {
            Ok(())
        }
        other => Err(format!("expected the deployment-stage refusal, got {other:?}").into()),
    }
}

#[test]
fn backend_without_recovery_deployments_refuses_actor_authentication() {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store, fence.clone())
        .expect("qualified admission store");
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("chio.recovery", "inspect")]),
        300,
    );
    let result = kernel.authenticate_recovery_actor(
        &recovery_scope(&fence),
        &capability,
        RecoveryPermission::Inspect,
    );
    assert!(
        matches!(
            &result,
            Err(KernelError::DurableAdmission(reason))
                if reason == "native recovery profile is unsupported"
        ),
        "{result:?}"
    );
}

#[test]
fn kernel_without_a_durable_store_refuses_actor_authentication() {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("chio.recovery", "inspect")]),
        300,
    );
    let result = kernel.authenticate_recovery_actor(
        &recovery_scope(&admission_test_fence()),
        &capability,
        RecoveryPermission::Inspect,
    );
    assert!(
        matches!(
            &result,
            Err(KernelError::DurableAdmission(reason))
                if reason == "qualified admission operation store is unavailable"
        ),
        "{result:?}"
    );
}

/// Positive control for every field isolation below: the same issuer, subject
/// and scope with no prohibited field pass every actor gate.
#[test]
fn plain_signed_capability_reaches_the_deployment_stage() -> TestResult {
    let issuer = make_keypair();
    let agent = make_keypair();
    let kernel = recovery_kernel(&issuer);
    let token = CapabilityToken::sign(
        token_body(&issuer, &agent, "cap-recovery-plain", inspect_scope()),
        &issuer,
    )?;
    reaches_the_deployment_stage(&kernel, &token)
}

#[test]
fn aggregate_invocation_budgets_pass_verification_and_are_denied() -> TestResult {
    let issuer = make_keypair();
    let agent = make_keypair();
    let kernel = recovery_kernel(&issuer);
    let mut capability_budget = token_body(&issuer, &agent, "cap-recovery-budget", inspect_scope());
    capability_budget.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 4,
        root_binding: None,
    });
    let capability_budget = CapabilityToken::sign(capability_budget, &issuer)?;
    verified_then_denied(&kernel, &capability_budget)?;
    let family_root = CapabilityToken::sign_aggregate_family_root(
        token_body(&issuer, &agent, "cap-recovery-family", inspect_scope()),
        4,
        &issuer,
    )?;
    assert!(family_root.aggregate_invocation_budget.is_some());
    verified_then_denied(&kernel, &family_root)
}

/// A plain one-hop delegation carries only a delegation chain. The verifier
/// resolves its signed root from the receipt store's capability snapshot.
#[test]
fn delegated_capability_passes_verification_and_is_denied() -> TestResult {
    let issuer = make_keypair();
    let root_subject = make_keypair();
    let agent = make_keypair();
    let mut kernel = recovery_kernel(&issuer);
    let mut delegable = make_grant("chio.recovery", "inspect");
    delegable.operations.push(Operation::Delegate);
    let root = CapabilityToken::sign(
        token_body(
            &issuer,
            &root_subject,
            "cap-recovery-root",
            make_scope(vec![delegable]),
        ),
        &issuer,
    )?;
    let path = unique_receipt_db_path("chio-recovery-delegated-root");
    let snapshots = SqliteReceiptStore::open(&path)?;
    snapshots.record_capability_snapshot(&root, None)?;
    drop(snapshots);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;
    let now = FIXTURE_NOW;
    let receipt = chio_core::capability::attenuation::delegate(
        &root,
        &root.issuer,
        &inspect_scope(),
        &root_subject,
        &agent.public_key(),
        chio_core_types::ScopeAttenuation::empty(),
        chio_core::capability::attenuation::DelegationStamp {
            signed_at: now,
            nonce: [7_u8; 16],
        },
    )?;
    let mut child = token_body(&issuer, &agent, "cap-recovery-delegated", inspect_scope());
    child.issued_at = now;
    child.delegation_chain = receipt.complete_chain();
    let child = CapabilityToken::sign(child, &issuer)?;
    assert!(child.attenuation_proof.is_none() && child.budget_share_bps.is_none());
    verified_then_denied(&kernel, &child)
}

/// `sign_attenuated` always sets both `scope_attenuations` and
/// `attenuation_proof`, and it is the only signer of `budget_share_bps`, so
/// those three fields cannot occur apart. Each direct-issue token below binds
/// its proof to the issuer's registered trust-root scope.
#[test]
fn attenuated_capability_fields_pass_verification_and_are_denied() -> TestResult {
    let issuer = make_keypair();
    let agent = make_keypair();
    let kernel = recovery_kernel(&issuer);
    let mut delegable = make_grant("chio.recovery", "inspect");
    delegable.operations.push(Operation::Delegate);
    let parent = make_scope(vec![delegable]);
    let child = inspect_scope();
    kernel.set_capability_trust_root(issuer.public_key(), scope_hash(&parent)?);
    let narrowed = vec![Attenuation::RemoveOperation {
        server_id: "chio.recovery".into(),
        tool_name: "inspect".into(),
        operation: Operation::Delegate,
    }];
    let cases: [(&str, Vec<Attenuation>, Option<u16>); 3] = [
        ("cap-recovery-attenuated", Vec::new(), None),
        ("cap-recovery-shared", Vec::new(), Some(4_000)),
        ("cap-recovery-narrowed", narrowed, None),
    ];
    for (id, scope_attenuations, budget_share_bps) in cases {
        let token = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: token_body(&issuer, &agent, id, child.clone()),
                caveats: Vec::new(),
                scope_attenuations,
                attenuation_proof: AttenuationProof {
                    parent_scope_hash: scope_hash(&parent)?,
                    child_scope_hash: scope_hash(&child)?,
                    normalized_subset_proof: compute_attenuation_witness(&parent, &child)?,
                },
                budget_share_bps,
            },
            &issuer,
        )?;
        assert!(token.attenuation_proof.is_some() && token.scope_attenuations.is_some());
        assert_eq!(token.budget_share_bps, budget_share_bps);
        assert!(token.delegation_chain.is_empty() && token.aggregate_invocation_budget.is_none());
        verified_then_denied(&kernel, &token)?;
    }
    Ok(())
}

/// No current signer can produce a caveat: `CapabilityTokenBody` has no
/// caveat field and `sign_attenuated` refuses any caveat before signing.
#[test]
fn caveats_cannot_be_signed_under_the_current_contract() -> TestResult {
    let issuer = make_keypair();
    let agent = make_keypair();
    let scope = inspect_scope();
    let result = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: token_body(&issuer, &agent, "cap-recovery-caveat", scope.clone()),
            caveats: vec![Caveat {
                kind: CaveatKind::RestrictTool,
                predicate: "inspect".into(),
                sig: None,
            }],
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&scope, &scope)?,
            },
            budget_share_bps: None,
        },
        &issuer,
    );
    assert!(
        matches!(
            &result,
            Err(chio_core::error::Error::AttenuationViolation { reason })
                if reason
                    == "capability caveats are not enforced by admission and are rejected fail-closed"
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn unsupported_scope_constraints_are_policy_refusals() -> TestResult {
    use chio_core::capability::scope::Constraint;
    let issuer = make_keypair();
    let agent = make_keypair();
    let kernel = recovery_kernel(&issuer);
    let mut grant = make_grant("other-server", "query");
    grant.constraints = vec![Constraint::TableAllowlist(vec!["public".into()])];
    let scope = make_scope(vec![make_grant("chio.recovery", "inspect"), grant]);
    let token = CapabilityToken::sign(
        token_body(
            &issuer,
            &agent,
            "cap-recovery-unsupported-constraint",
            scope,
        ),
        &issuer,
    )?;
    assert_eq!(
        kernel.verify_capability_full_pre_admit(&token, None, FIXTURE_NOW),
        Err(
            "invalid capability constraint: unsupported capability constraint: TableAllowlist; grant-specific enforcement is unavailable"
                .into()
        )
    );
    assert!(matches!(
        authenticate(&kernel, &token),
        Err(KernelError::RecoveryAuthorityDenied)
    ));
    Ok(())
}

#[test]
fn lifecycle_refusal_text_preserves_the_public_verifier_contract() {
    use crate::kernel::validation::CapabilityPreAdmissionError;
    assert_eq!(
        CapabilityPreAdmissionError::IssuerLifecycle(KernelError::UntrustedIssuer).deny_reason(),
        "capability issuer lifecycle denied: capability issuer is not a trusted CA"
    );
    assert_eq!(
        CapabilityPreAdmissionError::IssuerLifecycle(KernelError::CapabilityIssuanceFailed(
            "authority unavailable".into()
        ))
        .deny_reason(),
        "capability issuer lifecycle denied: capability issuance failed: authority unavailable"
    );
}
