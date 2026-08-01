use super::*;

use std::sync::{Arc, Mutex};

use crate::kernel::active_response_policy::{
    ActiveResponsePolicyRequest, ActiveResponsePolicyResolutionError, ActiveResponseRequirement,
    MAX_ACTIVE_RESPONSE_FINDING_AGE_MS,
};

const ACTIVE_RESPONSE_POLICY_VERSION: &str = "policy-version-active-response";
const GOVERNED_RESPONSE_POLICY_ID: &str = "governed-active-response-policy";

fn governed_effect(kind: ResponseEffectKind) -> GovernedResponseEffect {
    match kind {
        ResponseEffectKind::EscalateAlert => {
            panic!("alert-only effects do not enter active-response policy resolution")
        }
        ResponseEffectKind::ThrottleSession => GovernedResponseEffect::ThrottleSession,
        ResponseEffectKind::RestrictEgress => GovernedResponseEffect::RestrictEgress,
        ResponseEffectKind::SuspendSession => GovernedResponseEffect::SuspendSession,
        ResponseEffectKind::SuspendCapabilitySet => GovernedResponseEffect::SuspendCapabilitySet,
        ResponseEffectKind::FreezeIssuance => GovernedResponseEffect::FreezeIssuance,
    }
}

fn policy_fixture(
    kind: ResponseEffectKind,
    approval_requirement: ResponseApprovalRequirement,
) -> ActiveResponseFixture {
    if kind == ResponseEffectKind::SuspendCapabilitySet {
        return active_response_fixture_with_grants_and_approval(
            &[
                ResponseEffectKind::FreezeIssuance,
                ResponseEffectKind::SuspendCapabilitySet,
            ],
            vec![
                GovernedResponseEffect::FreezeIssuance,
                GovernedResponseEffect::SuspendCapabilitySet,
            ],
            vec![
                active_response_grant(GovernedResponseEffect::FreezeIssuance),
                active_response_grant(GovernedResponseEffect::SuspendCapabilitySet),
            ],
            approval_requirement,
        );
    }
    let logical_effect = governed_effect(kind);
    active_response_fixture_with_grants_and_approval(
        &[kind],
        vec![logical_effect],
        vec![active_response_grant(logical_effect)],
        approval_requirement,
    )
}

fn governed_requirement() -> ResponseApprovalRequirement {
    ResponseApprovalRequirement::Governed {
        policy_id: RecordId::new(GOVERNED_RESPONSE_POLICY_ID).expect("governed policy id"),
    }
}

fn resolved_requirement(
    policy_hash: &str,
    policy_version: RecordId,
    approval_requirement: ResponseApprovalRequirement,
    automatic_ttl_ceiling_ms: u64,
) -> ActiveResponseRequirement {
    match approval_requirement {
        ResponseApprovalRequirement::Automatic => ActiveResponseRequirement::automatic(
            policy_hash.to_string(),
            policy_version,
            automatic_ttl_ceiling_ms,
            1_000,
        ),
        ResponseApprovalRequirement::Governed { policy_id } => ActiveResponseRequirement::governed(
            policy_hash.to_string(),
            policy_version,
            policy_id,
            1_000,
        ),
    }
}

fn active_response_requirement_resolver(
    policy_version: RecordId,
    throttle_ceiling_ms: u64,
    restrict_ceiling_ms: u64,
) -> impl Fn(
    &ActiveResponsePolicyRequest,
    &str,
) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError>
       + Send
       + Sync
       + 'static {
    move |request: &ActiveResponsePolicyRequest, policy_hash: &str| {
        let automatic_ttl_ceiling_ms = request
            .ordered_effects()
            .iter()
            .filter_map(|effect| match effect {
                GovernedResponseEffect::ThrottleSession => Some(throttle_ceiling_ms),
                GovernedResponseEffect::RestrictEgress => Some(restrict_ceiling_ms),
                GovernedResponseEffect::SuspendSession
                | GovernedResponseEffect::SuspendCapabilitySet
                | GovernedResponseEffect::FreezeIssuance => None,
            })
            .min()
            .unwrap_or(0);
        let governed = request.ordered_effects().iter().any(|effect| {
            matches!(
                effect,
                GovernedResponseEffect::SuspendSession
                    | GovernedResponseEffect::SuspendCapabilitySet
                    | GovernedResponseEffect::FreezeIssuance
            )
        }) || request.ttl_ms() > automatic_ttl_ceiling_ms;
        let approval_requirement = if governed {
            governed_requirement()
        } else {
            ResponseApprovalRequirement::Automatic
        };
        Ok(resolved_requirement(
            policy_hash,
            policy_version.clone(),
            approval_requirement,
            automatic_ttl_ceiling_ms,
        ))
    }
}

fn install_active_response_policy(
    kernel: &mut ChioKernel,
    policy_version: RecordId,
    throttle_ceiling_ms: u64,
    restrict_ceiling_ms: u64,
) {
    kernel
        .set_active_response_requirement_resolver(Arc::new(active_response_requirement_resolver(
            policy_version,
            throttle_ceiling_ms,
            restrict_ceiling_ms,
        )))
        .expect("active-response policy resolver");
}

fn enable_active_response_plan_feature(
    fixture: &mut ActiveResponseFixture,
) -> Arc<RecordingActiveResponseExecutor> {
    let authority = Arc::new(RecordingActiveResponseExecutor::new(
        fixture.executor.clone(),
        1,
    ));
    fixture
        .kernel
        .set_active_response_executor_authority(authority.clone())
        .expect("active-response executor authority");
    if fixture.kernel.admission_operation_store.is_none() {
        fixture
            .kernel
            .set_admission_operation_store_handle(Arc::new(super::super::ProfiledTestStore::new(
                crate::security_admission_operation::AdmissionOperationStoreProfile::SingleNodeDurable,
            )))
            .expect("durable active-response operation store");
    }
    fixture
        .kernel
        .enable_governed_active_response_plans()
        .expect("active-response plan activation");
    authority
}

fn enable_threshold_feature(kernel: &mut ChioKernel) {
    let policy_hash = "33".repeat(32);
    kernel.config.policy_hash = policy_hash.clone();
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        policy_hash,
        1,
    )
    .expect("threshold requirement");
    kernel
        .set_threshold_approval_requirement_resolver(Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("threshold resolver");
    kernel
        .set_threshold_approval_policy_authority(Keypair::generate().public_key())
        .expect("threshold policy authority");
    kernel
        .set_admission_operation_store_handle(Arc::new(super::super::ProfiledTestStore::new(
            crate::security_admission_operation::AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .expect("durable operation store");
    kernel
        .set_approval_store_handle(Arc::new(super::super::DurableThresholdApprovalStore::new()))
        .expect("durable approval store");
    kernel
        .set_budget_store_handle(Arc::new(super::super::DurableThresholdBudgetStore::new()))
        .expect("durable budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold feature activation");
}

fn verify_policy_fixture(
    fixture: &ActiveResponseFixture,
) -> crate::kernel::active_response_admission::VerifiedActiveResponseBindings {
    fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .expect("immutable active-response authorization")
}

#[test]
fn active_response_rollout_denies_activation_without_a_policy_resolver() {
    let mut kernel = make_kernel(make_config());

    let error = kernel
        .enable_governed_active_response_plans()
        .expect_err("missing active-response policy authority must deny activation");
    assert!(error
        .to_string()
        .contains("active-response requirement resolver"));
    assert!(!kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));
}

#[test]
fn active_response_rollout_denies_activation_without_an_executor_authority() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_active_response_requirement_resolver(Arc::new(
            |_: &ActiveResponsePolicyRequest, policy_hash: &str| {
                Ok(ActiveResponseRequirement::automatic(
                    policy_hash.to_string(),
                    RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).map_err(|error| {
                        ActiveResponsePolicyResolutionError::Invalid(error.to_string())
                    })?,
                    u64::MAX,
                    1_000,
                ))
            },
        ))
        .expect("active-response policy resolver");

    let error = kernel
        .enable_governed_active_response_plans()
        .expect_err("missing executor authority must deny activation");
    assert!(error.to_string().contains("executor authority"));
    assert!(!kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));
}

#[test]
fn active_response_rollout_denies_activation_without_a_finding_authority() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let policy_version = fixture.request.plan_body().policy_version.clone();
    install_active_response_policy(&mut fixture.kernel, policy_version, u64::MAX, u64::MAX);
    let executor = Arc::new(RecordingActiveResponseExecutor::new(
        fixture.executor.clone(),
        1,
    ));
    fixture
        .kernel
        .set_active_response_executor_authority(executor)
        .expect("active-response executor authority");
    fixture.kernel.clear_active_response_finding_authority();

    let error = fixture
        .kernel
        .enable_governed_active_response_plans()
        .expect_err("missing signed-finding authority must deny activation");
    assert!(error.to_string().contains("finding authority"));
}

#[test]
fn active_response_feature_is_masked_when_executor_readiness_or_identity_drifts() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let policy_version = fixture.request.plan_body().policy_version.clone();
    install_active_response_policy(&mut fixture.kernel, policy_version, u64::MAX, u64::MAX);
    let authority = enable_active_response_plan_feature(&mut fixture);
    assert!(fixture
        .kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("ready capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));

    authority.set_ready(false);
    assert!(!fixture
        .kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("unready capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));

    authority.set_ready(true);
    authority.set_subject(Keypair::generate());
    assert!(!fixture
        .kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("identity-drift capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));
}

#[test]
fn active_response_policy_denies_a_wrong_resolved_policy_version() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    install_active_response_policy(
        &mut fixture.kernel,
        RecordId::new("stale-active-response-policy").expect("stale policy version"),
        u64::MAX,
        u64::MAX,
    );
    enable_active_response_plan_feature(&mut fixture);
    let verified = verify_policy_fixture(&fixture);

    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("resolver output for another policy version must deny");
    assert!(error.to_string().contains("policy version"));
}

#[test]
fn active_response_policy_denies_a_wrong_resolved_policy_hash() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let policy_version = fixture.request.plan_body().policy_version.clone();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |_: &ActiveResponsePolicyRequest, _: &str| {
                Ok(resolved_requirement(
                    "stale-active-response-policy-hash",
                    policy_version.clone(),
                    ResponseApprovalRequirement::Automatic,
                    u64::MAX,
                ))
            },
        ))
        .expect("active-response policy resolver");
    enable_active_response_plan_feature(&mut fixture);
    let verified = verify_policy_fixture(&fixture);

    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("resolver output for another policy hash must deny");
    assert!(error.to_string().contains("policy hash"));
}

#[test]
fn active_response_policy_denies_a_stale_policy_resolution() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            |request: &ActiveResponsePolicyRequest, _: &str| {
                Err(ActiveResponsePolicyResolutionError::StalePolicy {
                    expected: "current-active-response-policy".to_string(),
                    received: request.policy_version().as_str().to_string(),
                })
            },
        ))
        .expect("active-response policy resolver");
    enable_active_response_plan_feature(&mut fixture);
    let verified = verify_policy_fixture(&fixture);

    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("stale active-response policy must deny");
    assert!(error.to_string().contains("stale"));
}

#[test]
fn active_response_policy_denies_stale_findings_for_automatic_and_governed_paths() {
    for approval_requirement in [
        ResponseApprovalRequirement::Automatic,
        governed_requirement(),
    ] {
        let mut fixture = active_response_fixture_with_grants_approval_and_finding_age(
            &[ResponseEffectKind::RestrictEgress],
            vec![GovernedResponseEffect::RestrictEgress],
            vec![active_response_grant(
                GovernedResponseEffect::RestrictEgress,
            )],
            approval_requirement.clone(),
            1_001,
        );
        let policy_version = fixture.request.plan_body().policy_version.clone();
        fixture
            .kernel
            .set_active_response_requirement_resolver(Arc::new({
                let approval_requirement = approval_requirement.clone();
                move |_: &ActiveResponsePolicyRequest, policy_hash: &str| {
                    Ok(resolved_requirement(
                        policy_hash,
                        policy_version.clone(),
                        approval_requirement.clone(),
                        u64::MAX,
                    ))
                }
            }))
            .expect("active-response policy resolver");
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        let error = fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .expect_err("stale trigger finding must fail policy resolution");
        assert!(error.to_string().contains("freshness ceiling"));
    }
}

#[test]
fn active_response_policy_rejects_zero_or_unbounded_finding_age_ceiling() {
    for max_finding_age_ms in [0, MAX_ACTIVE_RESPONSE_FINDING_AGE_MS.saturating_add(1)] {
        let mut fixture = policy_fixture(
            ResponseEffectKind::RestrictEgress,
            ResponseApprovalRequirement::Automatic,
        );
        let policy_version = fixture.request.plan_body().policy_version.clone();
        fixture
            .kernel
            .set_active_response_requirement_resolver(Arc::new(
                move |_: &ActiveResponsePolicyRequest, policy_hash: &str| {
                    Ok(ActiveResponseRequirement::automatic(
                        policy_hash.to_string(),
                        policy_version.clone(),
                        u64::MAX,
                        max_finding_age_ms,
                    ))
                },
            ))
            .expect("active-response policy resolver");
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        assert!(fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .is_err());
    }
}

#[test]
fn lightweight_response_effects_below_their_ttl_ceiling_resolve_automatic() {
    for kind in [
        ResponseEffectKind::RestrictEgress,
        ResponseEffectKind::ThrottleSession,
    ] {
        let mut fixture = policy_fixture(kind, ResponseApprovalRequirement::Automatic);
        let ttl_ceiling_ms = fixture.request.plan_body().ttl_ms;
        install_active_response_policy(
            &mut fixture.kernel,
            RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).expect("policy version"),
            ttl_ceiling_ms,
            ttl_ceiling_ms,
        );
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        let resolved = fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .expect("eligible lightweight response");
        assert_eq!(
            resolved.approval_requirement(),
            &ResponseApprovalRequirement::Automatic
        );
    }
}

#[test]
fn lightweight_response_effects_above_their_ttl_ceiling_resolve_governed() {
    for kind in [
        ResponseEffectKind::RestrictEgress,
        ResponseEffectKind::ThrottleSession,
    ] {
        let mut fixture = policy_fixture(kind, governed_requirement());
        let ttl_ceiling_ms = fixture.request.plan_body().ttl_ms.saturating_sub(1);
        install_active_response_policy(
            &mut fixture.kernel,
            RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).expect("policy version"),
            ttl_ceiling_ms,
            ttl_ceiling_ms,
        );
        enable_threshold_feature(&mut fixture.kernel);
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        let resolved = fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .expect("over-ceiling lightweight response");
        assert_eq!(resolved.approval_requirement(), &governed_requirement());
    }
}

#[test]
fn heavy_response_effects_always_resolve_governed() {
    for kind in [
        ResponseEffectKind::SuspendSession,
        ResponseEffectKind::SuspendCapabilitySet,
        ResponseEffectKind::FreezeIssuance,
    ] {
        let mut fixture = policy_fixture(kind, governed_requirement());
        install_active_response_policy(
            &mut fixture.kernel,
            RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).expect("policy version"),
            u64::MAX,
            u64::MAX,
        );
        enable_threshold_feature(&mut fixture.kernel);
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        let resolved = fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .expect("heavy response classification");
        assert_eq!(resolved.approval_requirement(), &governed_requirement());
    }
}

#[test]
fn disabled_governed_active_response_plan_feature_denies_resolution() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    install_active_response_policy(
        &mut fixture.kernel,
        RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).expect("policy version"),
        u64::MAX,
        u64::MAX,
    );
    let verified = verify_policy_fixture(&fixture);

    assert!(!fixture
        .kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local capability negotiation")
        .supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));
    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("disabled active-response feature must deny");
    assert!(error
        .to_string()
        .contains("governed active-response plans were not negotiated"));
}

#[test]
fn governed_response_denies_when_threshold_feature_is_disabled() {
    let mut fixture = policy_fixture(ResponseEffectKind::SuspendSession, governed_requirement());
    install_active_response_policy(
        &mut fixture.kernel,
        RecordId::new(ACTIVE_RESPONSE_POLICY_VERSION).expect("policy version"),
        u64::MAX,
        u64::MAX,
    );
    enable_active_response_plan_feature(&mut fixture);
    let verified = verify_policy_fixture(&fixture);
    let negotiated = fixture
        .kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local capability negotiation");

    assert!(negotiated.supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN));
    assert!(!negotiated.supports(chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS));
    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("governed response without threshold rollout must deny");
    assert!(error
        .to_string()
        .contains("threshold governed approvals were not negotiated"));
}

#[test]
fn policy_resolver_receives_only_the_operator_capability_subject() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let expected_executor = fixture.request.operator_capability().subject.clone();
    let caller_submitter = fixture.request.authenticated_submitter().clone();
    assert_ne!(expected_executor, caller_submitter);
    let observed_executor = Arc::new(Mutex::new(None));
    let observed_for_resolver = Arc::clone(&observed_executor);
    let policy_version = fixture.request.plan_body().policy_version.clone();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |request: &ActiveResponsePolicyRequest, policy_hash: &str| {
                *observed_for_resolver
                    .lock()
                    .expect("observed executor lock") =
                    Some(request.operator_capability_subject().clone());
                Ok(resolved_requirement(
                    policy_hash,
                    policy_version.clone(),
                    ResponseApprovalRequirement::Automatic,
                    u64::MAX,
                ))
            },
        ))
        .expect("active-response policy resolver");
    enable_active_response_plan_feature(&mut fixture);

    // Resolution accepts only kernel-produced verified bindings. The subject
    // is cryptographically bound to the operator capability, but the later
    // dispatch coordinator must still authenticate the live executor.
    let verified = verify_policy_fixture(&fixture);
    fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect("automatic response policy resolution");

    assert_eq!(
        observed_executor
            .lock()
            .expect("observed executor lock")
            .as_ref(),
        Some(&expected_executor)
    );
}

#[test]
fn active_response_policy_request_carries_the_verified_tenant() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let expected_tenant = fixture.request.plan_body().tenant_id.clone();
    let observed_tenant = Arc::new(Mutex::new(None));
    let observed_for_resolver = Arc::clone(&observed_tenant);
    let policy_version = fixture.request.plan_body().policy_version.clone();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |request: &ActiveResponsePolicyRequest, policy_hash: &str| {
                *observed_for_resolver.lock().expect("observed tenant lock") =
                    Some(request.tenant_id().clone());
                Ok(resolved_requirement(
                    policy_hash,
                    policy_version.clone(),
                    ResponseApprovalRequirement::Automatic,
                    u64::MAX,
                ))
            },
        ))
        .expect("active-response policy resolver");
    enable_active_response_plan_feature(&mut fixture);

    let verified = verify_policy_fixture(&fixture);
    fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect("tenant-bound policy resolution");

    assert_eq!(
        observed_tenant
            .lock()
            .expect("observed tenant lock")
            .as_ref(),
        Some(&expected_tenant)
    );
}

#[test]
fn automatic_resolution_denies_when_the_bound_ttl_exceeds_its_ceiling() {
    let mut fixture = policy_fixture(
        ResponseEffectKind::RestrictEgress,
        ResponseApprovalRequirement::Automatic,
    );
    let policy_version = fixture.request.plan_body().policy_version.clone();
    let ceiling = fixture.request.plan_body().ttl_ms.saturating_sub(1);
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |_: &ActiveResponsePolicyRequest, policy_hash: &str| {
                Ok(ActiveResponseRequirement::automatic(
                    policy_hash.to_string(),
                    policy_version.clone(),
                    ceiling,
                    1_000,
                ))
            },
        ))
        .expect("active-response policy resolver");
    enable_active_response_plan_feature(&mut fixture);
    let verified = verify_policy_fixture(&fixture);

    let error = fixture
        .kernel
        .resolve_active_response_requirement(&verified)
        .expect_err("automatic response above the explicit ceiling must deny");
    assert!(error.to_string().contains("TTL"));
}

#[test]
fn active_response_policy_denies_both_declared_requirement_mismatch_directions() {
    let cases = [
        (
            ResponseApprovalRequirement::Automatic,
            governed_requirement(),
        ),
        (
            governed_requirement(),
            ResponseApprovalRequirement::Automatic,
        ),
    ];

    for (declared, resolved) in cases {
        let mut fixture = policy_fixture(ResponseEffectKind::RestrictEgress, declared);
        let policy_version = fixture.request.plan_body().policy_version.clone();
        fixture
            .kernel
            .set_active_response_requirement_resolver(Arc::new(
                move |_: &ActiveResponsePolicyRequest, policy_hash: &str| {
                    Ok(resolved_requirement(
                        policy_hash,
                        policy_version.clone(),
                        resolved.clone(),
                        u64::MAX,
                    ))
                },
            ))
            .expect("active-response policy resolver");
        enable_threshold_feature(&mut fixture.kernel);
        enable_active_response_plan_feature(&mut fixture);
        let verified = verify_policy_fixture(&fixture);

        let error = fixture
            .kernel
            .resolve_active_response_requirement(&verified)
            .expect_err("declared and authoritative requirements must match exactly");
        assert!(error.to_string().contains("approval requirement"));
    }
}
