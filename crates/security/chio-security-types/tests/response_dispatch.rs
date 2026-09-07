#![cfg(feature = "std")]

use chio_security_types::ports::{
    ActionId, Digest32, LeaseOwnerId, RecordId, ResponseDispatchApproval,
    ResponseDispatchAuthorizationBody, ResponseDispatchKey, ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecoveryOutcome, ResponseDispatchRecoveryRequest,
    ScheduledWork, TenantId, RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::ResponseExecutionDispatchBinding;

fn record_id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn tenant_id(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("invalid tenant id: {error}"))
}

fn action_id(value: &str) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("invalid action id: {error}"))
}

#[test]
fn dispatch_authorization_binds_every_security_identity() {
    let key = ResponseDispatchKey {
        tenant_id: tenant_id("tenant-dispatch"),
        dispatch_id: record_id("dispatch-response"),
    };
    let authorization = ResponseDispatchAuthorizationBody {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        key: key.clone(),
        action_id: action_id("action-response"),
        plan_hash: Digest32::new([1; 32]),
        response_body_hash: Digest32::new([2; 32]),
        authorization_capability_hash: Digest32::new([3; 32]),
        governed_intent_hash: Digest32::new([4; 32]),
        policy_decision_hash: Digest32::new([5; 32]),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 7,
        authorized_at_unix_ms: 40_000,
        approval: ResponseDispatchApproval::Governed {
            admission_operation_id: record_id("admission-operation"),
            admission_operation_version: 9,
            approval_set_hash: Digest32::new([6; 32]),
        },
    };

    assert_eq!(authorization.key, key);
    assert_eq!(authorization.executor_authority_generation, 7);
    assert!(matches!(
        authorization.approval,
        ResponseDispatchApproval::Governed {
            admission_operation_version: 9,
            ..
        }
    ));

    let mut encoded = serde_json::to_value(&authorization)
        .unwrap_or_else(|error| panic!("authorization serialization failed: {error}"));
    encoded["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseDispatchAuthorizationBody>(encoded).is_err());
}

fn execution_dispatch_binding() -> ResponseExecutionDispatchBinding {
    ResponseExecutionDispatchBinding {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        tenant_id: tenant_id("tenant-dispatch"),
        dispatch_id: record_id("dispatch-response"),
        action_id: action_id("action-response"),
        plan_hash: Digest32::new([1; 32]),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 7,
        authorization_capability_hash: Digest32::new([3; 32]),
        governed_intent_hash: Digest32::new([4; 32]),
        policy_decision_hash: Digest32::new([5; 32]),
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: 40_000,
    }
}

#[test]
fn execution_dispatch_binding_rejects_zero_and_mismatched_authority_fields() {
    let tenant = tenant_id("tenant-dispatch");
    let action = action_id("action-response");
    let plan_hash = Digest32::new([1; 32]);
    let valid = execution_dispatch_binding();
    assert!(valid
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_ok());

    let mut wrong_tenant = valid.clone();
    wrong_tenant.tenant_id = tenant_id("tenant-other");
    assert!(wrong_tenant
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    let mut zero_generation = valid.clone();
    zero_generation.executor_authority_generation = 0;
    assert!(zero_generation
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    let mut zero_dispatch = valid.clone();
    zero_dispatch.dispatch_id = record_id(&format!("active_response_dispatch_{}", "0".repeat(64)));
    assert!(zero_dispatch
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    let mut zero_uuid_dispatch = valid.clone();
    zero_uuid_dispatch.dispatch_id = record_id("00000000-0000-0000-0000-000000000000");
    assert!(zero_uuid_dispatch
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    let mut zero_authority = valid.clone();
    zero_authority.executor_authority_id =
        record_id(&format!("executor-authority_{}", "0".repeat(64)));
    assert!(zero_authority
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    let zero_mutations: [fn(&mut ResponseExecutionDispatchBinding); 3] = [
        |binding: &mut ResponseExecutionDispatchBinding| {
            binding.authorization_capability_hash = Digest32::new([0; 32]);
        },
        |binding: &mut ResponseExecutionDispatchBinding| {
            binding.governed_intent_hash = Digest32::new([0; 32]);
        },
        |binding: &mut ResponseExecutionDispatchBinding| {
            binding.policy_decision_hash = Digest32::new([0; 32]);
        },
    ];
    for mutate in zero_mutations {
        let mut binding = valid.clone();
        mutate(&mut binding);
        assert!(binding
            .validate_for_response(&tenant, &action, &plan_hash, 50_000)
            .is_err());
    }

    let mut invalid_governed = valid;
    invalid_governed.approval = ResponseDispatchApproval::Governed {
        admission_operation_id: record_id("admission-operation"),
        admission_operation_version: 0,
        approval_set_hash: Digest32::new([6; 32]),
    };
    assert!(invalid_governed
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());
    if let ResponseDispatchApproval::Governed {
        admission_operation_version,
        approval_set_hash,
        ..
    } = &mut invalid_governed.approval
    {
        *admission_operation_version = 1;
        *approval_set_hash = Digest32::new([0; 32]);
    }
    assert!(invalid_governed
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());

    if let ResponseDispatchApproval::Governed {
        admission_operation_id,
        approval_set_hash,
        ..
    } = &mut invalid_governed.approval
    {
        *admission_operation_id = record_id("00000000-0000-0000-0000-000000000000");
        *approval_set_hash = Digest32::new([6; 32]);
    }
    assert!(invalid_governed
        .validate_for_response(&tenant, &action, &plan_hash, 50_000)
        .is_err());
}

#[test]
fn dispatch_lease_and_load_outcome_are_explicit() {
    let lease = ResponseDispatchLease {
        lease_owner_id: LeaseOwnerId::new("executor-worker")
            .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
        lease_expires_at_unix_ms: 50_000,
    };
    assert_eq!(lease.lease_expires_at_unix_ms, 50_000);

    let missing = ResponseDispatchLoadOutcome::Missing;
    assert!(matches!(missing, ResponseDispatchLoadOutcome::Missing));
}

#[test]
fn dispatch_recovery_binds_the_exact_action_and_fencing_observation() {
    let request = ResponseDispatchRecoveryRequest {
        key: ResponseDispatchKey {
            tenant_id: tenant_id("tenant-dispatch"),
            dispatch_id: record_id("dispatch-response"),
        },
        action_id: action_id("action-response"),
        recovery_id: record_id("recovery-response"),
        lease_owner_id: LeaseOwnerId::new("executor-worker")
            .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
        expected_fencing_token: Some(8),
        now_unix_ms: 40_000,
        lease_expires_at_unix_ms: 50_000,
    };
    let mut encoded = serde_json::to_value(&request)
        .unwrap_or_else(|error| panic!("recovery serialization failed: {error}"));
    encoded["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseDispatchRecoveryRequest>(encoded).is_err());

    let outcome = ResponseDispatchRecoveryOutcome::Takeover(ScheduledWork {
        tenant_id: request.key.tenant_id,
        action_id: request.action_id,
        lease_owner_id: request.lease_owner_id,
        lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
        fencing_token: 9,
    });
    assert!(matches!(
        outcome,
        ResponseDispatchRecoveryOutcome::Takeover(ScheduledWork {
            fencing_token: 9,
            ..
        })
    ));
}
