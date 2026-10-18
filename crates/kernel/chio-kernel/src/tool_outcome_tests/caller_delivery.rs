use super::*;

#[test]
fn caller_report_outcome_requires_delivery_evidence() {
    let operation = committed_operation("caller-report-evidence");
    let mut persisted = raw_for(&operation, json!({"returned": true})).to_persisted();
    persisted.provider_attempt.transport_id = "caller-report:executor-1".to_owned();
    assert_eq!(
        RawInvocationOutcomeV1::from_persisted(persisted),
        Err(ToolOutcomeError::Binding("raw.caller_delivery_evidence"))
    );
}

#[test]
fn noncaller_outcome_refuses_caller_delivery_evidence() {
    use crate::caller_delivery::{
        CallerCommittedDispatchV1, CallerDeliveryEvidenceV1, CallerDeliveryReportBodyV1,
        CallerDispatchAuthorizationBodyV1, CallerExecutorIdentityV1, CallerInvocationBindingV1,
        SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1,
        CALLER_DELIVERY_REPORT_SCHEMA, CALLER_DISPATCH_AUTHORIZATION_SCHEMA,
    };
    let operation = committed_operation("noncaller-delivery-evidence");
    let mut raw = raw_for(&operation, json!({"returned": true}));
    let kernel = Keypair::from_seed(&[41; 32]);
    let executor_key = Keypair::from_seed(&[42; 32]);
    let executor = CallerExecutorIdentityV1 {
        executor_id: id("caller-worker"),
        public_key: executor_key.public_key(),
        key_epoch: 7,
    };
    let mut dispatch_commit = operation.dispatch_commit().unwrap().clone();
    dispatch_commit
        .provider_attempt
        .as_mut()
        .unwrap()
        .transport_id = "caller-report:server".into();
    let authorization = SignedCallerDispatchAuthorizationV1::sign(
        CallerDispatchAuthorizationBodyV1 {
            schema: CALLER_DISPATCH_AUTHORIZATION_SCHEMA.into(),
            kernel_public_key: kernel.public_key(),
            executor: executor.clone(),
            invocation: CallerInvocationBindingV1 {
                operation_id: operation.binding().operation_id().clone(),
                request_id: operation.binding().request_id().clone(),
                request_binding_hash: operation.binding().request_binding_hash().clone(),
                capability_id: id("capability"),
                capability_digest: admission_digest("capability"),
                server_id: id("server"),
                tool_name: id("tool"),
                parameters_digest: admission_digest("parameters"),
            },
            committed: CallerCommittedDispatchV1 {
                execution_nonce_id: id("nonce"),
                budget_hold_id: id("hold"),
                dispatch_commit,
                frozen_context_digest: admission_digest("context"),
            },
            not_before_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        },
        &kernel,
    )
    .unwrap();
    let report = SignedCallerDeliveryReportV1::sign(
        CallerDeliveryReportBodyV1 {
            schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
            authorization_digest: AdmissionDigest::try_new(
                "authorization",
                sha256_hex(&authorization.canonical_bytes().unwrap()),
            )
            .unwrap(),
            executor,
            claim_id: id("claim"),
            execution_started_at_unix_ms: 1_100,
            completed_at_unix_ms: 1_200,
            output: json!({"returned": true}),
            realized_cost: None,
        },
        &executor_key,
    )
    .unwrap();
    raw.caller_delivery_evidence = Some(Box::new(CallerDeliveryEvidenceV1 {
        authorization,
        report,
    }));
    assert_eq!(
        raw.validate_caller_delivery_evidence(),
        Err(ToolOutcomeError::Binding("raw.caller_delivery_evidence"))
    );
}
