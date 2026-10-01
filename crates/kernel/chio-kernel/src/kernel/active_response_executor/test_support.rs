//! Explicit test-only construction for executor boundary fault injection.
//! This module is absent without admission-test-support. Production callers
//! cannot construct execution requests; the durable verifier owns that boundary.
use super::*;

pub struct ExecutionRequestFixture {
    pub response_plan: ResponsePlan,
    pub dispatch_id: RecordId,
    pub executor_authority: ActiveResponseExecutorAuthorityIdentity,
    pub request_id: String,
    pub plan_body_hash: String,
    pub authorization_capability_hash: String,
    pub governed_intent_hash: String,
    pub policy_decision_hash: String,
    pub approval: ActiveResponseExecutionApproval,
    pub authorized_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub origin: ActiveResponseExecutionOrigin,
}

pub fn execution_request(fixture: ExecutionRequestFixture) -> ActiveResponseExecutionRequest {
    ActiveResponseExecutionRequest::from_parts(
        ActiveResponseExecutionRequestParts {
            response_plan: fixture.response_plan,
            dispatch_id: fixture.dispatch_id,
            executor_authority: fixture.executor_authority,
            request_id: fixture.request_id,
            plan_body_hash: fixture.plan_body_hash,
            authorization_capability_hash: fixture.authorization_capability_hash,
            governed_intent_hash: fixture.governed_intent_hash,
            policy_decision_hash: fixture.policy_decision_hash,
            approval: fixture.approval,
            authorized_at_unix_ms: fixture.authorized_at_unix_ms,
            expires_at_unix_ms: fixture.expires_at_unix_ms,
        },
        fixture.origin,
    )
}

pub struct CommittedAdmissionFixture {
    pub response_plan: ResponsePlan,
    pub executor_authority: ActiveResponseExecutorAuthorityIdentity,
    pub governed_intent_hash: String,
    pub policy_decision_hash: String,
    pub authorized_at_unix_ms: u64,
}

/// Seed the durable boundary left by an older binary, without constructing a
/// fresh admission or an execution permit. Recovery must still verify the real
/// operation, approval reservation and anchor before it can prepare a dispatch.
pub fn seed_committed_admission(
    kernel: &super::super::ChioKernel,
    fixture: CommittedAdmissionFixture,
    approval_set: &crate::approval::ApprovalSetReservationInput,
) -> Result<
    chio_security_types::ports::PreparedActiveResponseDispatchBinding,
    Box<dyn std::error::Error>,
> {
    use super::super::active_response_operation_binding::{
        active_response_dispatch_operation_version, build_active_response_operation_anchor,
        derive_active_response_operation_request_binding_hash,
    };
    use crate::security_admission_operation::{
        AdmissionDispatchState, AdmissionOperation, AdmissionOperationKind,
        AdmissionOperationState, PreparedAdmissionOperation,
    };
    let plan = &fixture.response_plan;
    plan.require_live_execution()?;
    let policy_hash = chio_core::Hash::from_bytes(*plan.policy_hash.as_bytes()).to_hex();
    let plan_body_hash = chio_core::Hash::from_bytes(*plan.plan_hash.as_bytes()).to_hex();
    let authorization_capability_hash =
        chio_core::Hash::from_bytes(*plan.operator_capability.capability_digest.as_bytes())
            .to_hex();
    let operation = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: fixture.executor_authority.authority_id().to_owned(),
        request_id: plan.action_id.as_str().to_owned(),
        capability_id: plan.operator_capability.capability_id.as_str().to_owned(),
        authorization_capability_hash: authorization_capability_hash.clone(),
        request_binding_hash: derive_active_response_operation_request_binding_hash(
            &plan_body_hash,
            fixture.executor_authority.authority_id(),
            fixture.executor_authority.generation(),
            &authorization_capability_hash,
            &fixture.governed_intent_hash,
            approval_set.approval_set_hash(),
            &policy_hash,
        )?,
        policy_hash,
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some(approval_set.approval_set_hash().to_owned()),
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })?;
    let operations = kernel
        .admission_operation_store
        .as_ref()
        .ok_or("operation store")?;
    operations.create_prepared(operation.clone())?;
    let anchor = build_active_response_operation_anchor(
        plan,
        &fixture.executor_authority,
        fixture.authorized_at_unix_ms,
        &authorization_capability_hash,
        &fixture.governed_intent_hash,
        &fixture.policy_decision_hash,
        approval_set.approval_set_hash(),
    )?;
    kernel.journal_active_response_operation_anchor(&operation, anchor, approval_set)
        .map_err(|error| match error {
            super::super::admission_cleanup::ActiveResponseOperationAnchorJournalError::Conflict =>
                std::io::Error::other("committed anchor conflict"),
            super::super::admission_cleanup::ActiveResponseOperationAnchorJournalError::Kernel(error) =>
                std::io::Error::other(error.to_string()),
        })?;
    kernel
        .approval_store
        .as_ref()
        .ok_or("approval store")?
        .reserve_approval_set(operation.operation_id(), approval_set)?;
    kernel.active_response_cas(
        &operation,
        AdmissionOperationState::ApprovalReserved,
        AdmissionDispatchState::NotStarted,
        None,
    )?;
    let reserved = operations
        .load(operation.operation_id())?
        .ok_or("reserved operation")?;
    kernel.commit_active_response_approval_set(operation.operation_id(), approval_set)?;
    kernel.active_response_cas(
        &reserved,
        AdmissionOperationState::DispatchCommitted,
        AdmissionDispatchState::Committed,
        None,
    )?;
    let committed = operations
        .load(operation.operation_id())?
        .ok_or("committed operation")?;
    let approval = ActiveResponseExecutionApproval::Governed {
        admission_operation_id: operation.operation_id().to_owned(),
        admission_operation_version: active_response_dispatch_operation_version(&committed)?,
        approval_set_hash: approval_set.approval_set_hash().to_owned(),
    };
    let dispatch_id = derive_active_response_dispatch_id(
        plan,
        &fixture.executor_authority,
        &authorization_capability_hash,
        &fixture.governed_intent_hash,
        &fixture.policy_decision_hash,
        fixture.authorized_at_unix_ms,
        &approval,
    )?;
    super::super::PreparedActiveResponseAdmission::Governed(
        super::super::GovernedActiveResponseReservation {
            operation: Box::new(committed),
            approval_set: Box::new(approval_set.clone()),
            policy_decision_hash: fixture.policy_decision_hash,
            authorization_capability_hash,
            governed_intent_hash: fixture.governed_intent_hash,
            executor_authority_id: fixture.executor_authority.authority_id().to_owned(),
            executor_authority_generation: fixture.executor_authority.generation(),
            authorized_at_unix_ms: fixture.authorized_at_unix_ms,
            dispatch_operation_version: active_response_dispatch_operation_version(&reserved)?,
            dispatch_id,
        },
    )
    .durable_dispatch_binding(plan)
    .map_err(Into::into)
}
