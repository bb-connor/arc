use chio_kernel::ActiveResponseExecutorError;
use chio_kernel::{
    ActiveResponseExecutionApproval, ActiveResponseExecutionOrigin, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthorityIdentity,
};
use chio_security_types::ports::{RecordId, ResponseDispatchCommitRequest, ResponseDispatchLease};
use chio_security_types::ResponsePlan;

#[derive(Clone)]
pub(super) struct RawActiveResponseExecutionRequest {
    pub(super) response_plan: ResponsePlan,
    pub(super) dispatch_id: RecordId,
    pub(super) executor_authority: ActiveResponseExecutorAuthorityIdentity,
    pub(super) request_id: String,
    pub(super) plan_body_hash: String,
    pub(super) authorization_capability_hash: String,
    pub(super) governed_intent_hash: String,
    pub(super) policy_decision_hash: String,
    pub(super) approval: ActiveResponseExecutionApproval,
    pub(super) expires_at_unix_ms: u64,
    pub(super) authorized_at_unix_ms: u64,
    pub(super) origin: ActiveResponseExecutionOrigin,
}

pub(super) trait ActiveResponseRequestSource {
    fn raw_request(&self) -> RawActiveResponseExecutionRequest;
    fn prepare_dispatch(
        &self,
        lease: ResponseDispatchLease,
        now: u64,
    ) -> Result<ResponseDispatchCommitRequest, ActiveResponseExecutorError>;
}

impl ActiveResponseRequestSource for ActiveResponseExecutionRequest {
    fn prepare_dispatch(
        &self,
        lease: ResponseDispatchLease,
        now: u64,
    ) -> Result<ResponseDispatchCommitRequest, ActiveResponseExecutorError> {
        self.prepare_dispatch(lease, now)
    }
    fn raw_request(&self) -> RawActiveResponseExecutionRequest {
        RawActiveResponseExecutionRequest {
            response_plan: self.response_plan().clone(),
            dispatch_id: self.dispatch_id().clone(),
            executor_authority: self.executor_authority().clone(),
            request_id: self.request_id().to_string(),
            plan_body_hash: self.plan_body_hash().to_string(),
            authorization_capability_hash: self.authorization_capability_hash().to_string(),
            governed_intent_hash: self.governed_intent_hash().to_string(),
            policy_decision_hash: self.policy_decision_hash().to_string(),
            approval: self.approval().clone(),
            expires_at_unix_ms: self.expires_at_unix_ms(),
            authorized_at_unix_ms: self.authorized_at_unix_ms(),
            origin: self.origin(),
        }
    }
}

#[cfg(test)]
impl ActiveResponseRequestSource for RawActiveResponseExecutionRequest {
    fn prepare_dispatch(
        &self,
        lease: ResponseDispatchLease,
        now: u64,
    ) -> Result<ResponseDispatchCommitRequest, ActiveResponseExecutorError> {
        use chio_kernel::active_response_test_support::{
            execution_request, ExecutionRequestFixture,
        };
        execution_request(ExecutionRequestFixture {
            response_plan: self.response_plan.clone(),
            dispatch_id: self.dispatch_id.clone(),
            executor_authority: self.executor_authority.clone(),
            request_id: self.request_id.clone(),
            plan_body_hash: self.plan_body_hash.clone(),
            authorization_capability_hash: self.authorization_capability_hash.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            policy_decision_hash: self.policy_decision_hash.clone(),
            approval: self.approval.clone(),
            authorized_at_unix_ms: self.authorized_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            origin: self.origin,
        })
        .prepare_dispatch(lease, now)
    }

    fn raw_request(&self) -> RawActiveResponseExecutionRequest {
        self.clone()
    }
}
