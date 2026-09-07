use chio_kernel::{
    ActiveResponseExecutionApproval, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthorityIdentity,
};
use chio_security_types::ports::RecordId;
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
    pub(super) dispatch_committed_resume: bool,
}

pub(super) trait ActiveResponseRequestSource {
    fn raw_request(&self) -> RawActiveResponseExecutionRequest;
}

impl ActiveResponseRequestSource for ActiveResponseExecutionRequest {
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
            dispatch_committed_resume: self.dispatch_committed_resume(),
        }
    }
}

#[cfg(test)]
impl ActiveResponseRequestSource for RawActiveResponseExecutionRequest {
    fn raw_request(&self) -> RawActiveResponseExecutionRequest {
        self.clone()
    }
}
