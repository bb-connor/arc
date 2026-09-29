#[cfg(test)]
mod authority_tests;
mod committed_readback;
mod config;
mod request;

use self::config::{readiness, validate_lease_duration};
use self::request::{ActiveResponseRequestSource, RawActiveResponseExecutionRequest};
use super::active_response_validation::{
    decode_lower_hex_digest, digest_is_zero, has_durable_execution_proof, recovery_id,
    valid_prefixed_digest_id,
};
use chio_kernel::{
    derive_active_response_dispatch_id, ActiveResponseCommittedDispatch,
    ActiveResponseEffectEvidence, ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionEvidenceParts, ActiveResponseExecutionOrigin,
    ActiveResponseExecutionOutcome, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, ActiveResponseFailedEffectEvidence, ActiveResponseFailureEvidence,
    ActiveResponseReceiptProofSource, AutomaticActiveResponseDispatchFenceOutcome,
};
use chio_quarantine::{decode_response_record, DurableActiveResponseOutcome, ResponseExecutor};
use chio_security_kernel::Clock;
use chio_security_types::ports::{
    AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRequest, Digest32,
    EffectPort, LeaseOwnerId, PortErrorKind, PreparedActiveResponseDispatchBinding, RecordId,
    ResponseDispatchApproval, ResponseDispatchCommitOutcome, ResponseDispatchKey,
    ResponseDispatchLease, ResponseDispatchLoadOutcome, ResponseDispatchRecord,
    ResponseDispatchRecoveryOutcome, ResponseDispatchRecoveryRequest, ResponseDispatchStore,
    ResponsePlanKey, ResponsePlanRecord, ScheduledWork, SchedulerWorkKey, SecurityAlertPort,
    SecurityReceiptSink, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{ResponseApprovalRequirement, ResponsePlan, ResponseState};
use std::sync::Arc;
use thiserror::Error;

pub const MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS: u64 = 60_000;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DurableActiveResponseExecutorConfigError {
    #[error("active-response execution lease duration must be nonzero")]
    ZeroLeaseDuration,
    #[error("active-response execution lease duration {actual_ms} exceeds maximum {maximum_ms}")]
    LeaseDurationTooLong { actual_ms: u64, maximum_ms: u64 },
    #[error("active-response executor authority identifier is invalid")]
    InvalidAuthorityId,
}

pub struct DurableActiveResponseExecutor<
    S: ResponseDispatchStore + ?Sized,
    E: EffectPort + ?Sized,
    R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
    A: SecurityAlertPort + ?Sized,
> {
    identity: ActiveResponseExecutorAuthorityIdentity,
    lease_owner_id: LeaseOwnerId,
    store: Arc<S>,
    effects: Arc<E>,
    receipts: Arc<R>,
    alerts: Arc<A>,
    clock: Arc<dyn Clock>,
    lease_duration_ms: u64,
    response_executor: ResponseExecutor<S, E, R, A>,
}
mod executor;
#[cfg(test)]
#[path = "active_response/tests.rs"]
mod tests;
