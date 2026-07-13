use crate::executor::{ExecutorError, ResponseExecutor};
use crate::state_machine::decode_response_record;
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    ActionId, EffectPort, ErrorCode, LeaseOwnerId, PortError, PortErrorKind, RecordId,
    ResponsePlanKey, ResponsePlanRecord, ResponseSchedulerStore, ScheduledWork,
    SchedulerClaimRequest, SchedulerHealthAckRequest, SchedulerHealthPageRequest,
    SchedulerHealthPort, SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest,
    SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey, SecurityAlert, SecurityAlertPort,
    SecurityReceiptSink, TenantId,
};
use chio_security_types::ResponseState;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

const SCHEDULER_TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-scheduler-transition.v1\0";
const SCHEDULER_HEALTH_EVENT_ID_DOMAIN: &[u8] = b"chio.response-scheduler-health-event.v1\0";
const SCHEDULER_HEALTH_ALERT_HASH_DOMAIN: &[u8] = b"chio.response-scheduler-health-alert.v1\0";

pub trait ScheduledResponseExecutor: Send + Sync {
    fn execute_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError>;
}

impl<
        S: ResponseSchedulerStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > ScheduledResponseExecutor for ResponseExecutor<S, E, R, A>
{
    fn execute_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        self.execute(current, work, now_unix_ms)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerPolicy {
    pub lease_duration_ms: u64,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub operator_page_threshold_ms: u64,
    pub max_claims: u32,
}

impl SchedulerPolicy {
    pub fn validate(self) -> Result<Self, SchedulerError> {
        if self.lease_duration_ms == 0
            || self.base_backoff_ms == 0
            || self.max_backoff_ms < self.base_backoff_ms
            || self.operator_page_threshold_ms <= self.max_backoff_ms
            || self.max_claims == 0
        {
            return Err(SchedulerError::InvalidPolicy);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerTickRequest {
    pub tenant_id: TenantId,
    pub claim_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    pub now_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerWorkOutcome {
    Completed {
        action_id: ActionId,
        state: ResponseState,
    },
    RetryScheduled {
        action_id: ActionId,
        attempts: u32,
        not_before_unix_ms: u64,
        error_code: ErrorCode,
    },
    LeaseLost {
        action_id: ActionId,
    },
    ProcessingFailed {
        action_id: ActionId,
        error_code: ErrorCode,
    },
}

pub struct ResponseScheduler<
    S: ResponseSchedulerStore + ?Sized,
    X: ScheduledResponseExecutor + ?Sized,
    H: SchedulerHealthPort + ?Sized,
> {
    store: Arc<S>,
    executor: Arc<X>,
    health: Arc<H>,
    policy: SchedulerPolicy,
    last_observed_clock: Mutex<BTreeMap<String, u64>>,
}

impl<
        S: ResponseSchedulerStore + ?Sized,
        X: ScheduledResponseExecutor + ?Sized,
        H: SchedulerHealthPort + ?Sized,
    > ResponseScheduler<S, X, H>
{
    pub fn new(
        store: Arc<S>,
        executor: Arc<X>,
        health: Arc<H>,
        policy: SchedulerPolicy,
    ) -> Result<Self, SchedulerError> {
        Ok(Self {
            store,
            executor,
            health,
            policy: policy.validate()?,
            last_observed_clock: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn tick(
        &self,
        request: &SchedulerTickRequest,
    ) -> Result<Vec<SchedulerWorkOutcome>, SchedulerError> {
        self.observe_clock(&request.tenant_id, request.now_unix_ms)?;
        let lease_expires_at_unix_ms = request
            .now_unix_ms
            .checked_add(self.policy.lease_duration_ms)
            .ok_or(SchedulerError::TimeOverflow)?;
        let claimed = self.store.claim_due(&SchedulerClaimRequest {
            tenant_id: request.tenant_id.clone(),
            claim_id: request.claim_id.clone(),
            lease_owner_id: request.lease_owner_id.clone(),
            now_unix_ms: request.now_unix_ms,
            lease_expires_at_unix_ms,
            max_claims: self.policy.max_claims,
        })?;
        let mut outcomes = Vec::with_capacity(claimed.len());
        for work in claimed {
            if work.tenant_id != request.tenant_id
                || work.lease_owner_id != request.lease_owner_id
                || work.lease_expires_at_unix_ms != lease_expires_at_unix_ms
            {
                return Err(SchedulerError::InvalidClaim);
            }
            match self.process(&work, request.now_unix_ms) {
                Ok(outcome) => outcomes.push(outcome),
                Err(SchedulerError::Store(error) | SchedulerError::Health(error)) => {
                    outcomes.push(SchedulerWorkOutcome::ProcessingFailed {
                        action_id: work.action_id,
                        error_code: error.code().clone(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(outcomes)
    }

    pub fn process(
        &self,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<SchedulerWorkOutcome, SchedulerError> {
        self.observe_clock(&work.tenant_id, now_unix_ms)?;
        if let Err(error) = self.store.validate_lease(work) {
            if error.kind() == PortErrorKind::Conflict {
                return Ok(SchedulerWorkOutcome::LeaseLost {
                    action_id: work.action_id.clone(),
                });
            }
            return Err(SchedulerError::Store(error));
        }
        let key = ResponsePlanKey {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
        };
        let Some(current) = self.store.load_plan(&key)? else {
            return self.schedule_retry(
                work,
                now_unix_ms,
                error_code("response.scheduler_plan_missing")?,
            );
        };
        let current_snapshot =
            decode_response_record(&current).map_err(|_| SchedulerError::InvalidExecutionRecord)?;
        match self.executor.execute_scheduled(&current, work, now_unix_ms) {
            Ok(record) => {
                let snapshot = decode_response_record(&record)
                    .map_err(|_| SchedulerError::InvalidExecutionRecord)?;
                if record.tenant_id != current.tenant_id
                    || record.action_id != current.action_id
                    || record.generation < current.generation
                    || snapshot.plan.tenant_id != work.tenant_id
                    || snapshot.plan.action_id != work.action_id
                    || snapshot.plan.plan_hash != current_snapshot.plan.plan_hash
                {
                    return Err(SchedulerError::InvalidExecutionRecord);
                }
                if self.store.load_plan(&key)?.as_ref() != Some(&record) {
                    return Err(SchedulerError::InvalidExecutionRecord);
                }
                match snapshot.state {
                    ResponseState::Active
                    | ResponseState::Cancelled
                    | ResponseState::Expired
                    | ResponseState::Failed
                    | ResponseState::Lifted => {
                        self.release(work, true)?;
                        Ok(SchedulerWorkOutcome::Completed {
                            action_id: work.action_id.clone(),
                            state: snapshot.state,
                        })
                    }
                    ResponseState::RollbackPartial => self.schedule_retry(
                        work,
                        now_unix_ms,
                        error_code("response.rollback_partial")?,
                    ),
                    ResponseState::Planned
                    | ResponseState::AwaitingApproval
                    | ResponseState::Applying
                    | ResponseState::ApplyPartial
                    | ResponseState::Expiring
                    | ResponseState::RollingBack => self.schedule_retry(
                        work,
                        now_unix_ms,
                        error_code("response.execution_incomplete")?,
                    ),
                }
            }
            Err(error) => {
                let code = executor_error_code(&error)?;
                self.schedule_retry(work, now_unix_ms, code)
            }
        }
    }

    pub fn renew(
        &self,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ScheduledWork, SchedulerError> {
        self.observe_clock(&work.tenant_id, now_unix_ms)?;
        self.store.validate_lease(work)?;
        let current = self
            .store
            .load_plan(&ResponsePlanKey {
                tenant_id: work.tenant_id.clone(),
                action_id: work.action_id.clone(),
            })?
            .ok_or(SchedulerError::InvalidExecutionRecord)?;
        let snapshot =
            decode_response_record(&current).map_err(|_| SchedulerError::InvalidExecutionRecord)?;
        if snapshot.state.is_terminal() {
            return Err(SchedulerError::WorkNotActive);
        }
        let lease_expires_at_unix_ms = now_unix_ms
            .checked_add(self.policy.lease_duration_ms)
            .ok_or(SchedulerError::TimeOverflow)?;
        let request = SchedulerLeaseRenewRequest {
            work: work.clone(),
            now_unix_ms,
            lease_expires_at_unix_ms,
            transition_id: scheduler_transition_id(
                "renew",
                work,
                &(now_unix_ms, lease_expires_at_unix_ms),
            )?,
        };
        self.store
            .renew_lease(&request)
            .map_err(SchedulerError::Store)
    }

    pub fn release_for_shutdown(&self, work: &ScheduledWork) -> Result<(), SchedulerError> {
        self.release(work, false)
    }

    fn schedule_retry(
        &self,
        work: &ScheduledWork,
        now_unix_ms: u64,
        error_code: ErrorCode,
    ) -> Result<SchedulerWorkOutcome, SchedulerError> {
        let key = SchedulerWorkKey {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
        };
        let previous = self.store.load_retry(&key)?;
        let expected_attempts = previous.as_ref().map(|retry| retry.attempts).unwrap_or(0);
        let first_failure_at_unix_ms = previous
            .as_ref()
            .map(|retry| retry.first_failure_at_unix_ms)
            .unwrap_or(now_unix_ms);
        if first_failure_at_unix_ms > now_unix_ms
            || previous.as_ref().is_some_and(|retry| {
                retry.health_event_delivered && retry.health_event_id.is_none()
            })
        {
            return Err(SchedulerError::InvalidRetryState);
        }
        let health_event_id = match previous
            .as_ref()
            .and_then(|retry| retry.health_event_id.clone())
        {
            Some(event_id) => Some(event_id),
            None if now_unix_ms.saturating_sub(first_failure_at_unix_ms)
                >= self.policy.operator_page_threshold_ms =>
            {
                Some(scheduler_health_event_id(&key, first_failure_at_unix_ms)?)
            }
            None => None,
        };
        let delay = bounded_backoff(self.policy, expected_attempts);
        let not_before_unix_ms = now_unix_ms
            .checked_add(delay)
            .ok_or(SchedulerError::TimeOverflow)?;
        let request = SchedulerRetryRequest {
            work: work.clone(),
            expected_attempts,
            error_code: error_code.clone(),
            first_failure_at_unix_ms,
            now_unix_ms,
            not_before_unix_ms,
            health_event_id: health_event_id.clone(),
            transition_id: scheduler_transition_id(
                "retry",
                work,
                &(
                    expected_attempts,
                    &error_code,
                    first_failure_at_unix_ms,
                    not_before_unix_ms,
                    &health_event_id,
                ),
            )?,
        };
        let retry = self.store.record_retry(&request)?;
        self.deliver_health_event(&retry)?;
        Ok(retry_outcome(retry))
    }

    fn deliver_health_event(&self, retry: &SchedulerRetryState) -> Result<(), SchedulerError> {
        if retry.health_event_delivered {
            return Ok(());
        }
        let Some(event_id) = retry.health_event_id.as_ref() else {
            return Ok(());
        };
        let request = scheduler_health_page_request(retry, event_id)?;
        self.health
            .page_once(&request)
            .map_err(SchedulerError::Health)?;
        self.store
            .acknowledge_health_event(&SchedulerHealthAckRequest {
                key: retry.key.clone(),
                event_id: event_id.clone(),
                transition_id: scheduler_health_ack_id(&retry.key, event_id)?,
            })?;
        Ok(())
    }

    fn release(&self, work: &ScheduledWork, clear_retry_state: bool) -> Result<(), SchedulerError> {
        self.store
            .release_lease(&SchedulerLeaseReleaseRequest {
                work: work.clone(),
                clear_retry_state,
                transition_id: scheduler_transition_id("release", work, &clear_retry_state)?,
            })
            .map_err(SchedulerError::Store)
    }

    fn observe_clock(&self, tenant_id: &TenantId, now_unix_ms: u64) -> Result<(), SchedulerError> {
        let mut clocks = self
            .last_observed_clock
            .lock()
            .map_err(|_| SchedulerError::ClockStateUnavailable)?;
        if clocks
            .get(tenant_id.as_str())
            .is_some_and(|previous| now_unix_ms < *previous)
        {
            return Err(SchedulerError::ClockRollback);
        }
        clocks.insert(tenant_id.as_str().to_owned(), now_unix_ms);
        Ok(())
    }
}

fn bounded_backoff(policy: SchedulerPolicy, completed_attempts: u32) -> u64 {
    let shift = completed_attempts.min(63);
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    policy
        .base_backoff_ms
        .saturating_mul(multiplier)
        .min(policy.max_backoff_ms)
}

fn retry_outcome(retry: SchedulerRetryState) -> SchedulerWorkOutcome {
    SchedulerWorkOutcome::RetryScheduled {
        action_id: retry.key.action_id,
        attempts: retry.attempts,
        not_before_unix_ms: retry.not_before_unix_ms,
        error_code: retry.last_error,
    }
}

#[derive(Serialize)]
struct SchedulerHealthEventCommitment<'a> {
    kind: &'a str,
    tenant_id: &'a str,
    action_id: &'a str,
    first_failure_at_unix_ms: u64,
    event_id: Option<&'a str>,
}

fn scheduler_health_event_id(
    key: &SchedulerWorkKey,
    first_failure_at_unix_ms: u64,
) -> Result<RecordId, SchedulerError> {
    scheduler_health_id(
        &SchedulerHealthEventCommitment {
            kind: "page",
            tenant_id: key.tenant_id.as_str(),
            action_id: key.action_id.as_str(),
            first_failure_at_unix_ms,
            event_id: None,
        },
        "response_scheduler_health_",
    )
}

fn scheduler_health_ack_id(
    key: &SchedulerWorkKey,
    event_id: &RecordId,
) -> Result<RecordId, SchedulerError> {
    scheduler_health_id(
        &SchedulerHealthEventCommitment {
            kind: "ack",
            tenant_id: key.tenant_id.as_str(),
            action_id: key.action_id.as_str(),
            first_failure_at_unix_ms: 0,
            event_id: Some(event_id.as_str()),
        },
        "response_scheduler_health_ack_",
    )
}

fn scheduler_health_id(
    commitment: &SchedulerHealthEventCommitment<'_>,
    prefix: &str,
) -> Result<RecordId, SchedulerError> {
    let canonical = canonical_json_bytes(commitment).map_err(|_| SchedulerError::Canonical)?;
    let digest = scheduler_health_hash(SCHEDULER_HEALTH_EVENT_ID_DOMAIN, &canonical);
    RecordId::new(format!("{prefix}{}", hex_bytes(digest.as_bytes())))
        .map_err(|_| SchedulerError::Canonical)
}

fn scheduler_health_page_request(
    retry: &SchedulerRetryState,
    event_id: &RecordId,
) -> Result<SchedulerHealthPageRequest, SchedulerError> {
    let event_hash = scheduler_health_hash(
        SCHEDULER_HEALTH_ALERT_HASH_DOMAIN,
        event_id.as_str().as_bytes(),
    );
    let action_hash = scheduler_health_hash(
        SCHEDULER_HEALTH_ALERT_HASH_DOMAIN,
        retry.key.action_id.as_str().as_bytes(),
    );
    Ok(SchedulerHealthPageRequest {
        event_id: event_id.clone(),
        tenant_id: retry.key.tenant_id.clone(),
        action_id: retry.key.action_id.clone(),
        first_failure_at_unix_ms: retry.first_failure_at_unix_ms,
        alert: SecurityAlert {
            tenant_id: retry.key.tenant_id.clone(),
            alert_type: RecordId::new("response_scheduler_unavailable")
                .map_err(|_| SchedulerError::Canonical)?,
            finding_id_hash: event_hash,
            action_id_hash: Some(action_hash),
            evidence_hash: scheduler_health_hash(
                SCHEDULER_HEALTH_ALERT_HASH_DOMAIN,
                event_hash.as_bytes(),
            ),
        },
    })
}

fn scheduler_health_hash(domain: &[u8], body: &[u8]) -> chio_security_types::ports::Digest32 {
    let mut input = Vec::with_capacity(domain.len() + body.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(body);
    let digest = sha256(&input);
    chio_security_types::ports::Digest32::new(*digest.as_bytes())
}

#[derive(Serialize)]
struct SchedulerTransitionCommitment<'a, T> {
    kind: &'a str,
    tenant_id: &'a str,
    action_id: &'a str,
    lease_owner_id: &'a str,
    fencing_token: u64,
    body: &'a T,
}

fn scheduler_transition_id<T: Serialize>(
    kind: &str,
    work: &ScheduledWork,
    body: &T,
) -> Result<RecordId, SchedulerError> {
    let canonical = canonical_json_bytes(&SchedulerTransitionCommitment {
        kind,
        tenant_id: work.tenant_id.as_str(),
        action_id: work.action_id.as_str(),
        lease_owner_id: work.lease_owner_id.as_str(),
        fencing_token: work.fencing_token,
        body,
    })
    .map_err(|_| SchedulerError::Canonical)?;
    let mut input = Vec::with_capacity(SCHEDULER_TRANSITION_ID_DOMAIN.len() + canonical.len());
    input.extend_from_slice(SCHEDULER_TRANSITION_ID_DOMAIN);
    input.extend_from_slice(&canonical);
    let digest = sha256(&input);
    RecordId::new(format!(
        "response_scheduler_{}",
        hex_bytes(digest.as_bytes())
    ))
    .map_err(|_| SchedulerError::Canonical)
}

fn error_code(value: &str) -> Result<ErrorCode, SchedulerError> {
    ErrorCode::new(value).map_err(|_| SchedulerError::Canonical)
}

fn executor_error_code(error: &ExecutorError) -> Result<ErrorCode, SchedulerError> {
    match error {
        ExecutorError::Alert(error)
        | ExecutorError::EffectMutation(error)
        | ExecutorError::EffectQuery(error)
        | ExecutorError::Receipt(error)
        | ExecutorError::Store(error) => Ok(error.code().clone()),
        ExecutorError::ApprovalRequired => error_code("response.approval_required"),
        ExecutorError::AttemptOverflow => error_code("response.attempt_overflow"),
        ExecutorError::Canonical => error_code("response.executor_canonical"),
        ExecutorError::EffectOutcomeUnknown => error_code("response.effect_outcome_unknown"),
        ExecutorError::GenerationOverflow => error_code("response.generation_overflow"),
        ExecutorError::InvalidEffectResult => error_code("response.effect_result_invalid"),
        ExecutorError::InvalidEffectJournal => error_code("response.effect_journal_invalid"),
        ExecutorError::StaleLease => error_code("response.scheduler_lease_stale"),
        ExecutorError::StateMachine(_) => error_code("response.state_machine_error"),
        ExecutorError::WorkMismatch => error_code("response.scheduler_work_mismatch"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("response scheduler canonicalization failed")]
    Canonical,
    #[error("response scheduler clock moved backwards")]
    ClockRollback,
    #[error("response scheduler clock state is unavailable")]
    ClockStateUnavailable,
    #[error("response scheduler returned an invalid claim")]
    InvalidClaim,
    #[error("response scheduler execution record is invalid")]
    InvalidExecutionRecord,
    #[error("response scheduler retry state is invalid")]
    InvalidRetryState,
    #[error("response scheduler policy is invalid")]
    InvalidPolicy,
    #[error("response scheduler store failed: {0}")]
    Store(#[from] PortError),
    #[error("response scheduler health page failed: {0}")]
    Health(PortError),
    #[error("response scheduler time overflowed")]
    TimeOverflow,
    #[error("response scheduler work is not active")]
    WorkNotActive,
}
