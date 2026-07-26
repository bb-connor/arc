//! Settlement observer slot wired into the kernel evaluator.
//!
//! Plugs `chio-settle::SettlementHook` into the kernel's durable
//! observer surface. The observer is consulted only after a receipt has
//! been fully signed and durably stored: settlement is observer-only
//! relative to the receipt bytes, and a hook failure NEVER blocks the
//! dispatch path.
//!
//! The kernel field [`ChioKernel::settlement_observer`] holds an
//! optional handle; deployments that do not wire a settlement runtime
//! see byte-identical receipts (an integration test enforces this
//! invariant explicitly).

use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_core::receipt::{body::ChioReceipt, economics::ChannelReceiptMetadataV1};
use chio_settle::{
    SettlementFailureClass, SettlementFailureCode, SettlementFailureReason, SettlementHook,
    SettlementHookError, SettlementIdempotencyKey, SettlementObservation, SettlementOutcome,
    SettlementRoutingInput, SettlementSkipReason,
};

use crate::receipt_store::{
    ReceiptStore, SettlementObserverOutboxClaimOutcome, SettlementObserverOutboxLease,
};
use crate::settlement_retry::{SettleAttemptRecord, SettlementRetryError, SettlementRetryStore};

const SETTLEMENT_OBSERVER_RECOVERY_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(250);
const SETTLEMENT_OBSERVER_RECOVERY_LEASE_MS: u64 = 30_000;

#[derive(Clone)]
pub(super) struct SettlementReceiptTrustVerifier {
    current_kernel_key: PublicKey,
    resolver: Option<Arc<dyn crate::authority::AuthorityArtifactTrustResolver>>,
}

impl SettlementReceiptTrustVerifier {
    pub(super) fn new(
        current_kernel_key: PublicKey,
        resolver: Option<Arc<dyn crate::authority::AuthorityArtifactTrustResolver>>,
    ) -> Self {
        Self {
            current_kernel_key,
            resolver,
        }
    }

    fn verify(&self, receipt: &ChioReceipt) -> Result<bool, crate::KernelError> {
        super::validation::verify_trusted_receipt_with_resolver(
            receipt,
            &self.current_kernel_key,
            self.resolver.as_deref(),
        )
    }
}

/// Schema string emitted on the wire for settlement-observer status frames.
/// Public so external observers can pin against the same identifier the
/// kernel records.
#[allow(dead_code)]
pub const SETTLEMENT_OBSERVER_STATUS_SCHEMA: &str = "chio.settle.observer-status.v1";

/// Status the kernel records for each settlement observer invocation.
///
/// Settlement runs after durable receipt append: regardless of which variant lands,
/// the receipt has already been signed and persisted. The variants
/// document only what the observer slot did with the hook's return,
/// not whether the receipt committed (it always committed).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SettlementObserverStatus {
    /// No settlement hook is registered on this kernel; the observation
    /// was not produced.
    NotRegistered,
    /// The receipt was either zero-priced or otherwise outside the
    /// marketplace surface; the kernel produced no observation. This
    /// is the steady-state for non-economic deployments.
    Skipped { reason: SettlementSkipReason },
    /// The hook accepted the observation and returned an outcome
    /// classification. The downstream lifecycle is then driven by the
    /// retry policy and dead-letter machinery.
    Observed { outcome: SettlementOutcome },
    /// The hook surfaced an error. The error is routed through durable
    /// retry/dead-letter classification before delivery acknowledgement.
    HookFailed {
        class: SettlementFailureClass,
        reason: SettlementFailureReason,
    },
}

impl SettlementObserverStatus {
    #[must_use]
    pub const fn skipped(reason: SettlementSkipReason) -> Self {
        Self::Skipped { reason }
    }

    #[must_use]
    pub fn hook_failed(error: &SettlementHookError) -> Self {
        let (class, reason) = error.classification();
        Self::HookFailed { class, reason }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementObservationBuild {
    Observation(SettlementObservation),
    Skipped(SettlementSkipReason),
    Permanent(SettlementFailureReason),
}

impl SettlementObservationBuild {
    #[cfg(test)]
    fn is_none(&self) -> bool {
        !matches!(self, Self::Observation(_))
    }

    #[cfg(test)]
    fn expect(self, message: &str) -> SettlementObservation {
        match self {
            Self::Observation(observation) => observation,
            Self::Skipped(_) | Self::Permanent(_) => panic!("{message}"),
        }
    }
}

fn permanent(code: SettlementFailureCode, detail: impl AsRef<[u8]>) -> SettlementObservationBuild {
    SettlementObservationBuild::Permanent(SettlementFailureReason::from_detail(code, detail))
}

pub(super) fn validate_and_sanitize_settlement_outcome(
    outcome: &SettlementOutcome,
) -> Result<SettlementRoutingInput, SettlementRetryError> {
    if !outcome.has_supported_schema() {
        return Err(SettlementRetryError::Backend(
            "settlement hook returned an unsupported outcome schema".to_string(),
        ));
    }
    match outcome {
        SettlementOutcome::Accepted { transcript_id, .. } => {
            if transcript_id.trim().is_empty()
                || transcript_id.len() > 512
                || transcript_id.chars().any(char::is_control)
            {
                return Err(SettlementRetryError::Backend(
                    "settlement hook returned an invalid transcript identifier".to_string(),
                ));
            }
            Ok(SettlementRoutingInput::Accepted)
        }
        SettlementOutcome::Skipped { reason, .. } => {
            Ok(SettlementRoutingInput::Skipped { reason: *reason })
        }
        SettlementOutcome::Retryable { reason, .. } => Ok(SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        }),
        SettlementOutcome::Permanent { reason, .. } => Ok(SettlementRoutingInput::Permanent {
            reason: reason.clone(),
        }),
    }
}

#[must_use]
pub fn build_observation(
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
) -> SettlementObservationBuild {
    match receipt.verify_signature() {
        Ok(true) => {}
        Ok(false) => {
            return permanent(
                SettlementFailureCode::InvalidReceiptSignature,
                "receipt signature did not verify",
            );
        }
        Err(error) => {
            return permanent(
                SettlementFailureCode::InvalidReceiptSignature,
                error.to_string(),
            );
        }
    }
    match receipt.action.verify_hash() {
        Ok(true) => {}
        Ok(false) => {
            return permanent(
                SettlementFailureCode::InvalidActionHash,
                "receipt action hash did not verify",
            );
        }
        Err(error) => {
            return permanent(SettlementFailureCode::InvalidActionHash, error.to_string());
        }
    }
    if trusted_kernel_keys.is_empty()
        || !trusted_kernel_keys
            .iter()
            .any(|trusted| trusted == &receipt.kernel_key)
    {
        return permanent(
            SettlementFailureCode::UntrustedReceiptSigner,
            "receipt signer is not trusted",
        );
    }
    let metadata = receipt.metadata.as_ref();
    let channelized = if let Some(channel_value) = metadata.and_then(|value| value.get("channel")) {
        match serde_json::from_value::<ChannelReceiptMetadataV1>(channel_value.clone()) {
            Ok(channel) if channel.is_valid() => true,
            Ok(_) | Err(_) => {
                return permanent(
                    SettlementFailureCode::InvalidObservation,
                    "channel metadata is malformed",
                );
            }
        }
    } else {
        false
    };
    if channelized {
        if !receipt.is_allowed() && !receipt.is_denied() {
            return permanent(
                SettlementFailureCode::InvalidObservation,
                "receipt does not contain an authorized terminal decision",
            );
        }
        if receipt.financial_metadata().is_none() {
            return permanent(
                SettlementFailureCode::MalformedFinancialMetadata,
                "channel financial metadata is malformed",
            );
        }
        return permanent(
            SettlementFailureCode::InvalidObservation,
            "channel settlement handler is not configured",
        );
    }
    if receipt.is_denied() {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::Denied);
    }
    if !receipt.is_allowed() {
        return permanent(
            SettlementFailureCode::InvalidObservation,
            "receipt does not contain an authorized terminal decision",
        );
    }
    let Some(metadata) = metadata else {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::NoEconomicIntent);
    };
    let Some(financial_value) = metadata.get("financial") else {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::NoEconomicIntent);
    };
    let Some(financial) = financial_value.as_object() else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "financial metadata is not an object",
        );
    };
    let Some(units) = financial
        .get("cost_charged")
        .and_then(serde_json::Value::as_u64)
    else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "financial metadata is missing a valid cost_charged",
        );
    };
    if units == 0 {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::ZeroCharge);
    }
    let Some(currency) = financial
        .get("currency")
        .and_then(serde_json::Value::as_str)
    else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "positive cost_charged requires a currency",
        );
    };
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "positive cost_charged requires a three-letter uppercase currency",
        );
    }
    let observation = SettlementObservation::new(
        receipt.id.clone(),
        receipt.timestamp,
        receipt.tool_server.clone(),
        receipt.tool_name.clone(),
        receipt.capability_id.clone(),
        chio_core::capability::scope::MonetaryAmount {
            currency: currency.to_string(),
            units,
        },
        receipt.content_hash.clone(),
        receipt.policy_hash.clone(),
    );
    SettlementObservationBuild::Observation(if let Some(tenant_id) = receipt.tenant_id.clone() {
        observation.with_tenant(tenant_id)
    } else {
        observation
    })
}

/// Run the registered settlement hook against a freshly signed receipt.
///
/// Settlement is observer-only relative to receipt bytes: the receipt
/// has already been signed and persisted before this function runs,
/// and the returned status NEVER feeds back into the dispatch path.
/// The function is plumbed through the kernel struct in
/// [`super::ChioKernel::run_settlement_observer`] so callers only
/// need the kernel handle.
#[must_use]
pub fn run_observer(
    hook: Option<&Arc<dyn SettlementHook>>,
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
    idempotency_key: &SettlementIdempotencyKey,
) -> SettlementObserverStatus {
    let Some(hook) = hook else {
        return SettlementObserverStatus::NotRegistered;
    };

    let observation = match build_observation(receipt, trusted_kernel_keys) {
        SettlementObservationBuild::Observation(observation) => observation,
        SettlementObservationBuild::Skipped(reason) => {
            return SettlementObserverStatus::skipped(reason);
        }
        SettlementObservationBuild::Permanent(reason) => {
            return SettlementObserverStatus::HookFailed {
                class: SettlementFailureClass::Permanent,
                reason,
            };
        }
    };

    if idempotency_key.receipt_id != observation.receipt_id || idempotency_key.row_version == 0 {
        return SettlementObserverStatus::hook_failed(&SettlementHookError::InvalidObservation(
            "settlement idempotency key does not match the claimed receipt".to_string(),
        ));
    }

    match hook.observe(&observation, idempotency_key) {
        Ok(outcome) => match validate_and_sanitize_settlement_outcome(&outcome) {
            Ok(_) => SettlementObserverStatus::Observed { outcome },
            Err(_) => SettlementObserverStatus::HookFailed {
                class: SettlementFailureClass::Permanent,
                reason: SettlementFailureReason::from_detail(
                    SettlementFailureCode::InvalidObservation,
                    "settlement hook returned an invalid outcome",
                ),
            },
        },
        Err(error) => SettlementObserverStatus::hook_failed(&error),
    }
}

pub(super) fn route_staged_status(
    retry_store: &dyn SettlementRetryStore,
    retry_policy: &chio_settle::RetryPolicy,
    receipt: &ChioReceipt,
    status: &SettlementObserverStatus,
) -> Result<(), SettlementRetryError> {
    use chio_settle::RetryDecision;

    let input = match status {
        SettlementObserverStatus::Skipped { reason } => {
            SettlementRoutingInput::Skipped { reason: *reason }
        }
        SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Accepted { .. },
        } => SettlementRoutingInput::Accepted,
        SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Skipped { .. },
        } => SettlementRoutingInput::Permanent {
            reason: SettlementFailureReason::from_detail(
                SettlementFailureCode::InvalidObservation,
                "settlement hook skipped a positive economic observation",
            ),
        },
        SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Retryable { reason, .. },
        } => SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        },
        SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Permanent { reason, .. },
        } => SettlementRoutingInput::Permanent {
            reason: reason.clone(),
        },
        SettlementObserverStatus::HookFailed { class, reason } => {
            match reason.effective_class(*class) {
                SettlementFailureClass::Retryable => SettlementRoutingInput::Retryable {
                    reason: reason.clone(),
                },
                SettlementFailureClass::Permanent => SettlementRoutingInput::Permanent {
                    reason: reason.clone(),
                },
            }
        }
        SettlementObserverStatus::NotRegistered => {
            return Err(SettlementRetryError::Backend(
                "settlement observer disappeared before staged delivery".to_string(),
            ))
        }
    };
    match chio_settle::classify_attempt(retry_policy, 0, &input) {
        RetryDecision::Accepted | RetryDecision::Skip { .. } => {
            retry_store.clear_attempt(&receipt.id)
        }
        RetryDecision::Retry {
            attempt,
            backoff,
            reason,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            retry_store
                .insert_observer_attempt_if_absent(&SettleAttemptRecord {
                    receipt_id: receipt.id.clone(),
                    finalized_at: receipt.timestamp,
                    attempts: attempt,
                    next_visible_at: now.saturating_add(backoff.as_secs().max(1)),
                    last_reason: Some(reason.code().as_str().to_string()),
                })
                .map(|_| ())
        }
        RetryDecision::DeadLetter { reason } => {
            let record = chio_settle::DeadLetterRecord::new(
                receipt.id.clone(),
                receipt.timestamp,
                1,
                reason,
            );
            retry_store.insert_dead_letter(&record)?;
            retry_store.clear_attempt(&receipt.id)
        }
    }
}

pub(super) struct SettlementObserverRecoveryHandle {
    stop: Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl SettlementObserverRecoveryHandle {
    pub(super) fn spawn(
        receipt_store: Arc<dyn ReceiptStore>,
        retry_store: Arc<dyn SettlementRetryStore>,
        hook: Arc<dyn SettlementHook>,
        retry_policy: chio_settle::RetryPolicy,
        trust_verifier: SettlementReceiptTrustVerifier,
    ) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    drain_one_settlement_observer_outbox(
                        receipt_store.as_ref(),
                        retry_store.as_ref(),
                        &hook,
                        &retry_policy,
                        &trust_verifier,
                        worker_stop.as_ref(),
                    )
                }));
                match outcome {
                    Ok(Ok(true)) => continue,
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => tracing::warn!(
                        reason = %chio_log_redact::redacted!(&error),
                        "settlement-observer recovery remains pending"
                    ),
                    Err(_) => tracing::warn!("settlement-observer recovery panicked"),
                }
                let mut waited = std::time::Duration::ZERO;
                let slice = std::time::Duration::from_millis(50);
                while waited < SETTLEMENT_OBSERVER_RECOVERY_INTERVAL
                    && !worker_stop.load(std::sync::atomic::Ordering::SeqCst)
                {
                    std::thread::sleep(slice);
                    waited += slice;
                }
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for SettlementObserverRecoveryHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        // Dropping a JoinHandle detaches the worker. Store, resolver, and hook
        // implementations are external authorities and may block indefinitely;
        // composition changes must never wait on their return. The worker checks
        // this stop flag after every blocking boundary and abandons any lease it
        // owns before exiting.
        let _ = self.join.take();
    }
}

fn ensure_settlement_observer_recovery_running(
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    if stop.is_some_and(|stop| stop.load(std::sync::atomic::Ordering::Acquire)) {
        return Err("settlement-observer recovery stopped".to_string());
    }
    Ok(())
}

fn drain_one_settlement_observer_outbox(
    receipt_store: &dyn ReceiptStore,
    retry_store: &dyn SettlementRetryStore,
    hook: &Arc<dyn SettlementHook>,
    retry_policy: &chio_settle::RetryPolicy,
    trust_verifier: &SettlementReceiptTrustVerifier,
    stop: &std::sync::atomic::AtomicBool,
) -> Result<bool, String> {
    ensure_settlement_observer_recovery_running(Some(stop))?;
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let receipt_id = receipt_store
        .list_settlement_observer_outbox_receipt_ids(now_unix_ms, 1)
        .map_err(|_| "settlement-observer outbox inventory failed".to_string())?
        .into_iter()
        .next();
    ensure_settlement_observer_recovery_running(Some(stop))?;
    let Some(receipt_id) = receipt_id else {
        return Ok(false);
    };
    let claim_deadline_unix_ms = now_unix_ms
        .checked_add(SETTLEMENT_OBSERVER_RECOVERY_LEASE_MS)
        .ok_or_else(|| "settlement-observer recovery lease overflowed u64".to_string())?;
    let claim_token = uuid::Uuid::now_v7().to_string();
    let claim = receipt_store
        .claim_settlement_observer_outbox(
            &receipt_id,
            &claim_token,
            now_unix_ms,
            claim_deadline_unix_ms,
        )
        .map_err(|_| "settlement-observer outbox claim failed".to_string())?;
    let mut lease = match claim {
        SettlementObserverOutboxClaimOutcome::Claimed(lease) => lease,
        SettlementObserverOutboxClaimOutcome::Completed
        | SettlementObserverOutboxClaimOutcome::Busy => return Ok(false),
        SettlementObserverOutboxClaimOutcome::Missing => {
            return Err("settlement-observer outbox row disappeared".to_string())
        }
    };
    if let Err(error) = ensure_settlement_observer_recovery_running(Some(stop)) {
        let _ = receipt_store.abandon_settlement_observer_outbox(
            &lease.receipt_id,
            lease.version,
            &lease.claim_token,
            &error,
        );
        return Err(error);
    }
    let result = deliver_claimed_settlement_observer_outbox(
        receipt_store,
        retry_store,
        hook,
        retry_policy,
        trust_verifier,
        Some(stop),
        &mut lease,
    );
    if let Err(error) = &result {
        let _ = receipt_store.abandon_settlement_observer_outbox(
            &lease.receipt_id,
            lease.version,
            &lease.claim_token,
            error,
        );
    }
    result.map(|()| true)
}

pub(super) fn deliver_claimed_settlement_observer_outbox(
    receipt_store: &dyn ReceiptStore,
    retry_store: &dyn SettlementRetryStore,
    hook: &Arc<dyn SettlementHook>,
    retry_policy: &chio_settle::RetryPolicy,
    trust_verifier: &SettlementReceiptTrustVerifier,
    stop: Option<&std::sync::atomic::AtomicBool>,
    lease: &mut SettlementObserverOutboxLease,
) -> Result<(), String> {
    let receipt = receipt_store
        .load_chio_receipt(&lease.receipt_id)
        .map_err(|_| "settlement-observer authoritative receipt lookup failed".to_string())?
        .ok_or_else(|| {
            "settlement-observer receipt is absent from authoritative storage".to_string()
        })?;
    ensure_settlement_observer_recovery_running(stop)?;
    if receipt.id != lease.receipt_id || receipt.timestamp != lease.finalized_at {
        return Err("settlement-observer outbox diverged from authoritative receipt".to_string());
    }
    if !receipt
        .action
        .verify_hash()
        .map_err(|_| "settlement-observer action integrity check failed".to_string())?
    {
        return Err(
            "settlement-observer authoritative receipt failed action integrity validation"
                .to_string(),
        );
    }
    if !trust_verifier
        .verify(&receipt)
        .map_err(|_| "settlement-observer receipt trust resolution failed".to_string())?
    {
        return Err(
            "settlement-observer authoritative receipt failed trust validation".to_string(),
        );
    }
    ensure_settlement_observer_recovery_running(stop)?;
    let status = if let Some(staged) = lease.staged_status_json.as_deref() {
        serde_json::from_str::<SettlementObserverStatus>(staged)
            .map_err(|_| "settlement-observer staged status is invalid".to_string())?
    } else {
        let status = run_observer(
            Some(hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &SettlementIdempotencyKey {
                receipt_id: lease.receipt_id.clone(),
                row_version: lease.version,
            },
        );
        ensure_settlement_observer_recovery_running(stop)?;
        let status_json = serde_json::to_string(&status)
            .map_err(|_| "settlement-observer status serialization failed".to_string())?;
        *lease = receipt_store
            .stage_settlement_observer_outbox_status(
                &lease.receipt_id,
                lease.version,
                &lease.claim_token,
                &status_json,
            )
            .map_err(|_| "settlement-observer status staging failed".to_string())?
            .ok_or_else(|| "settlement-observer lease became stale before routing".to_string())?;
        ensure_settlement_observer_recovery_running(stop)?;
        status
    };
    route_staged_status(retry_store, retry_policy, &receipt, &status)
        .map_err(|_| "settlement-observer durable outcome routing failed".to_string())?;
    ensure_settlement_observer_recovery_running(stop)?;
    if !receipt_store
        .acknowledge_settlement_observer_outbox(
            &lease.receipt_id,
            lease.version,
            &lease.claim_token,
        )
        .map_err(|_| "settlement-observer outbox acknowledgement failed".to_string())?
    {
        return Err("settlement-observer acknowledgement lost its fenced lease".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
        metadata::GuardEvidence,
    };

    fn sign_with(body_metadata: serde_json::Value, decision: Decision) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("test tool-call action constructs");
        sign_with_action(body_metadata, decision, action)
    }

    fn sign_with_action(
        body_metadata: serde_json::Value,
        decision: Decision,
        action: ToolCallAction,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let body = ChioReceiptBody {
            id: "rcpt-test".to_string(),
            timestamp: 100,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-1".to_string(),
            tool_name: "tool-1".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "ch-1".to_string(),
            policy_hash: "ph-1".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "G".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: Some(body_metadata),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &kp).expect("test receipt signs")
    }

    fn idempotency_key(receipt: &ChioReceipt) -> SettlementIdempotencyKey {
        SettlementIdempotencyKey {
            receipt_id: receipt.id.clone(),
            row_version: 1,
        }
    }

    struct AcceptingHook;
    impl SettlementHook for AcceptingHook {
        fn supports_receipt_id_idempotency(&self) -> bool {
            true
        }

        fn observe(
            &self,
            observation: &SettlementObservation,
            _idempotency_key: &SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Ok(SettlementOutcome::accepted(format!(
                "ts-{}",
                observation.receipt_id
            )))
        }
    }

    struct FailingHook;
    impl SettlementHook for FailingHook {
        fn supports_receipt_id_idempotency(&self) -> bool {
            true
        }

        fn observe(
            &self,
            _observation: &SettlementObservation,
            _idempotency_key: &SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Err(SettlementHookError::Transient(
                "rpc lag credential-é-SEED-observer".to_string(),
            ))
        }
    }

    struct StaticOutcomeHook(SettlementOutcome);

    impl SettlementHook for StaticOutcomeHook {
        fn supports_receipt_id_idempotency(&self) -> bool {
            true
        }

        fn observe(
            &self,
            _observation: &SettlementObservation,
            _idempotency_key: &SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone, Copy)]
    enum DurableFailureMode {
        ReceiptLookup,
        StagedJson,
    }

    struct DurableFailureReceiptStore {
        receipt: ChioReceipt,
        mode: DurableFailureMode,
        abandoned_error: std::sync::Mutex<Option<String>>,
    }

    impl ReceiptStore for DurableFailureReceiptStore {
        fn append_chio_receipt(
            &self,
            _receipt: &ChioReceipt,
        ) -> Result<(), crate::ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), crate::ReceiptStoreError> {
            Ok(())
        }

        fn load_chio_receipt(
            &self,
            _receipt_id: &str,
        ) -> Result<Option<ChioReceipt>, crate::ReceiptStoreError> {
            match self.mode {
                DurableFailureMode::ReceiptLookup => Err(crate::ReceiptStoreError::Conflict(
                    "credential-é-SEED-store".to_string(),
                )),
                DurableFailureMode::StagedJson => Ok(Some(self.receipt.clone())),
            }
        }

        fn list_settlement_observer_outbox_receipt_ids(
            &self,
            _now_unix_ms: u64,
            _limit: usize,
        ) -> Result<Vec<String>, crate::ReceiptStoreError> {
            Ok(vec![self.receipt.id.clone()])
        }

        fn claim_settlement_observer_outbox(
            &self,
            receipt_id: &str,
            claim_token: &str,
            _now_unix_ms: u64,
            claim_deadline_unix_ms: u64,
        ) -> Result<SettlementObserverOutboxClaimOutcome, crate::ReceiptStoreError> {
            Ok(SettlementObserverOutboxClaimOutcome::Claimed(
                SettlementObserverOutboxLease {
                    receipt_id: receipt_id.to_string(),
                    finalized_at: self.receipt.timestamp,
                    claim_token: claim_token.to_string(),
                    claim_deadline_unix_ms,
                    version: 1,
                    staged_status_json: matches!(self.mode, DurableFailureMode::StagedJson)
                        .then(|| "{credential-é-SEED-serde".to_string()),
                },
            ))
        }

        fn abandon_settlement_observer_outbox(
            &self,
            _receipt_id: &str,
            _expected_version: u64,
            _claim_token: &str,
            last_error: &str,
        ) -> Result<bool, crate::ReceiptStoreError> {
            *self.abandoned_error.lock().map_err(|_| {
                crate::ReceiptStoreError::Conflict("abandon error lock poisoned".to_string())
            })? = Some(last_error.to_string());
            Ok(true)
        }
    }

    struct DurableFailureRetryStore;

    impl SettlementRetryStore for DurableFailureRetryStore {
        fn load_attempt(
            &self,
            _receipt_id: &str,
        ) -> Result<Option<SettleAttemptRecord>, SettlementRetryError> {
            Ok(None)
        }

        fn upsert_attempt(
            &self,
            _record: &SettleAttemptRecord,
        ) -> Result<(), SettlementRetryError> {
            Ok(())
        }

        fn clear_attempt(&self, _receipt_id: &str) -> Result<(), SettlementRetryError> {
            Ok(())
        }

        fn insert_dead_letter(
            &self,
            _record: &chio_settle::DeadLetterRecord,
        ) -> Result<bool, SettlementRetryError> {
            Ok(true)
        }

        fn due_attempts(
            &self,
            _now_unix_secs: u64,
            _limit: usize,
        ) -> Result<Vec<SettleAttemptRecord>, SettlementRetryError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn build_observation_skips_non_allow_decisions() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 100, "currency": "USD"}
            }),
            Decision::Deny {
                reason: "denied".to_string(),
                guard: "G".to_string(),
            },
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_zero_priced_receipts() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_when_metadata_missing_financial_section() {
        let receipt = sign_with(serde_json::json!({}), Decision::Allow);
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_invalid_signature() {
        let mut receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        receipt.tool_name = "tampered".to_string();
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_mismatched_action_hash() {
        let mut action = ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/a"}))
            .expect("test tool-call action constructs");
        action.parameters = serde_json::json!({"path": "/tmp/b"});
        let receipt = sign_with_action(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
            action,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_constructs_priced_frame() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let observation = build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .expect("priced receipt yields observation");
        assert_eq!(observation.receipt_id, receipt.id);
        assert_eq!(observation.finalized_at, 100);
        assert_eq!(
            observation.amount,
            MonetaryAmount {
                currency: "USD".to_string(),
                units: 250,
            }
        );
        assert_eq!(observation.content_hash, "ch-1");
    }

    #[test]
    fn build_observation_rejects_untrusted_signer() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, &[]).is_none());
    }

    #[test]
    fn run_observer_returns_not_registered_without_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let status = run_observer(
            None,
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(status, SettlementObserverStatus::NotRegistered));
    }

    #[test]
    fn run_observer_records_hook_outcome() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(AcceptingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        match status {
            SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::Accepted { transcript_id, .. },
            } => assert_eq!(transcript_id, format!("ts-{}", receipt.id)),
            other => panic!("expected accepted outcome, got {other:?}"),
        }
    }

    #[test]
    fn run_observer_skips_zero_price_without_invoking_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(status, SettlementObserverStatus::Skipped { .. }));
    }

    #[test]
    fn build_observation_reads_canonical_financial_metadata() {
        // The kernel canonical financial-metadata shape is
        // `FinancialReceiptMetadata` (`cost_charged`, `currency`,
        // `attempted_cost`). Receipts emitted by the kernel's normal
        // finalize path use this shape, so the settlement observer
        // MUST recognize it.
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 250,
                    "currency": "USD",
                    "budget_remaining": 750,
                    "budget_total": 1000,
                    "delegation_depth": 1,
                    "root_budget_holder": "tenant-a",
                    "settlement_status": "pending"
                }
            }),
            Decision::Allow,
        );
        let observation = build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .expect("canonical FinancialReceiptMetadata shape yields observation");
        assert_eq!(observation.amount.units, 250);
        assert_eq!(observation.amount.currency, "USD");
    }

    #[test]
    fn build_observation_skips_zero_cost_charged() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "cost_charged": 0,
                    "currency": "USD"
                }
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn run_observer_records_hook_failures_without_panicking() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(
            status,
            SettlementObserverStatus::HookFailed {
                class: SettlementFailureClass::Retryable,
                ref reason,
            } if reason.code() == SettlementFailureCode::Backend
        ));
        let status_json = serde_json::to_string(&status).expect("status serializes");
        assert!(!status_json.contains("credential-é-SEED-observer"));
    }

    #[test]
    fn run_observer_rejects_malformed_hook_outcomes_without_truncation() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let malformed = [
            SettlementOutcome::Accepted {
                schema: "chio.settle.outcome.v0".to_string(),
                transcript_id: "transcript".to_string(),
            },
            SettlementOutcome::accepted("   "),
            SettlementOutcome::accepted("t".repeat(513)),
        ];
        for outcome in malformed {
            let hook: Arc<dyn SettlementHook> = Arc::new(StaticOutcomeHook(outcome));
            assert_eq!(
                run_observer(
                    Some(&hook),
                    &receipt,
                    std::slice::from_ref(&receipt.kernel_key),
                    &idempotency_key(&receipt),
                ),
                SettlementObserverStatus::HookFailed {
                    class: SettlementFailureClass::Permanent,
                    reason: SettlementFailureReason::from_detail(
                        SettlementFailureCode::InvalidObservation,
                        "settlement hook returned an invalid outcome",
                    ),
                }
            );
        }

        let transcript_id = "t".repeat(512);
        let hook: Arc<dyn SettlementHook> = Arc::new(StaticOutcomeHook(
            SettlementOutcome::accepted(transcript_id.clone()),
        ));
        assert_eq!(
            run_observer(
                Some(&hook),
                &receipt,
                std::slice::from_ref(&receipt.kernel_key),
                &idempotency_key(&receipt),
            ),
            SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::accepted(transcript_id),
            }
        );
    }

    #[test]
    fn durable_observer_failures_never_persist_raw_store_or_serde_errors() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(AcceptingHook);
        let retry_store = DurableFailureRetryStore;
        let verifier = SettlementReceiptTrustVerifier::new(receipt.kernel_key.clone(), None);
        for (mode, expected) in [
            (
                DurableFailureMode::ReceiptLookup,
                "settlement-observer authoritative receipt lookup failed",
            ),
            (
                DurableFailureMode::StagedJson,
                "settlement-observer staged status is invalid",
            ),
        ] {
            let store = DurableFailureReceiptStore {
                receipt: receipt.clone(),
                mode,
                abandoned_error: std::sync::Mutex::new(None),
            };
            let stop = std::sync::atomic::AtomicBool::new(false);
            let error = drain_one_settlement_observer_outbox(
                &store,
                &retry_store,
                &hook,
                &chio_settle::RetryPolicy::default(),
                &verifier,
                &stop,
            )
            .expect_err("delivery must remain pending");
            assert_eq!(error, expected);
            let abandoned = store
                .abandoned_error
                .lock()
                .expect("abandoned error lock")
                .clone()
                .expect("abandon recorded");
            assert_eq!(abandoned, expected);
            assert!(!abandoned.contains("credential-é-SEED"));
        }
    }
}
