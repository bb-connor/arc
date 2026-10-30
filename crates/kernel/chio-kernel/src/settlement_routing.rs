use std::sync::Arc;

use chio_log_redact::redacted;
use chio_settle_types::{
    RetryPolicy, RetryPolicyError, SettlementAttemptClaim, SettlementFailureClass, SettlementHook,
    SettlementOutcome, SettlementOutcomeStore, SettlementRoute, SettlementRouteError,
    SettlementRouteErrorClass, SettlementRoutingInput,
};

use crate::kernel::settlement_observer::SettlementObserverStatus;

const INVALID_HOOK_SKIP_DETAIL: &str =
    "settlement hook returned skipped for a positive economic observation";

const INVALID_TRANSCRIPT_ID_DETAIL: &str =
    "settlement hook returned an invalid transcript identifier";

const MAX_TRANSCRIPT_ID_BYTES: usize = 512;

const INLINE_SETTLEMENT_WORKER_ID: &str = "kernel-inline-observer";
const INLINE_SETTLEMENT_LEASE_MS: u64 = 30_000;
const DRAIN_SETTLEMENT_WORKER_ID: &str = "kernel-settlement-drain";
const DRAIN_SETTLEMENT_LEASE_MS: u64 = 30_000;

/// Durable result of completing one claimed settlement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementCompletion {
    /// The outcome was committed under this worker's claim.
    Recorded(SettlementRoute),
    /// Another worker reclaimed the row after this lease lapsed, so nothing
    /// was written for this claim.
    LostLease,
}

pub(crate) struct SettlementObserverRuntime {
    hook: Arc<dyn SettlementHook>,
    outcome_store: Arc<dyn SettlementOutcomeStore>,
    retry_policy: RetryPolicy,
    drain_trust: crate::SettlementDrainTrust,
    store_binding: chio_settle_types::SettlementStoreBinding,
}

impl SettlementObserverRuntime {
    pub(crate) fn new(
        hook: Arc<dyn SettlementHook>,
        outcome_store: Arc<dyn SettlementOutcomeStore>,
        retry_policy: RetryPolicy,
        drain_trust: crate::SettlementDrainTrust,
    ) -> Result<Self, RetryPolicyError> {
        retry_policy.validate()?;
        let store_binding = outcome_store.settlement_store_binding();
        Ok(Self {
            hook,
            outcome_store,
            retry_policy,
            drain_trust,
            store_binding,
        })
    }

    pub(crate) fn drain_keys(&self) -> &[chio_core::crypto::PublicKey] {
        self.drain_trust.keys()
    }

    pub(crate) fn hook(&self) -> Arc<dyn SettlementHook> {
        Arc::clone(&self.hook)
    }

    pub(crate) fn hook_ref(&self) -> &Arc<dyn SettlementHook> {
        &self.hook
    }

    pub(crate) const fn store_binding(&self) -> chio_settle_types::SettlementStoreBinding {
        self.store_binding
    }

    pub(crate) fn claim_receipt(
        &self,
        receipt_id: &str,
        finalized_at: u64,
        now_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
        let claim = self.outcome_store.claim_receipt(
            receipt_id,
            INLINE_SETTLEMENT_WORKER_ID,
            now_ms,
            INLINE_SETTLEMENT_LEASE_MS,
        )?;
        if let Some(claim) = claim.as_ref() {
            if claim.receipt_id != receipt_id
                || claim.finalized_at != finalized_at
                || claim.row_version == 0
                || claim.lease_owner != INLINE_SETTLEMENT_WORKER_ID
                || claim.lease_token.is_empty()
                || claim.lease_until_ms <= now_ms
            {
                return Err(SettlementRouteError::InvalidRecord {
                    detail: "claimed settlement row does not match the requested receipt"
                        .to_string(),
                });
            }
        }
        Ok(claim)
    }

    pub(crate) fn claim_due(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
        let claims = self.outcome_store.claim_due(
            DRAIN_SETTLEMENT_WORKER_ID,
            now_ms,
            DRAIN_SETTLEMENT_LEASE_MS,
            limit,
        )?;
        if claims.len() > limit
            || claims.iter().any(|claim| {
                claim.row_version == 0
                    || claim.lease_owner != DRAIN_SETTLEMENT_WORKER_ID
                    || claim.lease_token.is_empty()
                    || claim.lease_until_ms <= now_ms
            })
        {
            return Err(SettlementRouteError::InvalidRecord {
                detail: "claimed settlement batch does not match the drain lease".to_string(),
            });
        }
        Ok(claims)
    }

    /// Complete the inline post-signing claim without blocking the caller. A
    /// persistence failure is counted as unresolved and the row stays durable
    /// for the drain.
    pub(crate) fn record_claimed_status(
        &self,
        claim: &SettlementAttemptClaim,
        status: &SettlementObserverStatus,
        observed_at_ms: u64,
    ) {
        if let Err(error) = self.complete_claim(claim, status, observed_at_ms) {
            tracing::debug!(
                receipt_id = claim.receipt_id.as_str(),
                error = %redacted!(&error),
                "inline settlement completion left the attempt for the drain"
            );
        }
    }

    pub(crate) fn complete_claim(
        &self,
        claim: &SettlementAttemptClaim,
        status: &SettlementObserverStatus,
        observed_at_ms: u64,
    ) -> Result<SettlementCompletion, SettlementRouteError> {
        self.record_claimed_status_with_metrics(
            claim,
            status,
            observed_at_ms,
            &RuntimeSettlementRoutingMetrics,
        )
    }

    fn record_claimed_status_with_metrics(
        &self,
        claim: &SettlementAttemptClaim,
        status: &SettlementObserverStatus,
        observed_at_ms: u64,
        metrics: &dyn SettlementRoutingMetrics,
    ) -> Result<SettlementCompletion, SettlementRouteError> {
        let Some(input) = normalize_status(status) else {
            return Err(SettlementRouteError::InvalidRecord {
                detail: "settlement status has no registered hook outcome".to_string(),
            });
        };
        let outcome_class = settlement_outcome_class(&input);
        let route = self.outcome_store.record_claimed_outcome(
            claim,
            &input,
            self.retry_policy,
            observed_at_ms,
        );
        let clean = matches!(
            (&input, &route),
            (
                SettlementRoutingInput::Accepted | SettlementRoutingInput::Skipped { .. },
                Ok(SettlementRoute::NoAction)
            )
        );
        let benign_conflict = matches!(route, Err(SettlementRouteError::Conflict { .. }));
        if benign_conflict {
            tracing::debug!(
                receipt_id = claim.receipt_id.as_str(),
                outcome_class,
                "settlement outcome lost a claim race"
            );
        } else if !clean {
            record_unresolved(
                &claim.receipt_id,
                outcome_class,
                settlement_persistence_class(&route),
                metrics,
            );
        }
        match route {
            Ok(route) => Ok(SettlementCompletion::Recorded(route)),
            Err(SettlementRouteError::Conflict { .. }) => Ok(SettlementCompletion::LostLease),
            Err(error) => Err(error),
        }
    }
}

fn normalize_failure(
    class: SettlementFailureClass,
    reason: &chio_settle_types::SettlementFailureReason,
) -> SettlementRoutingInput {
    match reason.effective_class(class) {
        SettlementFailureClass::Retryable => SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        },
        SettlementFailureClass::Permanent => SettlementRoutingInput::Permanent {
            reason: reason.clone(),
        },
    }
}

fn is_valid_transcript_id(transcript_id: &str) -> bool {
    !transcript_id.trim().is_empty()
        && transcript_id.len() <= MAX_TRANSCRIPT_ID_BYTES
        && !transcript_id.chars().any(char::is_control)
}

fn normalize_status(status: &SettlementObserverStatus) -> Option<SettlementRoutingInput> {
    match status {
        SettlementObserverStatus::NotRegistered => None,
        SettlementObserverStatus::Skipped { reason } => {
            Some(SettlementRoutingInput::Skipped { reason: *reason })
        }
        SettlementObserverStatus::Observed { outcome } if !outcome.has_supported_schema() => {
            Some(SettlementRoutingInput::Permanent {
                reason: chio_settle_types::SettlementFailureReason::from_detail(
                    chio_settle_types::SettlementFailureCode::InvalidObservation,
                    "unsupported settlement outcome schema",
                ),
            })
        }
        SettlementObserverStatus::Observed { outcome } => Some(match outcome {
            SettlementOutcome::Accepted { transcript_id, .. }
                if !is_valid_transcript_id(transcript_id) =>
            {
                SettlementRoutingInput::Permanent {
                    reason: chio_settle_types::SettlementFailureReason::from_detail(
                        chio_settle_types::SettlementFailureCode::InvalidObservation,
                        INVALID_TRANSCRIPT_ID_DETAIL,
                    ),
                }
            }
            SettlementOutcome::Accepted { .. } => SettlementRoutingInput::Accepted,
            SettlementOutcome::Skipped { .. } => SettlementRoutingInput::Permanent {
                reason: chio_settle_types::SettlementFailureReason::from_detail(
                    chio_settle_types::SettlementFailureCode::InvalidObservation,
                    INVALID_HOOK_SKIP_DETAIL,
                ),
            },
            SettlementOutcome::Retryable { reason, .. } => {
                normalize_failure(SettlementFailureClass::Retryable, reason)
            }
            SettlementOutcome::Permanent { reason, .. } => {
                normalize_failure(SettlementFailureClass::Permanent, reason)
            }
        }),
        SettlementObserverStatus::HookFailed { class, reason } => {
            Some(normalize_failure(*class, reason))
        }
    }
}

trait SettlementRoutingMetrics {
    fn increment_unresolved(&self);
}

struct RuntimeSettlementRoutingMetrics;

impl SettlementRoutingMetrics for RuntimeSettlementRoutingMetrics {
    fn increment_unresolved(&self) {
        chio_metrics_spec::runtime::families::SETTLEMENT_UNRESOLVED.incr(&[]);
    }
}

const fn settlement_outcome_class(input: &SettlementRoutingInput) -> &'static str {
    match input {
        SettlementRoutingInput::Accepted | SettlementRoutingInput::Skipped { .. } => "cleanup",
        SettlementRoutingInput::Retryable { .. } => "retryable",
        SettlementRoutingInput::Permanent { .. } => "permanent",
    }
}

fn settlement_persistence_class(
    route: &Result<SettlementRoute, SettlementRouteError>,
) -> &'static str {
    match route {
        Ok(SettlementRoute::NoAction) => "no_action",
        Ok(SettlementRoute::RetryScheduled { .. }) => "retry_scheduled",
        Ok(SettlementRoute::DeadLettered { .. }) => "dead_lettered",
        Err(error) => settlement_persistence_error_class(error),
    }
}

const fn settlement_persistence_error_class(error: &SettlementRouteError) -> &'static str {
    match error.class() {
        SettlementRouteErrorClass::Backend => "backend_error",
        SettlementRouteErrorClass::Conflict => "conflict",
        SettlementRouteErrorClass::InvalidRecord => "invalid_record",
    }
}

fn record_unresolved(
    receipt_id: &str,
    outcome_class: &'static str,
    persistence_class: &'static str,
    metrics: &dyn SettlementRoutingMetrics,
) {
    tracing::warn!(
        receipt_id,
        outcome_class,
        persistence_class,
        "settlement observer outcome unresolved"
    );
    metrics.increment_unresolved();
}

pub(crate) fn record_unresolved_claim_failure(receipt_id: &str, error: &SettlementRouteError) {
    record_unresolved(
        receipt_id,
        "claim",
        settlement_persistence_error_class(error),
        &RuntimeSettlementRoutingMetrics,
    );
}

/// Record an attempt row that this transaction seeded but could not then observe.
///
/// The row stays due for a later claim, so this is not a failure of the receipt
/// write; it is work that no worker has picked up yet.
pub(crate) fn record_unresolved_claim_missed(receipt_id: &str) {
    record_unresolved_claim_missed_with_metrics(receipt_id, &RuntimeSettlementRoutingMetrics);
}

fn record_unresolved_claim_missed_with_metrics(
    receipt_id: &str,
    metrics: &dyn SettlementRoutingMetrics,
) {
    record_unresolved(receipt_id, "claim", "claim_missed", metrics);
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
    use chio_settle_types::{
        SettlementAttemptClaim, SettlementFailureClass, SettlementFailureCode,
        SettlementFailureReason, SettlementHookError, SettlementObservation, SettlementOutcome,
        SettlementRoute, SettlementRouteError, SettlementRoutingInput, SettlementSkipReason,
        SettlementStoreBinding,
    };

    use crate::{
        AtomicReceiptProjection, ChioKernel, KernelConfig, KernelError, MemoryBudgetConfig,
        PendingSettlementObservation, ReceiptStore, ReceiptStoreError,
        SettlementRuntimeConfigError, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };

    use super::*;

    struct NoopHook;

    impl SettlementHook for NoopHook {
        fn observe(
            &self,
            _observation: &SettlementObservation,
            _idempotency_key: &chio_settle_types::SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Ok(SettlementOutcome::accepted("noop"))
        }
    }

    struct TestAtomicStore {
        projection: AtomicReceiptProjection,
        binding: SettlementStoreBinding,
        exposes_binding: bool,
        reconciles: bool,
    }

    struct AtomicStoreWithoutTimeout {
        binding: SettlementStoreBinding,
    }

    struct RoutingOutcomeStore {
        claim: Result<Option<SettlementAttemptClaim>, SettlementRouteError>,
        route: Result<SettlementRoute, SettlementRouteError>,
        recorded: AtomicUsize,
    }

    impl RoutingOutcomeStore {
        fn new(route: Result<SettlementRoute, SettlementRouteError>) -> Arc<Self> {
            Arc::new(Self {
                claim: Ok(None),
                route,
                recorded: AtomicUsize::new(0),
            })
        }

        fn with_claim(claim: SettlementAttemptClaim) -> Arc<Self> {
            Arc::new(Self {
                claim: Ok(Some(claim)),
                route: Ok(SettlementRoute::NoAction),
                recorded: AtomicUsize::new(0),
            })
        }

        fn recorded_len(&self) -> usize {
            self.recorded.load(Ordering::SeqCst)
        }
    }

    impl SettlementOutcomeStore for RoutingOutcomeStore {
        fn settlement_store_binding(&self) -> SettlementStoreBinding {
            SettlementStoreBinding::from_digest([9; 32])
        }

        fn claim_receipt(
            &self,
            _receipt_id: &str,
            _worker_id: &str,
            _now_ms: u64,
            _lease_ms: u64,
        ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
            self.claim.clone()
        }

        fn claim_due(
            &self,
            _worker_id: &str,
            _now_ms: u64,
            _lease_ms: u64,
            _limit: usize,
        ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
            self.claim.clone().map(|claim| claim.into_iter().collect())
        }

        fn record_claimed_outcome(
            &self,
            _claim: &SettlementAttemptClaim,
            _outcome: &SettlementRoutingInput,
            _policy: RetryPolicy,
            _observed_at_ms: u64,
        ) -> Result<SettlementRoute, SettlementRouteError> {
            self.recorded.fetch_add(1, Ordering::SeqCst);
            self.route.clone()
        }
    }

    #[derive(Default)]
    struct FakeRoutingMetrics {
        calls: AtomicUsize,
    }

    impl SettlementRoutingMetrics for FakeRoutingMetrics {
        fn increment_unresolved(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl SettlementOutcomeStore for TestAtomicStore {
        fn settlement_store_binding(&self) -> SettlementStoreBinding {
            self.binding
        }

        fn claim_receipt(
            &self,
            _receipt_id: &str,
            _worker_id: &str,
            _now_ms: u64,
            _lease_ms: u64,
        ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
            Ok(None)
        }

        fn claim_due(
            &self,
            _worker_id: &str,
            _now_ms: u64,
            _lease_ms: u64,
            _limit: usize,
        ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
            Ok(Vec::new())
        }

        fn record_claimed_outcome(
            &self,
            _claim: &SettlementAttemptClaim,
            _outcome: &SettlementRoutingInput,
            _policy: RetryPolicy,
            _observed_at_ms: u64,
        ) -> Result<SettlementRoute, SettlementRouteError> {
            Ok(SettlementRoute::NoAction)
        }
    }

    impl ReceiptStore for TestAtomicStore {
        fn opening_status(
            &self,
            _receipt_id: &str,
        ) -> Result<crate::receipt_store::OpeningStatus, crate::receipt_store::ReceiptStoreError>
        {
            Ok(crate::receipt_store::OpeningStatus::Unknown)
        }
        fn read_openings(
            &self,
            _receipt_id: &str,
            _scope: &crate::receipt_store::OpeningReadScope,
        ) -> Result<crate::receipt_store::OpeningState, crate::receipt_store::ReceiptStoreError>
        {
            Ok(crate::receipt_store::OpeningState::Unknown)
        }
        fn erase_openings(
            &self,
            _receipt_id: &str,
            _erased_at: u64,
        ) -> Result<(), crate::receipt_store::ReceiptStoreError> {
            Err(crate::receipt_store::ReceiptStoreError::Unsupported(
                "test double holds no receipt openings".to_string(),
            ))
        }
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
            self.projection
        }

        fn supports_atomic_receipt_projection_with_timeout(&self) -> bool {
            self.projection == AtomicReceiptProjection::SettlementObservationV1
        }

        fn settlement_store_binding(&self) -> Option<SettlementStoreBinding> {
            self.exposes_binding.then_some(self.binding)
        }

        fn supports_settlement_reconciliation(&self) -> bool {
            self.reconciles
        }

        fn append_chio_receipt_with_pending_observation_and_timeout(
            &self,
            _receipt: &ChioReceipt,
            _pending: &PendingSettlementObservation,
            _budget: std::time::Duration,
        ) -> Result<Option<u64>, ReceiptStoreError> {
            match self.projection {
                AtomicReceiptProjection::SettlementObservationV1 => Ok(None),
                AtomicReceiptProjection::Unsupported => Err(ReceiptStoreError::Unsupported(
                    "atomic settlement observation projection".to_string(),
                )),
            }
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    impl ReceiptStore for AtomicStoreWithoutTimeout {
        fn opening_status(
            &self,
            _receipt_id: &str,
        ) -> Result<crate::receipt_store::OpeningStatus, crate::receipt_store::ReceiptStoreError>
        {
            Ok(crate::receipt_store::OpeningStatus::Unknown)
        }
        fn read_openings(
            &self,
            _receipt_id: &str,
            _scope: &crate::receipt_store::OpeningReadScope,
        ) -> Result<crate::receipt_store::OpeningState, crate::receipt_store::ReceiptStoreError>
        {
            Ok(crate::receipt_store::OpeningState::Unknown)
        }
        fn erase_openings(
            &self,
            _receipt_id: &str,
            _erased_at: u64,
        ) -> Result<(), crate::receipt_store::ReceiptStoreError> {
            Err(crate::receipt_store::ReceiptStoreError::Unsupported(
                "test double holds no receipt openings".to_string(),
            ))
        }
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn settlement_store_binding(&self) -> Option<SettlementStoreBinding> {
            Some(self.binding)
        }

        fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
            AtomicReceiptProjection::SettlementObservationV1
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    fn kernel() -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair: chio_core::crypto::Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: crate::HotPathDeadlineConfig::default(),
        })
    }

    fn hook() -> Arc<dyn SettlementHook> {
        Arc::new(NoopHook)
    }

    fn atomic_store(projection: AtomicReceiptProjection) -> Arc<TestAtomicStore> {
        atomic_store_with_binding(projection, 1)
    }

    fn atomic_store_with_binding(
        projection: AtomicReceiptProjection,
        binding_byte: u8,
    ) -> Arc<TestAtomicStore> {
        Arc::new(TestAtomicStore {
            projection,
            binding: SettlementStoreBinding::from_digest([binding_byte; 32]),
            exposes_binding: true,
            reconciles: false,
        })
    }

    fn unbound_atomic_store() -> Arc<TestAtomicStore> {
        Arc::new(TestAtomicStore {
            projection: AtomicReceiptProjection::SettlementObservationV1,
            binding: SettlementStoreBinding::from_digest([1; 32]),
            exposes_binding: false,
            reconciles: false,
        })
    }

    fn outcome_store(store: &Arc<TestAtomicStore>) -> Arc<dyn SettlementOutcomeStore> {
        store.clone()
    }

    fn receipt_store(store: &Arc<TestAtomicStore>) -> Arc<dyn ReceiptStore> {
        store.clone()
    }

    fn failure(code: SettlementFailureCode) -> SettlementFailureReason {
        SettlementFailureReason::from_detail(code, "detail")
    }

    fn attempt_claim(receipt_id: &str, finalized_at: u64) -> SettlementAttemptClaim {
        SettlementAttemptClaim {
            receipt_id: receipt_id.to_string(),
            finalized_at,
            attempts: 0,
            row_version: 1,
            lease_owner: INLINE_SETTLEMENT_WORKER_ID.to_string(),
            lease_token: "lease-token".to_string(),
            lease_until_ms: 10_000,
        }
    }

    fn routing_runtime(store: &Arc<RoutingOutcomeStore>) -> SettlementObserverRuntime {
        let outcome_store: Arc<dyn SettlementOutcomeStore> = store.clone();
        match SettlementObserverRuntime::new(
            hook(),
            outcome_store,
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(
                chio_core::crypto::Keypair::from_seed(&[61; 32]).public_key(),
            ),
        ) {
            Ok(runtime) => runtime,
            Err(error) => panic!("test runtime rejected: {error}"),
        }
    }

    #[test]
    fn settlement_status_normalization_is_exhaustive() {
        let rpc = failure(SettlementFailureCode::Rpc);
        let invalid = failure(SettlementFailureCode::InvalidBinding);
        let cases = [
            (SettlementObserverStatus::NotRegistered, None),
            (
                SettlementObserverStatus::Skipped {
                    reason: SettlementSkipReason::ZeroCharge,
                },
                Some(SettlementRoutingInput::Skipped {
                    reason: SettlementSkipReason::ZeroCharge,
                }),
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::accepted("transcript"),
                },
                Some(SettlementRoutingInput::Accepted),
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::skipped(SettlementSkipReason::Denied),
                },
                Some(SettlementRoutingInput::Permanent {
                    reason: SettlementFailureReason::from_detail(
                        SettlementFailureCode::InvalidObservation,
                        INVALID_HOOK_SKIP_DETAIL,
                    ),
                }),
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::retryable(rpc.clone()),
                },
                Some(SettlementRoutingInput::Retryable {
                    reason: rpc.clone(),
                }),
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::permanent(invalid.clone()),
                },
                Some(SettlementRoutingInput::Permanent {
                    reason: invalid.clone(),
                }),
            ),
            (
                SettlementObserverStatus::HookFailed {
                    class: SettlementFailureClass::Retryable,
                    reason: rpc.clone(),
                },
                Some(SettlementRoutingInput::Retryable { reason: rpc }),
            ),
            (
                SettlementObserverStatus::HookFailed {
                    class: SettlementFailureClass::Permanent,
                    reason: invalid.clone(),
                },
                Some(SettlementRoutingInput::Permanent { reason: invalid }),
            ),
        ];

        for (status, expected) in cases {
            assert_eq!(normalize_status(&status), expected);
        }
    }

    #[test]
    fn normalizer_rejects_an_unsupported_outcome_schema() {
        let status = SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Accepted {
                schema: "chio.settle.outcome.v99".to_string(),
                transcript_id: "transcript-1".to_string(),
            },
        };

        assert!(matches!(
            normalize_status(&status),
            Some(SettlementRoutingInput::Permanent { reason })
                if reason.code() == SettlementFailureCode::InvalidObservation
        ));
    }

    #[test]
    fn normalizer_rejects_an_accepted_outcome_with_an_invalid_transcript_id() {
        for transcript_id in [
            String::new(),
            " \n".to_string(),
            "x".repeat(MAX_TRANSCRIPT_ID_BYTES + 1),
            "transcript\u{7}".to_string(),
        ] {
            let status = SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::accepted(transcript_id.clone()),
            };
            assert!(
                matches!(
                    normalize_status(&status),
                    Some(SettlementRoutingInput::Permanent { reason })
                        if reason.code() == SettlementFailureCode::InvalidObservation
                ),
                "transcript id {transcript_id:?} must dead-letter"
            );
        }

        let bounded = SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::accepted("x".repeat(MAX_TRANSCRIPT_ID_BYTES)),
        };
        assert_eq!(
            normalize_status(&bounded),
            Some(SettlementRoutingInput::Accepted)
        );
    }

    #[test]
    fn normalizer_rejects_retry_for_a_known_permanent_code() {
        let outcome = match serde_json::from_value::<SettlementOutcome>(serde_json::json!({
            "kind": "retryable",
            "schema": chio_settle_types::SETTLEMENT_OUTCOME_SCHEMA,
            "reason": {
                "code": "invalid_receipt_signature",
                "detail_sha256": vec![0_u8; 32],
            },
        })) {
            Ok(outcome) => outcome,
            Err(error) => panic!("test outcome deserialization failed: {error}"),
        };
        let expected = SettlementFailureReason::from_digest(
            SettlementFailureCode::InvalidReceiptSignature,
            [0; 32],
        );

        assert_eq!(
            normalize_status(&SettlementObserverStatus::Observed { outcome }),
            Some(SettlementRoutingInput::Permanent { reason: expected })
        );
    }

    #[test]
    fn routing_sink_counts_each_unresolved_invocation_once() {
        let retryable = failure(SettlementFailureCode::Rpc);
        let permanent = failure(SettlementFailureCode::InvalidBinding);
        let cases = vec![
            (
                SettlementObserverStatus::NotRegistered,
                Ok(SettlementRoute::NoAction),
                0,
                0,
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::accepted("transcript"),
                },
                Ok(SettlementRoute::NoAction),
                0,
                1,
            ),
            (
                SettlementObserverStatus::Skipped {
                    reason: SettlementSkipReason::ZeroCharge,
                },
                Ok(SettlementRoute::NoAction),
                0,
                1,
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::accepted("transcript"),
                },
                Err(SettlementRouteError::Backend {
                    detail: "unbounded backend detail".to_string(),
                }),
                1,
                1,
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::accepted("transcript"),
                },
                Ok(SettlementRoute::RetryScheduled {
                    attempt: 1,
                    next_visible_at_ms: 20,
                }),
                1,
                1,
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::retryable(retryable.clone()),
                },
                Ok(SettlementRoute::RetryScheduled {
                    attempt: 1,
                    next_visible_at_ms: 20,
                }),
                1,
                1,
            ),
            (
                SettlementObserverStatus::Observed {
                    outcome: SettlementOutcome::permanent(permanent.clone()),
                },
                Ok(SettlementRoute::DeadLettered { attempts: 1 }),
                1,
                1,
            ),
            (
                SettlementObserverStatus::HookFailed {
                    class: SettlementFailureClass::Retryable,
                    reason: retryable,
                },
                Err(SettlementRouteError::Conflict {
                    detail: "stale lease".to_string(),
                }),
                0,
                1,
            ),
        ];

        for (status, route, expected_metrics, expected_records) in cases {
            let store = RoutingOutcomeStore::new(route);
            let runtime = routing_runtime(&store);
            let metrics = FakeRoutingMetrics::default();
            let _completion = runtime.record_claimed_status_with_metrics(
                &attempt_claim("receipt-1", 1),
                &status,
                2,
                &metrics,
            );

            assert_eq!(metrics.calls.load(Ordering::SeqCst), expected_metrics);
            assert_eq!(store.recorded_len(), expected_records);
        }

        let claim_metrics = FakeRoutingMetrics::default();
        record_unresolved("receipt-1", "claim", "backend_error", &claim_metrics);
        assert_eq!(claim_metrics.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_unclaimed_attempt_row_is_reported_as_unresolved() {
        let metrics = FakeRoutingMetrics::default();

        record_unresolved_claim_missed_with_metrics("receipt-1", &metrics);

        assert_eq!(metrics.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn claim_validation_rejects_a_row_for_another_receipt() {
        let store = RoutingOutcomeStore::with_claim(attempt_claim("receipt-b", 7));
        let runtime = routing_runtime(&store);

        let result = runtime.claim_receipt("receipt-a", 7, 1);

        assert!(matches!(
            result,
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        assert_eq!(store.recorded_len(), 0);
    }

    #[test]
    fn runtime_retains_the_complete_routing_configuration() {
        let hook = hook();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        let outcome_store = outcome_store(&store);
        let policy = RetryPolicy::default();
        let runtime = match SettlementObserverRuntime::new(
            Arc::clone(&hook),
            Arc::clone(&outcome_store),
            policy,
            crate::SettlementDrainTrust::from(
                chio_core::crypto::Keypair::from_seed(&[61; 32]).public_key(),
            ),
        ) {
            Ok(runtime) => runtime,
            Err(error) => panic!("valid runtime rejected: {error}"),
        };

        assert!(Arc::ptr_eq(&runtime.hook(), &hook));
        assert!(Arc::ptr_eq(&runtime.outcome_store, &outcome_store));
        assert_eq!(runtime.retry_policy, policy);
    }

    #[test]
    fn installer_allows_receipt_store_to_be_attached_after_the_runtime() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(result.is_ok());
        assert!(kernel.settlement_observer().is_some());
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
    }

    #[test]
    fn installer_rejects_a_receipt_store_without_atomic_projection() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::Unsupported);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::UnsupportedAtomicProjection
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn installer_rejects_an_atomic_store_without_timeout_support() {
        let mut kernel = kernel();
        let store = Arc::new(AtomicStoreWithoutTimeout {
            binding: SettlementStoreBinding::from_digest([9; 32]),
        });
        let receipt_store: Arc<dyn ReceiptStore> = store;
        assert!(kernel.set_receipt_store_handle(receipt_store).is_ok());
        let outcomes = RoutingOutcomeStore::new(Ok(SettlementRoute::NoAction));
        let outcome_store: Arc<dyn SettlementOutcomeStore> = outcomes;

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store,
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::UnsupportedAtomicProjection
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn installer_rejects_an_invalid_retry_policy() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
        let invalid_policy = RetryPolicy {
            max_retries: 33,
            ..RetryPolicy::default()
        };

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            invalid_policy,
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::InvalidRetryPolicy(
                    chio_settle_types::RetryPolicyError::MaxRetriesTooHigh { max_retries: 33 }
                )
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn claim_completion_reports_persistence_failures_and_lost_leases() {
        let accepted = SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::accepted("accepted"),
        };
        let cases = [
            (
                Ok(SettlementRoute::NoAction),
                Ok(SettlementCompletion::Recorded(SettlementRoute::NoAction)),
            ),
            (
                Err(SettlementRouteError::Conflict {
                    detail: "stale lease".to_string(),
                }),
                Ok(SettlementCompletion::LostLease),
            ),
            (
                Err(SettlementRouteError::Backend {
                    detail: "disk full".to_string(),
                }),
                Err(SettlementRouteError::Backend {
                    detail: "disk full".to_string(),
                }),
            ),
            (
                Err(SettlementRouteError::InvalidRecord {
                    detail: "corrupt row".to_string(),
                }),
                Err(SettlementRouteError::InvalidRecord {
                    detail: "corrupt row".to_string(),
                }),
            ),
        ];
        for (route, expected) in cases {
            let store = RoutingOutcomeStore::new(route);
            let runtime = routing_runtime(&store);

            let completion = runtime.complete_claim(&attempt_claim("receipt-1", 1), &accepted, 2);

            assert_eq!(completion, expected);
            assert_eq!(store.recorded_len(), 1);
        }
    }

    #[test]
    fn claim_completion_refuses_an_unregistered_status() {
        let store = RoutingOutcomeStore::new(Ok(SettlementRoute::NoAction));
        let runtime = routing_runtime(&store);

        let completion = runtime.complete_claim(
            &attempt_claim("receipt-1", 1),
            &SettlementObserverStatus::NotRegistered,
            2,
        );

        assert_eq!(
            completion,
            Err(SettlementRouteError::InvalidRecord {
                detail: "settlement status has no registered hook outcome".to_string(),
            })
        );
        assert_eq!(store.recorded_len(), 0);
    }

    #[test]
    fn drain_claim_rejects_a_row_leased_to_another_worker() {
        let store = RoutingOutcomeStore::with_claim(attempt_claim("receipt-a", 7));
        let runtime = routing_runtime(&store);

        let result = runtime.claim_due(1, 4);

        assert_eq!(
            result,
            Err(SettlementRouteError::InvalidRecord {
                detail: "claimed settlement batch does not match the drain lease".to_string(),
            })
        );
        assert_eq!(store.recorded_len(), 0);
    }

    #[test]
    fn ledger_install_refuses_a_kernel_without_a_receipt_store() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);

        let result = kernel.install_settlement_ledger(
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::MissingReceiptStore
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn ledger_install_refuses_a_store_that_cannot_record_reconciliations() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.install_settlement_ledger(
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::UnsupportedSettlementLedger
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn ledger_install_keeps_the_atomic_projection_requirement() {
        let mut kernel = kernel();
        let store = Arc::new(TestAtomicStore {
            projection: AtomicReceiptProjection::Unsupported,
            binding: SettlementStoreBinding::from_digest([1; 32]),
            exposes_binding: true,
            reconciles: true,
        });
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.install_settlement_ledger(
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::UnsupportedAtomicProjection
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn ledger_install_succeeds_on_a_reconciling_atomic_store() {
        let mut kernel = kernel();
        let store = Arc::new(TestAtomicStore {
            projection: AtomicReceiptProjection::SettlementObservationV1,
            binding: SettlementStoreBinding::from_digest([1; 32]),
            exposes_binding: true,
            reconciles: true,
        });
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.install_settlement_ledger(
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(result.is_ok());
        assert!(kernel.settlement_observer().is_some());
    }

    #[test]
    fn installer_accepts_a_complete_atomic_runtime() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(result.is_ok());
        assert!(kernel.settlement_observer().is_some());
    }

    #[test]
    fn installer_accepts_separate_handles_with_the_same_store_binding() {
        let mut kernel = kernel();
        let receipt_store_backend = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        let outcome_store_backend =
            atomic_store_with_binding(AtomicReceiptProjection::SettlementObservationV1, 1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&receipt_store_backend))
            .is_ok());

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&outcome_store_backend),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(result.is_ok());
        assert!(kernel.settlement_observer().is_some());
    }

    #[test]
    fn installer_rejects_mismatched_store_bindings() {
        let mut kernel = kernel();
        let receipt_store_backend = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        let outcome_store_backend =
            atomic_store_with_binding(AtomicReceiptProjection::SettlementObservationV1, 2);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&receipt_store_backend))
            .is_ok());

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&outcome_store_backend),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::StoreBindingMismatch
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn installer_rejects_a_missing_receipt_store_binding() {
        let mut kernel = kernel();
        let store = unbound_atomic_store();
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            RetryPolicy::default(),
            crate::SettlementDrainTrust::from(kernel.public_key()),
        );

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::MissingStoreBinding
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
    }

    #[test]
    fn installed_runtime_rejects_a_non_atomic_receipt_store() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
        assert!(kernel
            .set_settlement_observer_runtime(
                hook(),
                outcome_store(&store),
                RetryPolicy::default(),
                crate::SettlementDrainTrust::from(kernel.public_key())
            )
            .is_ok());
        let replacement = atomic_store(AtomicReceiptProjection::Unsupported);

        let result = kernel.set_receipt_store_handle(receipt_store(&replacement));

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::UnsupportedAtomicProjection
            ))
        ));
        assert!(kernel.settlement_observer().is_some());
    }

    #[test]
    fn installed_runtime_accepts_a_compatible_atomic_store_replacement() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
        assert!(kernel
            .set_settlement_observer_runtime(
                hook(),
                outcome_store(&store),
                RetryPolicy::default(),
                crate::SettlementDrainTrust::from(kernel.public_key())
            )
            .is_ok());
        let replacement = atomic_store(AtomicReceiptProjection::SettlementObservationV1);

        let result = kernel.set_receipt_store_handle(receipt_store(&replacement));

        assert!(result.is_ok());
        assert!(kernel.settlement_observer().is_some());
    }
}
