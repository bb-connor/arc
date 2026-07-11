use std::sync::Arc;

use chio_settle::{RetryPolicy, RetryPolicyError, SettlementHook, SettlementOutcomeStore};

#[cfg(test)]
use crate::kernel::settlement_observer::SettlementObserverStatus;
#[cfg(test)]
use chio_settle::{SettlementFailureClass, SettlementOutcome, SettlementRoutingInput};

#[cfg(test)]
const INVALID_HOOK_SKIP_DETAIL: &str =
    "settlement hook returned skipped for a positive economic observation";

pub(crate) struct SettlementObserverRuntime {
    hook: Arc<dyn SettlementHook>,
    #[allow(dead_code)]
    outcome_store: Arc<dyn SettlementOutcomeStore>,
    #[allow(dead_code)]
    retry_policy: RetryPolicy,
    store_binding: chio_settle::SettlementStoreBinding,
}

impl SettlementObserverRuntime {
    pub(crate) fn new(
        hook: Arc<dyn SettlementHook>,
        outcome_store: Arc<dyn SettlementOutcomeStore>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, RetryPolicyError> {
        retry_policy.validate()?;
        let store_binding = outcome_store.settlement_store_binding();
        Ok(Self {
            hook,
            outcome_store,
            retry_policy,
            store_binding,
        })
    }

    pub(crate) fn hook(&self) -> Arc<dyn SettlementHook> {
        Arc::clone(&self.hook)
    }

    pub(crate) fn hook_ref(&self) -> &Arc<dyn SettlementHook> {
        &self.hook
    }

    #[cfg(test)]
    pub(crate) fn outcome_store(&self) -> &Arc<dyn SettlementOutcomeStore> {
        &self.outcome_store
    }

    #[cfg(test)]
    pub(crate) const fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub(crate) const fn store_binding(&self) -> chio_settle::SettlementStoreBinding {
        self.store_binding
    }
}

#[cfg(test)]
fn normalize_failure(
    class: SettlementFailureClass,
    reason: &chio_settle::SettlementFailureReason,
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

#[cfg(test)]
pub(crate) fn normalize_status(
    status: &SettlementObserverStatus,
) -> Option<SettlementRoutingInput> {
    match status {
        SettlementObserverStatus::NotRegistered => None,
        SettlementObserverStatus::Skipped { reason } => {
            Some(SettlementRoutingInput::Skipped { reason: *reason })
        }
        SettlementObserverStatus::Observed { outcome } if !outcome.has_supported_schema() => {
            Some(SettlementRoutingInput::Permanent {
                reason: chio_settle::SettlementFailureReason::from_detail(
                    chio_settle::SettlementFailureCode::InvalidObservation,
                    "unsupported settlement outcome schema",
                ),
            })
        }
        SettlementObserverStatus::Observed { outcome } => Some(match outcome {
            SettlementOutcome::Accepted { .. } => SettlementRoutingInput::Accepted,
            SettlementOutcome::Skipped { .. } => SettlementRoutingInput::Permanent {
                reason: chio_settle::SettlementFailureReason::from_detail(
                    chio_settle::SettlementFailureCode::InvalidObservation,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
    use chio_settle::{
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
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Ok(SettlementOutcome::accepted("noop"))
        }
    }

    struct TestAtomicStore {
        projection: AtomicReceiptProjection,
        binding: SettlementStoreBinding,
        exposes_binding: bool,
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
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
            self.projection
        }

        fn settlement_store_binding(&self) -> Option<SettlementStoreBinding> {
            self.exposes_binding.then_some(self.binding)
        }

        fn append_chio_receipt_with_pending_observation(
            &self,
            _receipt: &ChioReceipt,
            _pending: &PendingSettlementObservation,
        ) -> Result<(), ReceiptStoreError> {
            match self.projection {
                AtomicReceiptProjection::SettlementObservationV1 => Ok(()),
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
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
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
        })
    }

    fn unbound_atomic_store() -> Arc<TestAtomicStore> {
        Arc::new(TestAtomicStore {
            projection: AtomicReceiptProjection::SettlementObservationV1,
            binding: SettlementStoreBinding::from_digest([1; 32]),
            exposes_binding: false,
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
    fn normalizer_rejects_retry_for_a_known_permanent_code() {
        let outcome = match serde_json::from_value::<SettlementOutcome>(serde_json::json!({
            "kind": "retryable",
            "schema": chio_settle::SETTLEMENT_OUTCOME_SCHEMA,
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
    fn runtime_retains_the_complete_routing_configuration() {
        let hook = hook();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        let outcome_store = outcome_store(&store);
        let policy = RetryPolicy::default();
        let runtime = match SettlementObserverRuntime::new(
            Arc::clone(&hook),
            Arc::clone(&outcome_store),
            policy,
        ) {
            Ok(runtime) => runtime,
            Err(error) => panic!("valid runtime rejected: {error}"),
        };

        assert!(Arc::ptr_eq(&runtime.hook(), &hook));
        assert!(Arc::ptr_eq(runtime.outcome_store(), &outcome_store));
        assert_eq!(runtime.retry_policy(), policy);
    }

    #[test]
    fn installer_rejects_a_missing_receipt_store() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);

        let result = kernel.set_settlement_observer_runtime(
            hook(),
            outcome_store(&store),
            RetryPolicy::default(),
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

        let result =
            kernel.set_settlement_observer_runtime(hook(), outcome_store(&store), invalid_policy);

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::InvalidRetryPolicy(
                    chio_settle::RetryPolicyError::MaxRetriesTooHigh { max_retries: 33 }
                )
            ))
        ));
        assert!(kernel.settlement_observer().is_none());
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
    fn installed_runtime_rejects_non_atomic_store_replacement() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
        assert!(kernel
            .set_settlement_observer_runtime(hook(), outcome_store(&store), RetryPolicy::default(),)
            .is_ok());
        let replacement = atomic_store(AtomicReceiptProjection::Unsupported);

        let result = kernel.set_receipt_store_handle(receipt_store(&replacement));

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::ReceiptStoreReplacement
            ))
        ));
        assert!(kernel.settlement_observer().is_some());
    }

    #[test]
    fn installed_runtime_rejects_atomic_store_replacement() {
        let mut kernel = kernel();
        let store = atomic_store(AtomicReceiptProjection::SettlementObservationV1);
        assert!(kernel
            .set_receipt_store_handle(receipt_store(&store))
            .is_ok());
        assert!(kernel
            .set_settlement_observer_runtime(hook(), outcome_store(&store), RetryPolicy::default(),)
            .is_ok());
        let replacement = atomic_store(AtomicReceiptProjection::SettlementObservationV1);

        let result = kernel.set_receipt_store_handle(receipt_store(&replacement));

        assert!(matches!(
            result,
            Err(KernelError::SettlementConfiguration(
                SettlementRuntimeConfigError::ReceiptStoreReplacement
            ))
        ));
        assert!(kernel.settlement_observer().is_some());
    }
}
