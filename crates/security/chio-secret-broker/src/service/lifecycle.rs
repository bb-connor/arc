use super::{
    attempt_operation_gate_index, failure_receipt_key_digest, Arc, AtomicU64, AttemptStore,
    BrokerError, BrokerExecuteRequest, BrokerService, BrokerServiceAuthorityBundle,
    BrokerServiceConfig, Mutex, MutexGuard, Ordering, ProductionSqliteAttemptStore, Result,
    RetainedDispatchCustody,
};

impl BrokerService {
    pub(crate) fn new_production(
        config: BrokerServiceConfig,
        attempts: ProductionSqliteAttemptStore,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        let mut service =
            Self::from_authorities(config, attempts.into_attempt_store()?, authorities)?;
        service.authority_clock = Some(Arc::new(crate::daemon::SystemClock));
        Ok(service)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        config: BrokerServiceConfig,
        attempts: Arc<dyn AttemptStore>,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        Self::from_authorities(config, attempts, authorities)
    }

    fn from_authorities(
        config: BrokerServiceConfig,
        attempts: Arc<dyn AttemptStore>,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        config.validate()?;
        authorities.validate_for_production()?;
        let BrokerServiceAuthorityBundle {
            trusted_issuer,
            backend,
            provider,
            https,
            budget,
            liveness,
            revocations,
            receipt_sink,
            receipt_signer,
            migration_enforcer,
        } = authorities;
        Ok(Self {
            // Only unit fixtures use their explicitly supplied observation time.
            // The production constructor always installs the system clock.
            authority_clock: None,
            config,
            trusted_issuer,
            backend,
            provider,
            https,
            attempts,
            budget,
            liveness,
            revocations,
            receipt_sink,
            receipt_signer,
            migration_enforcer,
            attempt_operation_gates: std::array::from_fn(|_| Mutex::new(())),
            retained_dispatches: RetainedDispatchCustody::default(),
            dispatch_claim_counter: AtomicU64::new(0),
        })
    }

    fn attempt_operation_guard_for_digest(&self, digest: &str) -> Result<MutexGuard<'_, ()>> {
        let gate_index = attempt_operation_gate_index(digest)?;
        self.attempt_operation_gates
            .get(gate_index)
            .ok_or_else(|| {
                BrokerError::Invariant("broker attempt gate index is invalid".to_owned())
            })?
            .lock()
            .map_err(|_| {
                BrokerError::Invariant("broker attempt operation gate is poisoned".to_string())
            })
    }

    pub(super) fn attempt_operation_guard_for_request(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<MutexGuard<'_, ()>> {
        self.attempt_operation_guard_for_digest(&failure_receipt_key_digest(request)?)
    }

    pub(super) fn next_dispatch_claim_id(&self) -> Result<String> {
        let previous = self
            .dispatch_claim_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| BrokerError::Invariant("dispatch claim counter overflowed".to_string()))?;
        let sequence = previous + 1;
        Ok(format!(
            "broker-dispatch-claim-{}-{sequence}",
            std::process::id()
        ))
    }

    pub(crate) fn require_migrations_for_provider(&self, credential_provider: &str) -> Result<()> {
        self.migration_enforcer
            .require_provider_enforced(credential_provider)
    }
}
