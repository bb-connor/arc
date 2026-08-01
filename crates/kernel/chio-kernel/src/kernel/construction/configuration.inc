impl ChioKernel {
    pub fn set_agent_economy_payment_adapter(
        &mut self,
        payment_adapter: Box<dyn crate::agent_economy_payment::PaymentAdapter>,
    ) {
        self.agent_economy_payment_adapter = Some(payment_adapter);
    }

    /// Install or safely replace the payment rail authority. A replacement
    /// first drains operation-owned payment work, then reconciles any durable
    /// payment-journal rows that became resolvable when the adapter attached.
    pub fn set_payment_adapter(
        &mut self,
        payment_adapter: Box<dyn PaymentAdapter>,
    ) -> Result<(), KernelError> {
        self.try_set_payment_adapter(payment_adapter)
    }

    pub fn try_set_payment_adapter(
        &mut self,
        payment_adapter: Box<dyn PaymentAdapter>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if (self.aggregate_invocation_admission_enabled
            || self.supplemental_broker_admission_enabled)
            && (!payment_adapter.supports_operation_authorization_recovery()
                || !payment_adapter.supports_operation_payment_mutations())
        {
            return Err(KernelError::Internal(
                "operation-owned ordinary admission requires authoritative authorization lookup and operation-bound payment mutations"
                    .to_string(),
            ));
        }
        if (self.aggregate_invocation_admission_enabled
            || self.supplemental_broker_admission_enabled)
            && !self
                .budget_store
                .supports_durable_atomic_payment_journal()
        {
            return Err(KernelError::Internal(
                "operation-owned payment admission requires a durable budget store that atomically co-commits payment-journal state"
                    .to_string(),
            ));
        }
        if self.payment_adapter.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.payment_adapter = Some(payment_adapter);
        if self.receipt_store.is_some() && self.payment_journal_active() {
            match self.reconcile_payment_journal(0) {
                Ok(report) => {
                    if report.resolved > 0
                        || report.reconcile_failed > 0
                        || report.deferred_to_admission_operation > 0
                    {
                        tracing::warn!(
                            resolved = report.resolved,
                            reconcile_failed = report.reconcile_failed,
                            deferred_to_admission_operation = report.deferred_to_admission_operation,
                            "payment journal rows survived a restart; reconciled at adapter install"
                        );
                    }
                }
                Err(error) => {
                    self.payment_adapter = None;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub fn set_price_oracle(&mut self, price_oracle: Box<dyn PriceOracle>) {
        self.price_oracle = Some(price_oracle);
    }

    pub fn set_attestation_trust_policy(
        &mut self,
        attestation_trust_policy: AttestationTrustPolicy,
    ) {
        self.attestation_trust_policy = Some(attestation_trust_policy);
    }

    /// Accept the default in-memory revocation store instead of requiring a
    /// durable one. A locally-run kernel with no durable or remote revocation
    /// backend keeps its revocation set in memory, so the durability gate would
    /// otherwise deny every dispatch. Opting in here relaxes the gate
    /// only while the store is genuinely ephemeral: installing a durable store
    /// (or a revocation view) satisfies the gate on its own regardless of this
    /// flag. Intended for local, interactive runtimes; deployments that must
    /// survive restart should wire a durable store instead of calling this.
    pub fn opt_in_ephemeral_revocation_store(&mut self) {
        self.config.allow_ephemeral_revocation_store = true;
    }

    pub fn set_revocation_store(&mut self, revocation_store: Box<dyn RevocationStore>) {
        self.set_revocation_store_handle(Arc::from(revocation_store));
    }

    pub fn set_revocation_store_handle(&mut self, revocation_store: Arc<dyn RevocationStore>) {
        self.revocation_store = revocation_store;
    }

    pub fn set_capability_authority(
        &mut self,
        capability_authority: Box<dyn CapabilityAuthority>,
    ) -> Result<(), KernelError> {
        self.require_threshold_deactivated_for_authority_change()?;
        if self.authority_composition_sealed {
            return Err(KernelError::Internal(
                "authority composition is permanently sealed".to_string(),
            ));
        }
        if self.authority_signing_used.load(Ordering::Acquire) {
            return Err(KernelError::Internal(
                "capability authority cannot be replaced after authority signing has begun"
                    .to_string(),
            ));
        }
        if capability_authority.authority_public_key() != self.public_key() {
            return Err(KernelError::Internal(
                "capability authority replacement would split the runtime signing authority"
                    .to_string(),
            ));
        }
        self.capability_authority = capability_authority;
        Ok(())
    }

    /// Install a capability authority whose signing identity is intentionally
    /// separate from this kernel's evidence-signing identity.
    ///
    /// Hosted runtimes use this closed composition surface when the kernel
    /// signs its own receipts, anchors, nonces, and checkpoints while a remote
    /// capability authority issues policy-scoped tokens. The replacement is
    /// permitted only before either signing domain has been used or the
    /// authority topology has been sealed.
    pub fn set_external_capability_authority(
        &mut self,
        capability_authority: Box<dyn CapabilityAuthority>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        if self.authority_backend_topology_locked || self.authority_composition_sealed {
            return Err(KernelError::Internal(
                "external capability authority topology is permanently locked".to_string(),
            ));
        }
        if self.authority_signing_used.load(Ordering::Acquire)
            || !self.signing_task.is_pristine()
            || self.receipt_store.is_some()
            || !self.sessions.is_empty()
        {
            return Err(KernelError::Internal(
                "external capability authority must be installed before kernel evidence signing or durable receipt configuration"
                    .to_string(),
            ));
        }
        self.capability_authority = capability_authority;
        Ok(())
    }

    pub fn set_budget_store(
        &mut self,
        budget_store: Box<dyn BudgetStore>,
    ) -> Result<(), KernelError> {
        self.set_budget_store_handle(Arc::from(budget_store))
    }

    pub fn set_budget_store_handle(
        &mut self,
        budget_store: Arc<dyn BudgetStore>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if Arc::ptr_eq(&self.budget_store, &budget_store) {
            return Ok(());
        }
        self.require_threshold_deactivated_for_authority_change()?;
        self.require_protocol_budget_admission_deactivated_for_authority_change()?;
        if self.partition_escrow_registry.is_some() {
            return Err(KernelError::Internal(
                "partition escrow permanently binds the installed budget store".to_string(),
            ));
        }
        self.prepare_current_admission_authority_replacement()?;
        self.budget_store = budget_store;
        Ok(())
    }

    pub fn install_partition_escrow_registry(
        &mut self,
        registry: Arc<crate::partition_escrow::PartitionEscrowRegistry>,
    ) -> Result<(), KernelError> {
        if self
            .partition_escrow_registry
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, &registry))
        {
            return Ok(());
        }
        if self.partition_escrow_registry.is_some() {
            return Err(KernelError::Internal(
                "partition escrow registry replacement is not supported".to_string(),
            ));
        }
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        self.require_protocol_budget_admission_deactivated_for_authority_change()?;
        if self.admission_capture_authority.is_none() {
            return Err(KernelError::Internal(
                "partition escrow registry requires an exact admission capture authority"
                    .to_string(),
            ));
        }
        if !matches!(
            self.budget_store.budget_guarantee_level(),
            crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed
        ) {
            return Err(KernelError::Internal(
                "partition escrow registry requires a partition-escrowed budget store"
                    .to_string(),
            ));
        }
        let store_binding = self
            .budget_store
            .partition_escrow_store_binding()?
            .ok_or_else(|| {
                KernelError::Internal(
                    "partition-escrowed budget store omitted its durable counter binding"
                        .to_string(),
                )
            })?;
        let expected = registry.durable_store();
        if store_binding.store_identity_digest() != expected.store_identity_digest()
            || store_binding.counter_namespace_digest() != expected.counter_namespace_digest()
            || store_binding.fencing_token() != expected.fencing_token()
        {
            return Err(KernelError::Internal(
                "partition escrow registry does not match the installed durable counter binding"
                .to_string(),
            ));
        }
        Self::validate_hard_budget_store_profile(
            self.budget_store.as_ref(),
            self.dispatch_worker_count,
            Some(registry.as_ref()),
        )?;
        self.partition_escrow_registry = Some(registry);
        Ok(())
    }

    /// Returns whether the frozen governed runtime retained one exact budget
    /// authority. This exposes identity only, never the authority handle.
    #[must_use]
    pub fn governed_runtime_uses_budget_authority(&self, expected: &Arc<dyn BudgetStore>) -> bool {
        self.governed_security_runtime_generation != 0 && Arc::ptr_eq(&self.budget_store, expected)
    }

    pub fn set_dispatch_worker_count(
        &mut self,
        dispatch_worker_count: usize,
    ) -> Result<(), KernelError> {
        if dispatch_worker_count == 0 {
            return Err(KernelError::Internal(
                "dispatch worker count must be greater than zero".to_string(),
            ));
        }
        if let Some(store) = self.admission_operation_store.as_ref() {
            Self::validate_admission_operation_store_profile(
                store.authority_profile(),
                dispatch_worker_count,
            )?;
        }
        if let Some(store) = self.approval_store.as_ref() {
            Self::validate_approval_store_profile(
                store.authority_profile(),
                dispatch_worker_count,
            )?;
        }
        if self.threshold_governed_approvals_enabled {
            if !self
                .budget_store
                .authority_profile()
                .supports_dispatch_workers(dispatch_worker_count)
            {
                return Err(KernelError::Internal(
                    "threshold budget store cannot coordinate the requested worker topology"
                        .to_string(),
                ));
            }
            if let Some(store) = self.execution_nonce_store.as_deref() {
                if !store
                    .authority_profile()
                    .supports_dispatch_workers(dispatch_worker_count)
                {
                    return Err(KernelError::Internal(
                        "threshold execution nonce store cannot coordinate the requested worker topology"
                            .to_string(),
                    ));
                }
            }
        }
        if self.aggregate_invocation_admission_enabled
            || self.supplemental_broker_admission_enabled
            || self.partition_escrow_registry.is_some()
        {
            Self::validate_hard_budget_store_profile(
                self.budget_store.as_ref(),
                dispatch_worker_count,
                self.partition_escrow_registry.as_deref(),
            )?;
            let store = self.admission_operation_store.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "aggregate admission operation store is not installed".to_string(),
                )
            })?;
            Self::validate_admission_operation_store_profile(
                store.authority_profile(),
                dispatch_worker_count,
            )?;
        }
        self.dispatch_worker_count = dispatch_worker_count;
        Ok(())
    }

    pub fn set_admission_operation_store(
        &mut self,
        store: Box<dyn crate::security_admission_operation::AdmissionOperationStore>,
    ) -> Result<(), KernelError> {
        self.set_admission_operation_store_handle(Arc::from(store))
    }

    pub fn set_admission_operation_store_handle(
        &mut self,
        store: Arc<dyn crate::security_admission_operation::AdmissionOperationStore>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if self
            .admission_operation_store
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &store))
        {
            return Ok(());
        }
        self.require_threshold_deactivated_for_authority_change()?;
        self.require_protocol_budget_admission_deactivated_for_authority_change()?;
        Self::validate_admission_operation_store_profile(
            store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        if self.admission_operation_store.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.admission_operation_store = Some(store);
        Ok(())
    }

    pub fn clear_admission_operation_store(&mut self) {
        if self.has_atomic_security_runtime_publication()
            || self
                .prepare_current_admission_authority_replacement()
                .is_err()
        {
            return;
        }
        self.admission_operation_store = None;
        self.threshold_governed_approvals_enabled = false;
        self.aggregate_invocation_admission_enabled = false;
        self.supplemental_broker_admission_enabled = false;
    }

    pub fn set_approval_store(
        &mut self,
        store: Box<dyn crate::approval::ApprovalStore>,
    ) -> Result<(), KernelError> {
        self.set_approval_store_handle(Arc::from(store))
    }

    pub fn set_approval_store_handle(
        &mut self,
        store: Arc<dyn crate::approval::ApprovalStore>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if self
            .approval_store
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &store))
        {
            return Ok(());
        }
        self.require_threshold_deactivated_for_authority_change()?;
        Self::validate_approval_store_profile(
            store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        if self.approval_store.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.approval_store = Some(store);
        Ok(())
    }

    pub fn clear_approval_store(&mut self) {
        if self.has_atomic_security_runtime_publication()
            || self
                .prepare_current_admission_authority_replacement()
                .is_err()
        {
            return;
        }
        self.approval_store = None;
        self.threshold_governed_approvals_enabled = false;
    }

    pub(super) fn validate_approval_store_profile(
        profile: crate::approval::ApprovalStoreProfile,
        dispatch_worker_count: usize,
    ) -> Result<(), KernelError> {
        if profile.supports_dispatch_workers(dispatch_worker_count) {
            return Ok(());
        }
        if matches!(
            profile,
            crate::approval::ApprovalStoreProfile::EphemeralLocal
        ) {
            return Err(KernelError::Internal(
                "durable approval store authority is required".to_string(),
            ));
        }
        Err(KernelError::Internal(
            "multiple dispatch workers require a shared linearizable approval store".to_string(),
        ))
    }

    pub(super) fn validate_admission_operation_store_profile(
        profile: crate::security_admission_operation::AdmissionOperationStoreProfile,
        dispatch_worker_count: usize,
    ) -> Result<(), KernelError> {
        if profile.supports_dispatch_workers(dispatch_worker_count) {
            return Ok(());
        }
        if matches!(
            profile,
            crate::security_admission_operation::AdmissionOperationStoreProfile::EphemeralLocal
        ) {
            return Err(KernelError::Internal(
                "durable admission operation store authority is required".to_string(),
            ));
        }
        Err(KernelError::Internal(
            "multiple dispatch workers require a shared linearizable admission operation store"
                .to_string(),
        ))
    }

    pub fn persist_prepared_admission_operation(
        &self,
        operation: crate::security_admission_operation::AdmissionOperation,
    ) -> Result<crate::security_admission_operation::AdmissionOperation, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is not installed".to_string())
        })?;
        Self::validate_admission_operation_store_profile(
            store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        match store.create_prepared(operation).map_err(|error| {
            KernelError::Internal(format!("failed to persist admission operation: {error}"))
        })? {
            crate::security_admission_operation::AdmissionOperationCreateOutcome::Created(operation)
            | crate::security_admission_operation::AdmissionOperationCreateOutcome::Existing(operation) => {
                Ok(operation)
            }
        }
    }

    pub fn set_supplemental_quota_verifier(
        &mut self,
        verifier: Arc<dyn crate::supplemental_quota::SupplementalQuotaVerifier>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_supplemental_broker_admission_deactivated()?;
        if self.supplemental_quota_verifier.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.supplemental_quota_verifier = Some(verifier);
        Ok(())
    }

    pub fn set_agent_economy_supplemental_quota_verifier(
        &mut self,
        verifier: Arc<
            dyn crate::agent_economy_supplemental_quota::SupplementalQuotaVerifier,
        >,
        binding: crate::agent_economy_supplemental_quota::SupplementalQuotaVerifierBinding,
    ) -> Result<(), crate::agent_economy_supplemental_quota::SupplementalQuotaError> {
        self.agent_economy_supplemental_quota_verifier = Some(
            crate::agent_economy_supplemental_quota::SupplementalQuotaVerifierRuntime::new(
                verifier, binding,
            )?,
        );
        Ok(())
    }

    pub fn set_supplemental_admission_registrar(
        &mut self,
        registrar: Arc<dyn crate::supplemental_quota::SupplementalAdmissionRegistrar>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_supplemental_broker_admission_deactivated()?;
        if self.supplemental_admission_registrar.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.supplemental_admission_registrar = Some(registrar);
        Ok(())
    }

    pub fn set_admission_capture_authority(
        &mut self,
        authority: Arc<dyn crate::admission_capture_authority::AdmissionCaptureAuthority>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_supplemental_broker_admission_deactivated()?;
        if self.partition_escrow_registry.is_some() {
            return Err(KernelError::Internal(
                "partition escrow permanently binds the installed admission capture authority"
                    .to_string(),
            ));
        }
        if self.admission_capture_authority.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.admission_capture_authority = Some(authority);
        Ok(())
    }

    pub fn deactivate_aggregate_invocation_admission(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.aggregate_invocation_admission_enabled = false;
    }

    pub fn deactivate_supplemental_broker_admission(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.supplemental_broker_admission_enabled = false;
    }

    pub fn enable_aggregate_invocation_admission(&mut self) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.validate_protocol_budget_admission_profiles()?;
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_nonterminal_admission_kind_with_authorities(
            operation_store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            crate::security_admission_operation::AdmissionOperationKind::ToolDispatch,
            &format!("kernel:{}", self.public_key().to_hex()),
        )?;
        self.aggregate_invocation_admission_enabled = true;
        Ok(())
    }

    pub fn enable_supplemental_broker_admission(&mut self) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.validate_protocol_budget_admission_profiles()?;
        if self.supplemental_quota_verifier.is_none()
            || self.supplemental_admission_registrar.is_none()
            || self.admission_capture_authority.is_none()
        {
            return Err(KernelError::Internal(
                "supplemental broker admission authorities are incomplete".to_string(),
            ));
        }
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_nonterminal_admission_kind_with_authorities(
            operation_store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            crate::security_admission_operation::AdmissionOperationKind::ToolDispatch,
            &format!("kernel:{}", self.public_key().to_hex()),
        )?;
        self.supplemental_broker_admission_enabled = true;
        Ok(())
    }

    pub(super) fn validate_protocol_budget_admission_profiles(&self) -> Result<(), KernelError> {
        if self.partition_escrow_registry.is_some()
            && self.admission_capture_authority.is_none()
        {
            return Err(KernelError::Internal(
                "partition escrow admission requires an exact admission capture authority"
                    .to_string(),
            ));
        }
        if self.payment_adapter.as_ref().is_some_and(|adapter| {
            !adapter.supports_operation_authorization_recovery()
                || !adapter.supports_operation_payment_mutations()
        }) {
            return Err(KernelError::Internal(
                "operation-owned ordinary admission requires authoritative authorization lookup and operation-bound payment mutations"
                    .to_string(),
            ));
        }
        if self.payment_adapter.is_some()
            && !self
                .budget_store
                .supports_durable_atomic_payment_journal()
        {
            return Err(KernelError::Internal(
                "operation-owned payment admission requires a durable budget store that atomically co-commits payment-journal state"
                    .to_string(),
            ));
        }
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "durable admission operation store is required for operation-owned admission"
                    .to_string(),
            )
        })?;
        Self::validate_admission_operation_store_profile(
            operation_store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        Self::validate_hard_budget_store_profile(
            self.budget_store.as_ref(),
            self.dispatch_worker_count,
            self.partition_escrow_registry.as_deref(),
        )?;
        Ok(())
    }

    pub(super) fn validate_hard_budget_store_profile(
        store: &dyn BudgetStore,
        dispatch_worker_count: usize,
        partition_escrow_registry: Option<&crate::partition_escrow::PartitionEscrowRegistry>,
    ) -> Result<(), KernelError> {
        let profile = store.authority_profile();
        let guarantee = store.budget_guarantee_level();
        if guarantee == crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed {
            let registry = partition_escrow_registry.ok_or_else(|| {
                KernelError::Internal(
                    "partition-escrowed budget enforcement requires a sealed signed allocation registry"
                        .to_string(),
                )
            })?;
            if profile != crate::budget_store::BudgetStoreProfile::SharedLinearizable
                || dispatch_worker_count == 0
            {
                return Err(KernelError::Internal(
                    "partition-escrowed production enforcement requires a shared linearizable fenced authority"
                        .to_string(),
                ));
            }
            let binding = store.partition_escrow_store_binding()?.ok_or_else(|| {
                KernelError::Internal(
                    "partition-escrowed budget authority omitted its sealed counter binding"
                        .to_string(),
                )
            })?;
            let expected = registry.durable_store();
            if binding.store_identity_digest() != expected.store_identity_digest()
                || binding.counter_namespace_digest() != expected.counter_namespace_digest()
                || binding.fencing_token() != expected.fencing_token()
            {
                return Err(KernelError::Internal(
                    "partition-escrowed budget authority diverged from its signed registry binding"
                        .to_string(),
                ));
            }
            return Ok(());
        }
        if partition_escrow_registry.is_some() || store.partition_escrow_store_binding()?.is_some()
        {
            return Err(KernelError::Internal(
                "partition escrow registry and store binding must be installed together"
                    .to_string(),
            ));
        }
        if guarantee.supports_hard_invocation_limit(profile, dispatch_worker_count) {
            return Ok(());
        }
        let reason = match guarantee {
            crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic => {
                "single-node atomic budget enforcement requires one worker and a single-node durable store"
            }
            crate::budget_store::BudgetGuaranteeLevel::HaLinearizable => {
                "HA-linearizable budget enforcement requires a shared linearizable store"
            }
            crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed => {
                "partition-escrowed budget enforcement requires signed allocation evidence"
            }
            crate::budget_store::BudgetGuaranteeLevel::AdvisoryPosthoc => {
                "advisory posthoc budget enforcement cannot enforce a hard invocation limit"
            }
        };
        Err(KernelError::Internal(reason.to_string()))
    }

    fn require_protocol_budget_admission_deactivated_for_authority_change(
        &self,
    ) -> Result<(), KernelError> {
        if self.aggregate_invocation_admission_enabled
            || self.supplemental_broker_admission_enabled
            || self.partition_escrow_registry.is_some()
        {
            return Err(KernelError::Internal(
                "aggregate and supplemental admission must be deactivated before authority replacement"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn require_supplemental_broker_admission_deactivated(&self) -> Result<(), KernelError> {
        if self.supplemental_broker_admission_enabled {
            return Err(KernelError::Internal(
                "supplemental broker admission must be deactivated before authority replacement"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn verify_supplemental_quota(
        &self,
        artifact: &crate::supplemental_quota::OpaqueSignedSupplementalQuota,
        context: &crate::supplemental_quota::SupplementalQuotaVerificationContext,
    ) -> Result<
        crate::supplemental_quota::VerifiedSupplementalQuota,
        crate::supplemental_quota::SupplementalQuotaError,
    > {
        let verifier = self
            .supplemental_quota_verifier
            .as_ref()
            .ok_or(crate::supplemental_quota::SupplementalQuotaError::VerifierUnavailable)?;
        crate::supplemental_quota::verify_supplemental_quota(verifier.as_ref(), artifact, context)
    }

    pub fn set_post_invocation_pipeline(
        &mut self,
        pipeline: crate::post_invocation::PostInvocationPipeline,
    ) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.post_invocation_pipeline = pipeline;
    }

    pub fn add_post_invocation_hook(
        &mut self,
        hook: Box<dyn crate::post_invocation::PostInvocationHook>,
    ) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.post_invocation_pipeline.add(hook);
    }

    /// Install the single settlement hook consumed by the background outbox
    /// recovery worker. Settlement is strictly an observer relative to receipt
    /// bytes; terminal receipt persistence atomically appends the outbox row
    /// and never invokes the hook on the caller's dispatch path. Hook failures
    /// are routed through the retry/dead-letter machinery.
    ///
    /// Fail-closed wiring: a durable settlement retry store MUST already
    /// be installed (see [`Self::set_settlement_retry_store`]) so every
    /// retryable or permanent outcome lands a durable `settle_attempts` or
    /// `settle_dead_letters` row. An observer without one would degrade
    /// those outcomes to a warn plus a counter, so the install is rejected
    /// here, at wiring time, never discovered at first use.
    pub fn set_settlement_observer(
        &mut self,
        hook: std::sync::Arc<dyn chio_settle::SettlementHook>,
    ) -> Result<(), KernelBuildError> {
        if self.settlement_observer.is_some() {
            return Err(KernelBuildError::SettlementObserverAlreadyInstalled);
        }
        if !hook.supports_receipt_id_idempotency() {
            return Err(KernelBuildError::SettlementHookNotIdempotent);
        }
        if self.settlement_retry_store.is_none() {
            return Err(KernelBuildError::MissingSettlementRetryStore);
        }
        if !self
            .settlement_retry_store
            .as_deref()
            .is_some_and(|store| store.supports_durable_settlement_retry())
        {
            return Err(KernelBuildError::SettlementRetryStoreNotDurable);
        }
        let receipt_store = self
            .receipt_store
            .as_deref()
            .ok_or(KernelBuildError::SettlementObserverOutboxUnsupported)?;
        if !receipt_store.supports_durable_settlement_observer_outbox()
            || !receipt_store.supports_authoritative_chio_receipt_lookup()
        {
            return Err(KernelBuildError::SettlementObserverOutboxUnsupported);
        }
        let receipt_identity = receipt_store
            .durable_storage_identity()
            .map_err(|error| {
                KernelBuildError::SettlementObserverStorageTopology(error.to_string())
            })?
            .ok_or_else(|| {
                KernelBuildError::SettlementObserverStorageTopology(
                    "receipt store omitted durable storage identity".to_string(),
                )
            })?;
        let retry_identity = self
            .settlement_retry_store
            .as_deref()
            .ok_or(KernelBuildError::MissingSettlementRetryStore)?
            .durable_storage_identity()
            .map_err(|error| {
                KernelBuildError::SettlementObserverStorageTopology(error.to_string())
            })?
            .ok_or_else(|| {
                KernelBuildError::SettlementObserverStorageTopology(
                    "retry store omitted durable storage identity".to_string(),
                )
            })?;
        if receipt_identity != retry_identity {
            return Err(KernelBuildError::SettlementObserverStorageTopology(
                "receipt outbox and retry store use different commit domains".to_string(),
            ));
        }
        let previous_observer = self.settlement_observer.replace(hook);
        let previous_recovery = self.settlement_observer_recovery.take();
        if let Err(error) = self.recover_settlement_observer_outboxes() {
            self.settlement_observer = previous_observer;
            self.settlement_observer_recovery = previous_recovery;
            return Err(KernelBuildError::SettlementObserverRecovery(
                error.to_string(),
            ));
        }
        self.settlement_observer_recovery = self.spawn_settlement_observer_recovery();
        Ok(())
    }

    /// Install the durable settlement retry/dead-letter sink the observer
    /// routing consumer writes to. Required before
    /// [`Self::set_settlement_observer`]: an observer whose outcomes have
    /// no durable sink is refused at wiring time.
    pub fn set_settlement_retry_store(
        &mut self,
        store: std::sync::Arc<dyn crate::settlement_retry::SettlementRetryStore>,
    ) -> Result<(), KernelBuildError> {
        if !store.supports_durable_settlement_retry() {
            return Err(KernelBuildError::SettlementRetryStoreNotDurable);
        }
        if self.settlement_observer.is_some() {
            let receipt_store = self
                .receipt_store
                .as_deref()
                .ok_or(KernelBuildError::SettlementObserverOutboxUnsupported)?;
            let receipt_identity = receipt_store
                .durable_storage_identity()
                .map_err(|error| {
                    KernelBuildError::SettlementObserverStorageTopology(error.to_string())
                })?
                .ok_or_else(|| {
                    KernelBuildError::SettlementObserverStorageTopology(
                        "receipt store omitted durable storage identity".to_string(),
                    )
                })?;
            let retry_identity = store
                .durable_storage_identity()
                .map_err(|error| {
                    KernelBuildError::SettlementObserverStorageTopology(error.to_string())
                })?
                .ok_or_else(|| {
                    KernelBuildError::SettlementObserverStorageTopology(
                        "retry store omitted durable storage identity".to_string(),
                    )
                })?;
            if receipt_identity != retry_identity {
                return Err(KernelBuildError::SettlementObserverStorageTopology(
                    "receipt outbox and retry store use different commit domains".to_string(),
                ));
            }
        }
        let previous_store = self.settlement_retry_store.replace(store);
        let previous_recovery = self.settlement_observer_recovery.take();
        if self.settlement_observer.is_some() {
            if let Err(error) = self.recover_settlement_observer_outboxes() {
                self.settlement_retry_store = previous_store;
                self.settlement_observer_recovery = previous_recovery;
                return Err(KernelBuildError::SettlementObserverRecovery(
                    error.to_string(),
                ));
            }
            self.settlement_observer_recovery = self.spawn_settlement_observer_recovery();
        }
        Ok(())
    }

    pub(super) fn spawn_settlement_observer_recovery(
        &self,
    ) -> Option<settlement_observer::SettlementObserverRecoveryHandle> {
        Some(settlement_observer::SettlementObserverRecoveryHandle::spawn(
            std::sync::Arc::clone(self.receipt_store.as_ref()?),
            std::sync::Arc::clone(self.settlement_retry_store.as_ref()?),
            std::sync::Arc::clone(self.settlement_observer.as_ref()?),
            self.settlement_retry_policy,
            settlement_observer::SettlementReceiptTrustVerifier::new(
                self.public_key(),
                self.authority_artifact_trust_resolver.clone(),
            ),
        ))
    }

    /// Start the background sweeper for orphaned budget holds: once at
    /// start, then every `interval_secs`, every open hold older than
    /// `horizon_secs` is expired and its remaining exposure released (no
    /// spend recorded), so a crash between a hold and its reconcile no
    /// longer burns capacity forever. Use
    /// [`DEFAULT_HOLD_SWEEP_INTERVAL_SECS`] and
    /// [`DEFAULT_HOLD_EXPIRY_HORIZON_SECS`] unless the deployment has a
    /// reason to deviate; the horizon must sit far above any legitimate
    /// in-flight call. Restarting replaces (and joins) a previous sweeper.
    pub fn start_budget_hold_sweeper(&mut self, interval_secs: u64, horizon_secs: u64) {
        self.budget_hold_sweep = Some(super::budget_sweep::BudgetHoldSweepHandle::spawn(
            Arc::clone(&self.budget_store),
            interval_secs,
            horizon_secs,
        ));
    }

    /// Whether the durable payment journal is in force: a payment adapter is
    /// installed and either the dispatch-intent journal covers the monetary
    /// class or a durable admission operation owns the payment mutation.
    pub(crate) fn payment_journal_active(&self) -> bool {
        self.payment_adapter.is_some()
            && (self.admission_operation_store.is_some()
                || !matches!(
                    self.config.dispatch_intent_journal,
                    crate::receipt_store::DispatchIntentJournalMode::Off
                ))
    }

    /// Advance the payment journal for a monetary call. Fail-closed: an
    /// advance that cannot commit surfaces an error so the caller denies or
    /// unwinds rather than moving money without a recoverable record. No-op
    /// when the journal is not in force.
    pub(crate) fn advance_payment_journal_if_active(
        &self,
        request_id: &str,
        expected: crate::payment::PaymentJournalState,
        next: crate::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), KernelError> {
        if !self.payment_journal_active() {
            return Ok(());
        }
        self.with_budget_store(|store| {
            store
                .advance_payment_journal(
                    request_id,
                    expected,
                    next,
                    authorization_id,
                    transaction_id,
                    settle,
                )
                .map_err(KernelError::from)
        })
    }

    /// Close the payment journal after the receipt commits. A crash before
    /// the close leaves a Settled row that boot reconciliation closes
    /// against the attested receipt, so a close failure here is warned, not
    /// fatal.
    ///
    /// State-aware: `HoldPlaced` and `Settling` are always incomplete recovery
    /// states. `Authorized` is also retained when the terminal receipt denies
    /// dispatch, because the authorization may need operation-bound cleanup.
    /// Boot reconciliation replays or resolves those rows idempotently instead
    /// of losing their only recovery handle.
    pub(crate) fn close_payment_journal_best_effort(
        &self,
        request_id: &str,
        terminal_allows_dispatch: bool,
    ) {
        if !self.payment_journal_active() {
            return;
        }
        match self.with_budget_store(|store| {
            store
                .get_payment_journal(request_id)
                .map_err(KernelError::from)
        }) {
            Ok(Some(row))
                if matches!(
                    row.state,
                    crate::payment::PaymentJournalState::HoldPlaced
                        | crate::payment::PaymentJournalState::Settling
                ) || (row.state == crate::payment::PaymentJournalState::Authorized
                    && !terminal_allows_dispatch) =>
            {
                tracing::warn!(
                    request_id = %request_id,
                    rail = %row.rail,
                    state = ?row.state,
                    "payment journal recovery is incomplete at receipt commit; leaving it open \
                     for boot reconciliation"
                );
                return;
            }
            Ok(_) => {}
            Err(error) => {
                // Unknown state: never destroy a possible recovery handle.
                // A stray open Settled row at the next boot re-emits an
                // advisory reconciliation receipt, never a second charge.
                tracing::warn!(
                    request_id = %request_id,
                    reason = %redacted!(&error.to_string()),
                    "payment journal lookup failed at receipt commit; leaving the row for boot \
                     reconciliation"
                );
                return;
            }
        }
        let closed = self.with_budget_store(|store| {
            store
                .close_payment_journal(request_id)
                .map_err(KernelError::from)
        });
        if let Err(error) = closed {
            tracing::warn!(
                request_id = %request_id,
                reason = %redacted!(&error.to_string()),
                "payment journal close failed; boot reconciliation will close the row"
            );
        }
    }

    /// Return a clone of the active settlement observer, or `None` when
    /// no hook has been installed. Useful for integration tests that
    /// want to assert observer state directly.
    #[must_use]
    pub fn settlement_observer(&self) -> Option<std::sync::Arc<dyn chio_settle::SettlementHook>> {
        self.settlement_observer.clone()
    }

    /// Invoke the registered settlement hook against a
    /// freshly signed receipt. The receipt is observer-only relative
    /// to this call: callers MUST pass a receipt that has already been
    /// signed and stored, and the returned status NEVER feeds back
    /// into the dispatch path.
    #[must_use]
    pub fn run_settlement_observer(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> settlement_observer::SettlementObserverStatus {
        if self.settlement_observer.is_none() {
            return settlement_observer::SettlementObserverStatus::NotRegistered;
        }
        match self.verify_trusted_receipt(receipt) {
            Ok(true) => {}
            Ok(false) => {
                return settlement_observer::SettlementObserverStatus::HookFailed {
                    class: chio_settle::SettlementFailureClass::Permanent,
                    reason: chio_settle::SettlementFailureReason::from_detail(
                        chio_settle::SettlementFailureCode::UntrustedReceiptSigner,
                        "receipt signer is not trusted by the runtime authority resolver",
                    ),
                };
            }
            Err(_) => {
                return settlement_observer::SettlementObserverStatus::HookFailed {
                    class: chio_settle::SettlementFailureClass::Permanent,
                    reason: chio_settle::SettlementFailureReason::from_detail(
                        chio_settle::SettlementFailureCode::UntrustedReceiptSigner,
                        "receipt authority trust resolution failed",
                    ),
                };
            }
        }
        let idempotency_key = chio_settle::SettlementIdempotencyKey {
            receipt_id: receipt.id.clone(),
            row_version: 1,
        };
        settlement_observer::run_observer(
            self.settlement_observer.as_ref(),
            receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key,
        )
    }

    /// Classify an observed settlement outcome against the retry policy and
    /// persist the decision: retryable outcomes upsert a bounded attempt row,
    /// terminal failures land an idempotent dead-letter row, and resolved
    /// outcomes clear the envelope.
    #[cfg(test)]
    pub(crate) fn classify_and_persist(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
        outcome: &chio_settle::SettlementOutcome,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        use crate::settlement_retry::{SettleAttemptRecord, SettlementRetryError};
        use chio_settle::RetryDecision;

        let outcome = settlement_observer::validate_and_sanitize_settlement_outcome(outcome)?;
        let store = self.settlement_retry_store.as_deref();
        let prior_attempts = match store {
            Some(store) => store
                .load_attempt(&receipt.id)?
                .map(|attempt| attempt.attempts)
                .unwrap_or(0),
            None => 0,
        };
        match chio_settle::classify_attempt(
            &self.settlement_retry_policy,
            prior_attempts,
            &outcome,
        )
        {
            RetryDecision::Accepted | RetryDecision::Skip { .. } => {
                // Resolved (accepted or skipped): the receipt owes nothing
                // downstream, so any bounded envelope for it is cleared.
                if let Some(store) = store {
                    store.clear_attempt(&receipt.id)?;
                }
                Ok(())
            }
            RetryDecision::Retry {
                attempt,
                backoff,
                reason,
            } => {
                let Some(store) = store else {
                    return Err(SettlementRetryError::Backend(
                        "no settlement retry store installed".to_string(),
                    ));
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or(0);
                store.upsert_attempt(&SettleAttemptRecord {
                    receipt_id: receipt.id.clone(),
                    finalized_at: receipt.timestamp,
                    attempts: attempt,
                    next_visible_at: now
                        .saturating_add(chio_settle::ceil_retry_delay_seconds(backoff)),
                    last_reason: Some(reason.code().as_str().to_string()),
                })
            }
            RetryDecision::DeadLetter { reason } => {
                let Some(store) = store else {
                    return Err(SettlementRetryError::Backend(
                        "no settlement retry store installed".to_string(),
                    ));
                };
                let record = chio_settle::DeadLetterRecord::new(
                    receipt.id.clone(),
                    receipt.timestamp,
                    prior_attempts.saturating_add(1),
                    reason,
                );
                match store.insert_dead_letter(&record) {
                    Ok(_) => store.clear_attempt(&receipt.id),
                    Err(SettlementRetryError::Conflict(message)) => {
                        // A divergent dead-letter row already exists. Keep the
                        // original row (operators clear it explicitly) and
                        // surface the divergence loud.
                        tracing::warn!(
                            receipt_id = %receipt.id,
                            reason = %redacted!(&message),
                            "dead-letter insert conflicted with a divergent row"
                        );
                        chio_metrics_spec::runtime::families::SETTLEMENT_UNRESOLVED.incr(&[]);
                        Err(SettlementRetryError::Conflict(message))
                    }
                    Err(other) => Err(other),
                }
            }
        }
    }

    /// Install a memory-provenance chain.
    ///
    /// Once installed, every governed `MemoryWrite`-shaped tool call
    /// appends an entry to the chain after the allow receipt is
    /// signed. A chain-store failure on that path is fatal: the call
    /// surfaces `KernelError::Internal(...)` so operators can detect
    /// and repair the drift rather than silently shipping a write
    /// without provenance evidence.
    ///
    /// Every `MemoryRead`-shaped tool call looks the entry up by
    /// `(store, key)` and attaches the result to the receipt as
    /// `memory_provenance` evidence metadata. Reads with no chain
    /// entry or with a tampered chain surface as
    /// [`crate::memory_provenance::ProvenanceVerification::Unverified`]
    /// so the receipt unambiguously records the gap.
    pub fn set_memory_provenance_store(
        &mut self,
        store: Arc<dyn crate::memory_provenance::MemoryProvenanceStore>,
    ) {
        self.memory_provenance = Some(store);
    }

    /// Return a clone of the active memory-provenance store handle,
    /// or `None` when no provenance chain has been installed.
    ///
    /// Useful for integration tests that want to assert on the chain
    /// state directly after driving `evaluate_tool_call`.
    #[must_use]
    pub fn memory_provenance_store(
        &self,
    ) -> Option<Arc<dyn crate::memory_provenance::MemoryProvenanceStore>> {
        self.memory_provenance.as_ref().map(Arc::clone)
    }

    /// Install a set of [`chio_federation::trust_establishment::FederationPeer`]s
    /// this kernel trusts for bilateral co-signing. Overwrites any
    /// previously declared set. Callers typically obtain these peers
    /// from [`chio_federation::trust_establishment::KernelTrustExchange::accept_envelope`]
    /// after a successful mTLS handshake.
    ///
    /// Builder-style so deployments can chain `.with_federation_peers(...)`
    /// onto `ChioKernel::new(config)`.
    #[must_use]
    pub fn with_federation_peers(
        self,
        peers: Vec<chio_federation::trust_establishment::FederationPeer>,
    ) -> Self {
        let mut next = HashMap::new();
        for peer in peers {
            next.insert(peer.kernel_id.clone(), peer);
        }
        self.federation_peers.store(Arc::new(next));
        self
    }

    /// Builder-style so deployments can chain
    /// `.with_capability_trust_roots(...)` onto `ChioKernel::new(config)`.
    #[must_use]
    pub fn with_capability_trust_roots(
        self,
        roots: Vec<(
            chio_core::PublicKey,
            chio_core::capability::attenuation::ScopeHash,
        )>,
    ) -> Self {
        {
            let _guard = self
                .capability_trust_roots_write_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut next: HashMap<String, chio_core::capability::attenuation::ScopeHash> =
                HashMap::new();
            for (issuer, root) in roots {
                next.insert(issuer.to_hex(), root);
            }
            self.capability_trust_roots.store(Arc::new(next));
        }
        self
    }

    /// Install or update a single capability trust-root entry without
    /// requiring builder-style construction. Returns the previous root
    /// hash for that issuer, if any.
    pub fn set_capability_trust_root(
        &self,
        issuer: chio_core::PublicKey,
        root: chio_core::capability::attenuation::ScopeHash,
    ) -> Option<chio_core::capability::attenuation::ScopeHash> {
        let _guard = self
            .capability_trust_roots_write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.capability_trust_roots.load_full();
        let mut next: HashMap<String, chio_core::capability::attenuation::ScopeHash> =
            (*current).clone();
        let prev = next.insert(issuer.to_hex(), root);
        self.capability_trust_roots.store(Arc::new(next));
        prev
    }

    /// Snapshot the currently registered capability trust-root registry.
    /// Hot-path callers should prefer the resolver returned by
    /// `capability_trust_root_resolver_snapshot`.
    pub fn capability_trust_roots_snapshot(
        &self,
    ) -> HashMap<String, chio_core::capability::attenuation::ScopeHash> {
        (*self.capability_trust_roots.load_full()).clone()
    }

    /// Build an owned snapshot of the capability trust-root registry
    /// suitable for use as a `chio_kernel_core::TrustRootResolver`. The
    /// returned closure captures a frozen snapshot so concurrent
    /// rotations cannot tear an in-flight verification.
    pub(crate) fn capability_trust_root_resolver_snapshot(
        &self,
    ) -> impl Fn(&chio_core::PublicKey) -> Option<chio_core::capability::attenuation::ScopeHash>
           + Send
           + Sync
           + 'static {
        let snapshot: Arc<HashMap<String, chio_core::capability::attenuation::ScopeHash>> =
            self.capability_trust_roots.load_full();
        move |issuer: &chio_core::PublicKey| -> Option<chio_core::capability::attenuation::ScopeHash> {
            snapshot.get(&issuer.to_hex()).cloned()
        }
    }

    pub(crate) fn capability_negotiation_for_remote(
        &self,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<chio_core::capability::features::CapabilityNegotiation, String> {
        if let Some(remote) = remote_kernel_id {
            if let Some(peer) = self.federation_peer(remote, now) {
                let mut capabilities = peer.capabilities;
                if !self.threshold_governed_approvals_enabled {
                    capabilities.features.insert(
                        chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS.to_string(),
                        false,
                    );
                }
                if !self.active_response_runtime_ready() {
                    capabilities.features.insert(
                        chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN.to_string(),
                        false,
                    );
                }
                if !self.aggregate_invocation_admission_enabled {
                    capabilities.features.insert(
                        chio_core::capability::features::AGGREGATE_INVOCATION_BUDGET.to_string(),
                        false,
                    );
                }
                if !self.supplemental_broker_admission_enabled {
                    capabilities.features.insert(
                        chio_core::capability::features::SUPPLEMENTAL_BROKER_EXECUTION_QUOTA
                            .to_string(),
                        false,
                    );
                }
                return Ok(capabilities);
            }
            return Err(format!(
                "no fresh federation peer negotiation profile pinned for remote kernel {remote}"
            ));
        }
        let mut capabilities = chio_core::capability::features::CapabilityNegotiation::t1_default();
        if self.threshold_governed_approvals_enabled {
            capabilities.features.insert(
                chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS.to_string(),
                true,
            );
        }
        if self.active_response_runtime_ready() {
            capabilities.features.insert(
                chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN.to_string(),
                true,
            );
        }
        if self.aggregate_invocation_admission_enabled {
            capabilities.features.insert(
                chio_core::capability::features::AGGREGATE_INVOCATION_BUDGET.to_string(),
                true,
            );
        }
        if self.supplemental_broker_admission_enabled {
            capabilities.features.insert(
                chio_core::capability::features::SUPPLEMENTAL_BROKER_EXECUTION_QUOTA.to_string(),
                true,
            );
        }
        Ok(capabilities)
    }

    /// Install the bilateral cosigner responsible for
    /// contacting a peer kernel to obtain a co-signature. Production
    /// deployments plug in an mTLS-backed RPC client; tests can use
    /// [`chio_federation::bilateral::InProcessCoSigner`].
    pub fn set_federation_cosigner(
        &mut self,
        cosigner: Arc<dyn chio_federation::bilateral::BilateralCoSigningProtocol>,
    ) {
        self.federation_cosigner = Some(cosigner);
    }

    /// Install a durable [`crate::federation_artifact_store::FederationArtifactStore`]
    /// for bilateral co-sign artifacts.
    ///
    /// When set, [`Self::apply_federation_cosign`] writes each
    /// `DualSignedReceipt` / `DsseEnvelope` through to the store BEFORE inserting
    /// it into the bounded in-memory caches, and [`Self::dual_signed_receipt`] /
    /// [`Self::federation_dsse_envelope`] fall back to the store on a cache miss.
    /// This closes the evidence-loss window where a federated deployment
    /// producing more than `federation_cache_capacity` receipts would drop
    /// evicted co-sign artifacts while the durable receipt store keeps only the
    /// base receipt. Without a store installed, evicted co-sign artifacts are
    /// lossy by policy (the bounded caches drop-oldest at capacity).
    ///
    /// A deployment requiring durable bilateral evidence installs a
    /// database-backed impl; the bundled
    /// [`crate::federation_artifact_store::InMemoryFederationArtifactStore`] is a
    /// capped, idle-swept reference impl and test double.
    pub fn set_federation_artifact_store(
        &mut self,
        store: Arc<dyn crate::federation_artifact_store::FederationArtifactStore>,
    ) {
        self.federation_artifact_store = Some(store);
    }

    /// Advertise this kernel's stable identifier as seen by
    /// remote federation peers. When unset, the hex encoding of the
    /// signing public key is used. Setting this is recommended in
    /// production so receipts reference DNS names rather than raw keys.
    pub fn set_federation_local_kernel_id(&self, kernel_id: impl Into<String>) {
        self.federation_local_kernel_id
            .store(Arc::new(Some(kernel_id.into())));
    }
}
