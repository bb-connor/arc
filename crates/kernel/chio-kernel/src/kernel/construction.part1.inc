impl ChioKernel {
    pub(crate) fn with_sessions_read<R>(
        &self,
        f: impl FnOnce(&DashMap<SessionId, Arc<Session>>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(&self.sessions)
    }

    pub(crate) fn with_sessions_write<R>(
        &self,
        f: impl FnOnce(&DashMap<SessionId, Arc<Session>>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(&self.sessions)
    }

    pub(crate) fn with_session<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&Arc<Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let session = self
            .sessions
            .get(session_id)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;
        f(&session)
    }

    /// Resolve the tenant_id for a given session by walking its
    /// authenticated auth context into the enterprise identity's tenant
    /// claim. Returns `None` for single-tenant / anonymous sessions, for
    /// unknown session IDs, or when the caller did not supply one.
    ///
    /// Tenant_id is taken from the OAuth bearer's `enterprise_identity`
    /// (preferred, richer SSO claims) and falls back to the OAuth
    /// `federated_claims.tenant_id` when the IdP surfaces only the minimal
    /// federated claim set. Both sources originate from the authenticated
    /// session -- never from caller-provided request fields, because
    /// caller choice would defeat the isolation guarantee.
    pub(crate) fn resolve_tenant_id_for_session(
        &self,
        session_id: Option<&SessionId>,
    ) -> Option<String> {
        let id = session_id?;
        self.with_session(id, |session| {
            let auth_context = session.auth_context();
            Ok(extract_tenant_id_from_auth_context(&auth_context))
        })
        .ok()
        .flatten()
    }

    pub(crate) fn scope_receipt_tenant_id_for_request(
        &self,
        request_id: &str,
        tenant_id: Option<String>,
    ) -> ScopedKernelReceiptTenantId {
        let previous = match tenant_id {
            Some(tenant_id) => self
                .receipt_tenant_ids
                .insert(request_id.to_string(), tenant_id),
            None => self
                .receipt_tenant_ids
                .remove(request_id)
                .map(|(_, previous)| previous),
        };
        ScopedKernelReceiptTenantId {
            request_id: request_id.to_string(),
            tenant_ids: Arc::clone(&self.receipt_tenant_ids),
            previous,
        }
    }

    pub(crate) fn receipt_tenant_id_for_request(&self, request_id: Option<&str>) -> Option<String> {
        request_id.and_then(|request_id| {
            self.receipt_tenant_ids
                .get(request_id)
                .map(|entry| entry.value().clone())
        })
    }

    pub(crate) fn with_session_mut<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&Arc<Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        self.with_session(session_id, f)
    }

    pub(crate) fn with_budget_store<R>(
        &self,
        f: impl FnOnce(&dyn BudgetStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(self.budget_store.as_ref())
    }

    pub(crate) fn with_revocation_store<R>(
        &self,
        f: impl FnOnce(&dyn RevocationStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(self.revocation_store.as_ref())
    }

    pub(crate) fn with_receipt_store<R>(
        &self,
        f: impl FnOnce(&dyn ReceiptStore) -> Result<R, KernelError>,
    ) -> Result<Option<R>, KernelError> {
        let Some(store) = self.receipt_store.as_ref() else {
            return Ok(None);
        };
        f(store.as_ref()).map(Some)
    }

    /// Flush any queued receipt writes to durable storage, bounded by `timeout`.
    ///
    /// A shutdown drain calls this to prove the commit-actor queue is empty
    /// before the process exits. `Ok(None)` means no receipt store is
    /// configured; a configured store's flush error is surfaced rather than
    /// swallowed, so a drain can exit non-zero when a receipt might not be
    /// durable.
    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<crate::ReceiptFlushReport>, KernelError> {
        self.with_receipt_store(|store| {
            store
                .flush_receipt_writes_with_timeout(timeout)
                .map_err(KernelError::from)
        })
    }

    pub fn new(config: KernelConfig) -> Self {
        let backend: Arc<dyn chio_core::crypto::SigningBackend> = Arc::new(
            chio_core::crypto::Ed25519Backend::new(config.keypair.clone()),
        );
        Self::new_with_validated_authority_backend(config, backend)
    }

    /// Construct a kernel with a custom authority signer and its mandatory
    /// artifact-time trust resolver as one atomic authority topology.
    ///
    /// The resolver is installed before the kernel is returned, and signer
    /// replacement is permanently locked. This is the only public custom
    /// authority construction path, so a custom signer cannot be published
    /// without an artifact verifier in the same topology transaction.
    pub fn new_with_authority_signing_runtime(
        config: KernelConfig,
        backend: Arc<dyn chio_core::crypto::SigningBackend>,
        resolver: Arc<dyn crate::authority::AuthorityArtifactTrustResolver>,
    ) -> Result<Self, KernelError> {
        if backend.public_key() != config.keypair.public_key() {
            return Err(KernelError::Internal(
                "configured authority backend does not match the kernel configuration public key"
                    .to_string(),
            ));
        }
        let mut kernel = Self::new_with_validated_authority_backend(config, backend);
        kernel.set_authority_artifact_trust_resolver(resolver)?;
        kernel.lock_authority_signing_backend_topology();
        Ok(kernel)
    }

    /// Construct a kernel whose singular runtime authority is an external
    /// signing backend and whose bootstrap configuration key is not an
    /// authority identity.
    ///
    /// This is intentionally separate from
    /// [`Self::new_with_authority_signing_runtime`]. The local custom-backend
    /// constructor retains its exact keypair/backend equality invariant. This
    /// external topology publishes only `backend.public_key()`, installs its
    /// mandatory artifact resolver atomically, and permanently locks signer
    /// replacement before the kernel is returned.
    pub fn new_with_external_authority_signing_runtime(
        config: KernelConfig,
        backend: Arc<dyn chio_core::crypto::SigningBackend>,
        resolver: Arc<dyn crate::authority::AuthorityArtifactTrustResolver>,
    ) -> Result<Self, KernelError> {
        let public_key = backend.public_key();
        if public_key.algorithm() != backend.algorithm() {
            return Err(KernelError::Internal(
                "external authority backend algorithm does not match its public key".to_string(),
            ));
        }
        let mut kernel = Self::new_with_validated_authority_backend(config, backend);
        kernel.set_authority_artifact_trust_resolver(resolver)?;
        kernel.lock_authority_signing_backend_topology();
        Ok(kernel)
    }

    fn new_with_validated_authority_backend(
        config: KernelConfig,
        backend: Arc<dyn chio_core::crypto::SigningBackend>,
    ) -> Self {
        Self::new_with_validated_authority_backend_and_clock(
            config,
            backend,
            Arc::new(chio_keyring::SystemTrustedClock),
        )
    }

    pub(super) fn new_with_validated_authority_backend_and_clock(
        config: KernelConfig,
        backend: Arc<dyn chio_core::crypto::SigningBackend>,
        capability_authority_clock: Arc<dyn chio_keyring::TrustedClock>,
    ) -> Self {
        info!("initializing Chio kernel");
        let checkpoint_batch_size = config.checkpoint_batch_size;
        let (backend, authority_signing_used) =
            crate::authority::TrackedAuthoritySigningBackend::wrap(backend);
        let signing_task =
            super::kernel_struct::build_authority_signing_task(&config, Arc::clone(&backend));
        // Read the memory-budget-driven caps before `config` is moved into the
        // struct literal.
        let receipt_mirror_capacity = config.memory_budget_receipt_mirror_capacity();
        let federation_cache_capacity = config.memory_budget_federation_cache_capacity();
        let federation_cache_idle_ttl = config.memory_budget_federation_cache_idle_ttl_secs();
        let rss_soft_limit_bytes = config.memory_budget.rss_soft_limit_bytes;
        let rss_sample_interval_secs = config.memory_budget.rss_sample_interval_secs;
        // Build the bounded-structure gauges first so they can be shared between
        // each structure and the telemetry / registry readers.
        let receipt_mirror_gauge;
        let child_receipt_mirror_gauge;
        let federation_dual_receipts_gauge;
        let federation_dsse_envelopes_gauge;
        let mut kernel = Self {
            config,
            guards: Vec::new(),
            post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline::new(),
            budget_store: Arc::new(InMemoryBudgetStore::new()),
            budget_store_lock: Mutex::new(()),
            admission_operation_store: None,
            approval_store: None,
            dispatch_worker_count: 1,
            aggregate_invocation_admission_enabled: false,
            supplemental_broker_admission_enabled: false,
            supplemental_quota_verifier: None,
            supplemental_admission_registrar: None,
            admission_capture_authority: None,
            revocation_store: Arc::new(InMemoryRevocationStore::new()),
            capability_authority_clock: Arc::clone(&capability_authority_clock),
            authority_signing_backend: Arc::clone(&backend),
            authority_signing_used,
            authority_backend_topology_locked: false,
            authority_composition_sealed: false,
            capability_authority: Box::new(crate::authority::GovernedCapabilityAuthority::new(
                backend,
                capability_authority_clock,
            )),
            authority_artifact_trust_resolver: None,
            tool_servers: HashMap::new(),
            resource_providers: Vec::new(),
            prompt_providers: Vec::new(),
            sessions: DashMap::new(),
            receipt_log: {
                let gauge = chio_bounded::SizeGauge::new();
                receipt_mirror_gauge = gauge.clone();
                Mutex::new(ReceiptLog::with_capacity(receipt_mirror_capacity, gauge))
            },
            child_receipt_log: {
                let gauge = chio_bounded::SizeGauge::new();
                child_receipt_mirror_gauge = gauge.clone();
                Mutex::new(ChildReceiptLog::with_capacity(
                    receipt_mirror_capacity,
                    gauge,
                ))
            },
            receipt_mirror_gauge,
            child_receipt_mirror_gauge,
            receipt_store: None,
            aggregate_family_root_resolver: None,
            active_response_requirement_resolver: None,
            active_response_finding_authority: None,
            active_response_submission_authority: None,
            active_response_executor: None,
            capability_issuance_admission_authority: None,
            active_response_executor_generation_floor: 0,
            governed_active_response_plans_enabled: false,
            threshold_approval_requirement_resolver: None,
            threshold_approval_policy_configured: false,
            threshold_governed_approvals_enabled: false,
            threshold_approval_policy_authorities: Vec::new(),
            governed_security_runtime_generation: 0,
            receipt_store_write_lock: Mutex::new(()),
            payment_adapter: None,
            price_oracle: None,
            runtime_admission_hook: None,
            security_pre_dispatch_policy: SecurityPreDispatchPolicy::Optional,
            security_pre_dispatch_hook: None,
            attestation_trust_policy: None,
            capability_crypto_floor: KernelCryptoFloor::AllowClassical,
            checkpoint_batch_size,
            checkpoint_seq_counter: AtomicU64::new(0),
            last_checkpoint_seq: AtomicU64::new(0),
            dpop_nonce_store: None,
            dpop_config: None,
            execution_nonce_config: None,
            execution_nonce_store: None,
            emergency_stopped: AtomicBool::new(false),
            emergency_stopped_since: AtomicU64::new(0),
            emergency_stop_reason: ArcSwap::from_pointee(Option::<String>::None),
            memory_provenance: None,
            federation_peers: ArcSwap::from_pointee(HashMap::new()),
            capability_trust_roots: ArcSwap::from_pointee(HashMap::new()),
            capability_trust_roots_write_lock: Mutex::new(()),
            federation_cosigner: None,
            federation_dual_receipts: {
                let gauge = chio_bounded::SizeGauge::new();
                federation_dual_receipts_gauge = gauge.clone();
                Mutex::new(chio_bounded::BoundedMap::new(
                    federation_cache_capacity,
                    federation_cache_idle_ttl,
                    gauge,
                ))
            },
            federation_dual_receipts_gauge,
            federation_dsse_envelopes: {
                let gauge = chio_bounded::SizeGauge::new();
                federation_dsse_envelopes_gauge = gauge.clone();
                Mutex::new(chio_bounded::BoundedMap::new(
                    federation_cache_capacity,
                    federation_cache_idle_ttl,
                    gauge,
                ))
            },
            federation_dsse_envelopes_gauge,
            federation_artifact_store: None,
            receipt_tenant_ids: Arc::new(DashMap::new()),
            receipt_federation_admissions: Arc::new(DashMap::new()),
            threshold_terminal_receipt_intents: Arc::new(DashMap::new()),
            federation_local_kernel_id: ArcSwap::from_pointee(Option::<String>::None),
            signing_task,
            settlement_observer: None,
            revocation_view: None,
            budget_registry: Mutex::new(chio_kernel_core::InMemoryBudgetRegistry::new()),
            threshold_delegated_budget_leases: Mutex::new(std::collections::HashMap::new()),
            rss_shed: Arc::new(AtomicBool::new(false)),
            rss_sampler: None,
        };
        // Start the RSS soft-ceiling sampler only when a limit is configured; with
        // no limit set, no thread is spawned.
        if let Some(limit) = rss_soft_limit_bytes {
            kernel.rss_sampler = Some(kernel_struct::RssSamplerHandle::spawn(
                Arc::clone(&kernel.rss_shed),
                limit,
                rss_sample_interval_secs,
            ));
        }
        kernel
    }

    pub(crate) fn ensure_federated_receipt_persistence_ready(
        &self,
        remote_kernel_id: Option<&str>,
    ) -> Result<(), KernelError> {
        if remote_kernel_id.is_none() {
            return Ok(());
        }
        if self.receipt_store.is_none() {
            return Err(KernelError::Internal(
                "federated receipt persistence unavailable: no durable receipt store configured"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
        if self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log {
            return Ok(());
        }
        Err(KernelError::Internal(
            "durable receipt persistence unavailable: no receipt store configured".to_string(),
        ))
    }

    pub(crate) fn scope_receipt_federation_admission_for_request(
        &self,
        request_id: &str,
        admission: ReceiptFederationAdmission,
    ) -> ScopedKernelReceiptFederationAdmission {
        let previous = self
            .receipt_federation_admissions
            .insert(request_id.to_string(), admission);
        ScopedKernelReceiptFederationAdmission {
            request_id: request_id.to_string(),
            admissions: Arc::clone(&self.receipt_federation_admissions),
            previous,
        }
    }

    pub(crate) fn receipt_federation_admission_for_request(
        &self,
        request_id: &str,
        remote_kernel_id: Option<&str>,
    ) -> Option<ReceiptFederationAdmission> {
        let admission = self
            .receipt_federation_admissions
            .get(request_id)
            .map(|entry| entry.value().clone())?;
        if admission.remote_kernel_id.as_deref() == remote_kernel_id {
            Some(admission)
        } else {
            None
        }
    }

    /// Resolve and snapshot federation receipt admission at the boundary.
    /// The returned snapshot must be carried through receipt persistence and
    /// federation cosigning; persistence must not re-resolve peer freshness
    /// after the tool has already executed.
    pub(crate) fn kernel_receipt_admission_for_remote(
        &self,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<ReceiptFederationAdmission, KernelError> {
        if let Some(remote) = remote_kernel_id {
            if let Some(peer) = self.federation_peer(remote, now) {
                return Ok(ReceiptFederationAdmission {
                    remote_kernel_id: Some(remote.to_string()),
                    peer: Some(peer),
                });
            }
            return Err(KernelError::Internal(format!(
                "named federation peer {remote} is not pinned fresh"
            )));
        }
        Ok(ReceiptFederationAdmission {
            remote_kernel_id: None,
            peer: None,
        })
    }

    /// Install (or replace) the recursive-delegation oracle handle.
    /// Default deployments leave this `None` and rely on the compatibility
    /// per-row `RevocationStore` lookup. Installing a
    /// [`chio_kernel_core::RevocationView`] here causes the verifier to
    /// consult it on every delegated dispatch.
    ///
    /// The handle is `Arc`-shared so federation gossip can install
    /// monotone snapshot updates without holding a kernel mutex.
    pub fn set_revocation_view(&mut self, view: std::sync::Arc<chio_kernel_core::RevocationView>) {
        self.revocation_view = Some(view);
    }

    /// Borrow the currently-installed revocation view, if any.
    #[must_use]
    pub fn revocation_view(&self) -> Option<&std::sync::Arc<chio_kernel_core::RevocationView>> {
        self.revocation_view.as_ref()
    }

    /// Borrow the kernel's mpsc-backed signing-task handle.
    ///
    /// Internal callers submit `ChioReceiptBody` payloads through this handle
    /// and `.await` the signed `ChioReceipt`. The underlying tokio task is
    /// spawned lazily on the first call.
    ///
    /// Not exposed publicly: callers should go through
    /// [`Self::sign_receipt_via_channel`] or the `ToolEvaluator` trait so the
    /// channel boundary stays an implementation detail of the kernel crate.
    /// Crash-recovery tests reach this directly.
    #[allow(dead_code)]
    pub(crate) fn signing_task_handle(&self) -> &signing_task::SigningTaskHandle {
        &self.signing_task
    }

    /// Sign a [`ChioReceiptBody`] off the kernel critical path via the
    /// mpsc-backed signing task.
    ///
    /// Producers `.await` on bounded backpressure rather than on a
    /// receipt-log mutex. Returns
    /// `Err(KernelError::ReceiptSigningFailed)` if the signing step
    /// itself rejected the body (e.g. the body's `kernel_key` does not
    /// match the kernel's signing public key) and
    /// `Err(KernelError::Internal)` if the signing task is no longer
    /// running.
    ///
    /// This method is async because it `.await`s on the channel send
    /// (backpressure) and on the oneshot reply. The caller must run
    /// inside a tokio runtime; every kernel-internal call site already
    /// does (the `ToolEvaluator` trait methods are async, and so is
    /// the public `evaluate_tool_call` entrypoint).
    ///
    /// `canonical_content` is the exact byte preimage `body.content_hash` was
    /// derived from. The signing task recomputes `sha256_hex(canonical_content)`
    /// inside the trust boundary and refuses to sign on mismatch (WYSIWYS,
    /// ), so this channel path is as fail-closed as the inline
    /// `build_and_sign_receipt` path.
    pub async fn sign_receipt_via_channel(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> Result<ChioReceipt, KernelError> {
        self.signing_task.sign(body, canonical_content).await
    }

    /// Drain the in-flight signing-task queue and join the task. After this
    /// call, every signing request that successfully `.send().await`-ed before
    /// shutdown has been signed and replied to; new sends surface
    /// `KernelError::Internal`.
    ///
    /// Idempotent: safe to call more than once. Safe to call on a
    /// kernel whose signing task was never spawned (no signing
    /// happened); in that case shutdown is a no-op.
    ///
    /// Note: shutdown does NOT mark the kernel as terminally stopped
    /// for other paths (capability validation, guard pipeline, store
    /// lookups). Operators that want a hard stop should call
    /// [`Self::emergency_stop`] in addition.
    pub async fn shutdown(&self) {
        self.signing_task.shutdown().await;
    }

    pub fn set_receipt_store(
        &mut self,
        receipt_store: Box<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        self.set_receipt_store_handle(Arc::from(receipt_store))
    }

    pub fn set_receipt_store_handle(
        &mut self,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        self.try_set_receipt_store_handle(receipt_store)
    }

    /// Install the explicit trusted authority for aggregate family roots.
    pub fn set_aggregate_family_root_resolver(
        &mut self,
        resolver: Arc<
            dyn chio_core::capability::aggregate_budget::AggregateFamilyRootResolver + Send + Sync,
        >,
    ) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.aggregate_family_root_resolver = Some(resolver);
    }

    /// Remove aggregate family-root authority during composition changes.
    pub fn clear_aggregate_family_root_resolver(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.aggregate_family_root_resolver = None;
    }

    /// Borrow the configured root authority without manufacturing a default.
    #[must_use]
    pub fn aggregate_family_root_resolver(
        &self,
    ) -> Option<
        &(dyn chio_core::capability::aggregate_budget::AggregateFamilyRootResolver + Send + Sync),
    > {
        self.aggregate_family_root_resolver.as_deref()
    }

    /// Install the policy-authoritative threshold requirement resolver.
    pub fn set_threshold_approval_requirement_resolver(
        &mut self,
        resolver: Arc<dyn crate::threshold_approval::ThresholdApprovalRequirementResolver>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        self.threshold_approval_requirement_resolver = Some(resolver);
        self.threshold_approval_policy_configured = true;
        Ok(())
    }

    /// Remove threshold authority during an explicit policy teardown.
    pub fn clear_threshold_approval_requirement_resolver(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.threshold_approval_requirement_resolver = None;
        self.threshold_governed_approvals_enabled = false;
        self.threshold_approval_policy_authorities.clear();
    }

    /// Disable threshold approval after an authenticated policy explicitly removes it.
    pub fn disable_threshold_approval_policy(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.threshold_approval_requirement_resolver = None;
        self.threshold_approval_policy_configured = false;
        self.threshold_governed_approvals_enabled = false;
        self.threshold_approval_policy_authorities.clear();
    }

    /// Deactivate threshold admission before changing any installed authority.
    pub fn deactivate_threshold_governed_approvals(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.threshold_governed_approvals_enabled = false;
    }

    pub(super) fn require_threshold_deactivated_for_authority_change(
        &self,
    ) -> Result<(), KernelError> {
        if self.threshold_governed_approvals_enabled {
            return Err(KernelError::Internal(
                "threshold admission must be explicitly deactivated before authority replacement"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Activate threshold admission only after all durable authorities are installed.
    pub fn enable_threshold_governed_approvals(&mut self) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if !self.threshold_approval_policy_configured
            || self.threshold_approval_requirement_resolver.is_none()
        {
            return Err(KernelError::Internal(
                "threshold approval requirement resolver is not installed".to_string(),
            ));
        }
        if self.threshold_approval_policy_authorities.is_empty() {
            return Err(KernelError::Internal(
                "threshold approval policy authority is not installed".to_string(),
            ));
        }
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "durable admission operation store authority is required".to_string(),
            )
        })?;
        Self::validate_admission_operation_store_profile(
            operation_store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        let approval_store = self.approval_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable approval store authority is required".to_string())
        })?;
        Self::validate_approval_store_profile(
            approval_store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        if !self
            .budget_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "durable budget store authority is required for threshold admission".to_string(),
            ));
        }
        if self.execution_nonce_config.is_some() {
            let nonce_store = self.execution_nonce_store.as_deref().ok_or_else(|| {
                KernelError::Internal(
                    "durable execution nonce store authority is required for threshold admission"
                        .to_string(),
                )
            })?;
            if !nonce_store
                .authority_profile()
                .supports_dispatch_workers(self.dispatch_worker_count)
            {
                return Err(KernelError::Internal(
                    "execution nonce store cannot coordinate the threshold worker topology"
                        .to_string(),
                ));
            }
        }
        self.recover_nonterminal_admission_kind_with_authorities(
            operation_store.as_ref(),
            self.budget_store.as_ref(),
            Some(approval_store.as_ref()),
            crate::admission_operation::AdmissionOperationKind::ToolDispatch,
            &format!("kernel:{}", self.public_key().to_hex()),
        )?;
        self.threshold_governed_approvals_enabled = true;
        Ok(())
    }

    /// Borrow the configured threshold authority without a permissive default.
    #[must_use]
    pub fn threshold_approval_requirement_resolver(
        &self,
    ) -> Option<&dyn crate::threshold_approval::ThresholdApprovalRequirementResolver> {
        self.threshold_approval_requirement_resolver.as_deref()
    }

    /// Replace the bounded, deduplicated policy-authority trust roots for threshold proposals.
    pub fn set_threshold_approval_policy_authorities(
        &mut self,
        authorities: Vec<chio_core::PublicKey>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        if authorities.is_empty()
            || authorities.len()
                > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        {
            return Err(KernelError::InvalidConstraint(
                "threshold proposal policy authorities must be nonempty and bounded".to_string(),
            ));
        }
        let mut deduplicated = Vec::with_capacity(authorities.len());
        for authority in authorities {
            if !deduplicated.contains(&authority) {
                deduplicated.push(authority);
            }
        }
        self.threshold_approval_policy_authorities = deduplicated;
        Ok(())
    }

    /// Install the single authenticated policy authority used by ordinary composition.
    pub fn set_threshold_approval_policy_authority(
        &mut self,
        authority: chio_core::PublicKey,
    ) -> Result<(), KernelError> {
        self.set_threshold_approval_policy_authorities(vec![authority])
    }

    /// Borrow the explicit threshold proposal trust roots.
    #[must_use]
    pub fn threshold_approval_policy_authorities(&self) -> &[chio_core::PublicKey] {
        &self.threshold_approval_policy_authorities
    }

    pub fn try_set_receipt_store_handle(
        &mut self,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        match receipt_store.load_latest_checkpoint() {
            Ok(Some(checkpoint)) => {
                if !self.verify_trusted_kernel_checkpoint(&checkpoint)? {
                    return Err(KernelError::Internal(
                        "latest receipt checkpoint is not trusted by the runtime authority resolver"
                            .to_string(),
                    ));
                }
                self.checkpoint_seq_counter
                    .store(checkpoint.body.checkpoint_seq, Ordering::SeqCst);
                self.last_checkpoint_seq
                    .store(checkpoint.body.batch_end_seq, Ordering::SeqCst);
            }
            Ok(None) => {
                self.checkpoint_seq_counter.store(0, Ordering::SeqCst);
                self.last_checkpoint_seq.store(0, Ordering::SeqCst);
            }
            Err(error) => {
                return Err(KernelError::Internal(format!(
                    "failed to hydrate checkpoint counters from receipt store: {error}"
                )));
            }
        }
        // Honor disabled checkpointing: KernelConfig
        // documents `checkpoint_batch_size = 0` as DISABLING automatic
        // checkpointing (non-web3 deployments). Only require a background signer
        // when checkpointing is enabled (batch_size > 0); with 0 the store
        // attaches with no checkpoint machinery. Web3-enabled deployments that
        // MUST checkpoint are separately guarded by
        // `validate_web3_evidence_prerequisites`, which rejects batch_size == 0.
        if self.checkpoint_batch_size > 0 && receipt_store.supports_kernel_signed_checkpoints() {
            let background_enabled = receipt_store
                .enable_background_checkpoints(
                    Arc::clone(&self.authority_signing_backend),
                    self.checkpoint_batch_size,
                )
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "failed to enable background receipt checkpoints: {error}"
                    ))
                })?;
            // Fail-closed: a store that claims checkpoint capability but did
            // not install a background signer (default hook returns
            // `Ok(false)`) would append forever without producing kernel-signed
            // Web3 checkpoints now that the synchronous trigger is gone. Reject
            // the attach rather than serve silently-checkpointless.
            if !background_enabled {
                return Err(KernelError::Internal(
                    "receipt store reports kernel-signed checkpoint support but did not install a \
                     background checkpoint signer; refusing to attach a store that would append \
                     without producing checkpoints"
                        .to_string(),
                ));
            }
        }
        self.receipt_store = Some(receipt_store);
        Ok(())
    }

    /// Compatibility installer. A replacement that cannot first prove all
    /// operation-owned payment work is drained leaves the existing adapter in
    /// place. Use [`Self::try_set_payment_adapter`] when the caller needs the
    /// rejection reason.
    pub fn set_payment_adapter(&mut self, payment_adapter: Box<dyn PaymentAdapter>) {
        let _ = self.try_set_payment_adapter(payment_adapter);
    }

    /// Install or safely replace the payment rail authority.
    pub fn try_set_payment_adapter(
        &mut self,
        payment_adapter: Box<dyn PaymentAdapter>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if self.payment_adapter.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.payment_adapter = Some(payment_adapter);
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
        if Arc::ptr_eq(&self.budget_store, &budget_store) {
            return Ok(());
        }
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        self.require_protocol_budget_admission_deactivated_for_authority_change()?;
        self.prepare_current_admission_authority_replacement()?;
        self.budget_store = budget_store;
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
        if self.aggregate_invocation_admission_enabled || self.supplemental_broker_admission_enabled
        {
            Self::validate_hard_budget_store_profile(
                self.budget_store.as_ref(),
                dispatch_worker_count,
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
        store: Box<dyn crate::admission_operation::AdmissionOperationStore>,
    ) -> Result<(), KernelError> {
        self.set_admission_operation_store_handle(Arc::from(store))
    }

    pub fn set_admission_operation_store_handle(
        &mut self,
        store: Arc<dyn crate::admission_operation::AdmissionOperationStore>,
    ) -> Result<(), KernelError> {
        if self
            .admission_operation_store
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &store))
        {
            return Ok(());
        }
        self.require_no_atomic_security_runtime_publication()?;
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
        if self
            .approval_store
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &store))
        {
            return Ok(());
        }
        self.require_no_atomic_security_runtime_publication()?;
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
        profile: crate::admission_operation::AdmissionOperationStoreProfile,
        dispatch_worker_count: usize,
    ) -> Result<(), KernelError> {
        if profile.supports_dispatch_workers(dispatch_worker_count) {
            return Ok(());
        }
        if matches!(
            profile,
            crate::admission_operation::AdmissionOperationStoreProfile::EphemeralLocal
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
        operation: crate::admission_operation::AdmissionOperation,
    ) -> Result<crate::admission_operation::AdmissionOperation, KernelError> {
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
            crate::admission_operation::AdmissionOperationCreateOutcome::Created(operation)
            | crate::admission_operation::AdmissionOperationCreateOutcome::Existing(operation) => {
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
            crate::admission_operation::AdmissionOperationKind::ToolDispatch,
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
            crate::admission_operation::AdmissionOperationKind::ToolDispatch,
            &format!("kernel:{}", self.public_key().to_hex()),
        )?;
        self.supplemental_broker_admission_enabled = true;
        Ok(())
    }

    pub(super) fn validate_protocol_budget_admission_profiles(&self) -> Result<(), KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "durable admission operation store is required for aggregate admission".to_string(),
            )
        })?;
        Self::validate_admission_operation_store_profile(
            operation_store.authority_profile(),
            self.dispatch_worker_count,
        )?;
        Self::validate_hard_budget_store_profile(
            self.budget_store.as_ref(),
            self.dispatch_worker_count,
        )?;
        Ok(())
    }

    pub(super) fn validate_hard_budget_store_profile(
        store: &dyn BudgetStore,
        dispatch_worker_count: usize,
    ) -> Result<(), KernelError> {
        let profile = store.authority_profile();
        let guarantee = store.budget_guarantee_level();
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
        if self.aggregate_invocation_admission_enabled || self.supplemental_broker_admission_enabled
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

    /// Install a settlement hook that runs after each receipt is signed
    /// and persisted. Settlement is strictly an observer relative to
    /// receipt bytes; the hook MUST NOT mutate the receipt store and
    /// MUST NOT block the dispatch path on its own latency. Hook
    /// failures are surfaced through
    /// [`Self::run_settlement_observer`]'s return value and are routed
    /// through the retry/dead-letter machinery.
    pub fn set_settlement_observer(
        &mut self,
        hook: std::sync::Arc<dyn chio_settle::SettlementHook>,
    ) {
        self.settlement_observer = Some(hook);
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
                return settlement_observer::SettlementObserverStatus::skipped(
                    "receipt signer is not trusted by the runtime authority resolver",
                );
            }
            Err(error) => {
                return settlement_observer::SettlementObserverStatus::skipped(format!(
                    "receipt authority trust resolution failed: {error}"
                ));
            }
        }
        settlement_observer::run_observer(
            self.settlement_observer.as_ref(),
            receipt,
            std::slice::from_ref(&receipt.kernel_key),
        )
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
