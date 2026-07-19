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

    /// Install the RESOLVED tenant for `request_id`, including a known-none
    /// entry for a tenantless request. The entry must exist either way:
    /// readers that miss the map fall back to the thread-local scope, and on
    /// a worker resuming this request while a sibling task's scope guard is
    /// alive that fallback would leak the sibling's tenant into this
    /// request's receipts and journaled dispatch intent.
    pub(crate) fn scope_receipt_tenant_id_for_request(
        &self,
        request_id: &str,
        tenant_id: Option<String>,
    ) -> ScopedKernelReceiptTenantId {
        let previous = self
            .receipt_tenant_ids
            .insert(request_id.to_string(), tenant_id);
        ScopedKernelReceiptTenantId {
            request_id: request_id.to_string(),
            tenant_ids: Arc::clone(&self.receipt_tenant_ids),
            previous,
        }
    }

    pub(crate) fn scope_dispatch_intent_for_request(
        &self,
        request_id: &str,
        handle: Option<crate::receipt_store::DispatchIntentHandle>,
    ) -> ScopedKernelDispatchIntent {
        let previous = match handle {
            Some(handle) => self.dispatch_intents.insert(request_id.to_string(), handle),
            None => self
                .dispatch_intents
                .remove(request_id)
                .map(|(_, previous)| previous),
        };
        ScopedKernelDispatchIntent {
            request_id: request_id.to_string(),
            intents: Arc::clone(&self.dispatch_intents),
            previous,
        }
    }

    pub(crate) fn dispatch_intent_for_request(
        &self,
        request_id: Option<&str>,
    ) -> Option<crate::receipt_store::DispatchIntentHandle> {
        request_id.and_then(|request_id| {
            self.dispatch_intents
                .get(request_id)
                .map(|entry| entry.value().clone())
        })
    }

    /// Unregister the request-scoped intent handle once a receipt has
    /// consumed the durable row, or once a timed-out consuming append has
    /// made the consume uncertain (the queued job may still commit and
    /// delete the row). A request can legitimately record more than one
    /// receipt (cleanup fault receipts alongside the terminal outcome); a
    /// handle retained past the consume would send every later receipt back
    /// through the consuming append, which rejects against the missing row
    /// and loses that audit record. With the handle gone, later receipts for
    /// the request append plainly, and a row an uncertain consume left open
    /// surfaces at the next boot.
    pub(crate) fn mark_dispatch_intent_consumed(&self, request_id: &str) {
        self.dispatch_intents.remove(request_id);
    }

    /// The tenant resolved for `request_id` by its evaluation scope. The
    /// outer `Option` is presence of the request-scoped entry; the inner one
    /// is the resolved tenant itself, so a known tenantless request returns
    /// `Some(None)` and callers do not fall back to the thread-local scope.
    pub(crate) fn receipt_tenant_id_for_request(
        &self,
        request_id: Option<&str>,
    ) -> Option<Option<String>> {
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

    /// Fallible constructor that runs fail-closed validation of the hot-path
    /// deadline config before building. This is the documented entrypoint for
    /// hosts that set `[deadlines]`. `new` stays infallible for existing
    /// callers; the append bound is additionally floor-clamped at read time so
    /// even a host that bypasses this path can never run an unbounded append.
    pub fn try_new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        config.deadlines.validate()?;
        Ok(Self::new(config))
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
            guards: std::sync::Arc::new(Vec::new()),
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
            retention_maintenance: None,
            dispatch_intent_recovery: None,
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
            lock_poison: chio_supervisor::HealthFlag::new(true),
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
            dispatch_intents: Arc::new(DashMap::new()),
            receipt_federation_admissions: Arc::new(DashMap::new()),
            threshold_terminal_receipt_intents: Arc::new(DashMap::new()),
            federation_local_kernel_id: ArcSwap::from_pointee(Option::<String>::None),
            signing_task,
            settlement_observer: None,
            settlement_retry_store: None,
            settlement_retry_policy: chio_settle::RetryPolicy::default(),
            budget_hold_sweep: None,
            revocation_view: None,
            budget_registry: Mutex::new(chio_kernel_core::InMemoryBudgetRegistry::new()),
            threshold_delegated_budget_leases: Mutex::new(std::collections::HashMap::new()),
            reserved_sibling_shares: Mutex::new(HashMap::new()),
            restart_reserved_hold_gate: Mutex::new(kernel_struct::RestartReservedHoldGate::Clear),
            rss_shed: Arc::new(AtomicBool::new(false)),
            rss_sampler: None,
            receipt_writer_watchdog: std::sync::Arc::new(
                receipt_writer_watchdog::ReceiptWriterWatchdogHandle::new(),
            ),
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
        match &self.receipt_store {
            None => Err(KernelError::Internal(
                "federated receipt persistence unavailable: no durable receipt store configured"
                    .to_string(),
            )),
            Some(store) if store.writer_serving_closed() => Err(KernelError::Internal(
                "federated receipt persistence degraded: commit writer is not serving".to_string(),
            )),
            Some(_) => Ok(()),
        }
    }

    /// Record that a trusted-computing-base lock was found poisoned. A poisoned
    /// lock means a panic unwound while the lock was held, so the state it guards
    /// may be half-mutated. Trip the persistent degraded flag so the pre-dispatch
    /// gate fails subsequent evaluations closed rather than proceeding on the
    /// recovered state.
    pub(crate) fn record_tcb_lock_poison(&self, lock: &str) {
        self.lock_poison.record_failure(
            format!("{lock} lock poisoned by a prior panic"),
            chio_supervisor::now_unix_ms(),
            0,
        );
    }

    /// Pre-dispatch gate: deny before dispatch once any TCB lock has been found
    /// poisoned, so no evaluation proceeds on state a panicking thread may have
    /// left half-mutated. Recovery is operator-visible only.
    pub(crate) fn ensure_tcb_locks_healthy(&self) -> Result<(), KernelError> {
        if self.lock_poison.is_serving_closed() {
            return Err(KernelError::Internal(
                "trusted state degraded: a TCB lock was poisoned by a prior panic".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
        if let Some(store) = &self.receipt_store {
            // A known-dead or degraded commit writer denies at the door: the tool
            // never runs, so no side effect occurs without a durable receipt path.
            if store.writer_serving_closed() {
                return Err(KernelError::Internal(
                    "durable receipt persistence degraded: commit writer is not serving"
                        .to_string(),
                ));
            }
        }
        if self.receipt_store.is_none() && !self.config.allow_ephemeral_receipt_log {
            return Err(KernelError::Internal(
                "durable receipt persistence unavailable: no receipt store configured".to_string(),
            ));
        }
        // A configured store is not enough: if the commit writer is wedged,
        // saturated, or dead, dispatching would run a tool side effect that
        // could never be durably receipted. Deny before that happens.
        // `receipt_writer_liveness` samples the store directly when no watchdog
        // has published a verdict, so the gate fails closed on a wedged writer
        // whether or not the host started the background watchdog.
        let liveness = self.receipt_writer_liveness();
        if liveness.healthy() {
            Ok(())
        } else {
            Err(KernelError::ReceiptWriterUnavailable(format!(
                "receipt commit writer is {liveness:?}; denying before dispatch"
            )))
        }
    }

    /// Receipt-writer liveness verdict the pre-dispatch gate reads. Prefers the
    /// watchdog's most recent published verdict; when no watchdog is running the
    /// published verdict stays `Unknown`, which the gate would otherwise treat as
    /// permissive. Fall back to sampling the installed store directly in that
    /// case so a durable store with a wedged commit writer is denied regardless
    /// of whether the host started the watchdog. A store without an async writer
    /// reports `Unknown` from the sample too, preserving the permissive behavior
    /// for writer-less stores.
    pub(crate) fn receipt_writer_liveness(&self) -> crate::receipt_store::ReceiptWriterLiveness {
        let published = self.receipt_writer_watchdog.current();
        if published != crate::receipt_store::ReceiptWriterLiveness::Unknown {
            return published;
        }
        self.sample_receipt_writer_liveness()
    }

    /// Sample the installed store's commit-writer liveness against the configured
    /// stall threshold. Reads the store's in-memory writer counters, so it is
    /// cheap enough to run inline on the pre-dispatch path. Returns `Unknown`
    /// when no store is installed or the store has no async writer.
    fn sample_receipt_writer_liveness(&self) -> crate::receipt_store::ReceiptWriterLiveness {
        let stall_threshold =
            std::time::Duration::from_millis(self.config.deadlines.receipt_writer_stall_ms);
        match self.with_receipt_store(|store| Ok(store.writer_liveness(stall_threshold))) {
            Ok(Some(verdict)) => verdict,
            _ => crate::receipt_store::ReceiptWriterLiveness::Unknown,
        }
    }

    /// Sample the installed store's writer liveness once and publish it into the
    /// gate's cell, without spawning the background poll task. Test-only shim so
    /// the pre-dispatch gate can be exercised deterministically.
    #[cfg(test)]
    pub(crate) fn refresh_receipt_writer_liveness_for_test(&self) {
        self.receipt_writer_watchdog
            .publish(self.sample_receipt_writer_liveness());
    }

    /// Whether the background receipt-writer watchdog poll task is installed.
    #[cfg(test)]
    pub(crate) fn receipt_writer_watchdog_is_running(&self) -> bool {
        self.receipt_writer_watchdog.is_running()
    }

    /// Start the receipt-writer liveness watchdog. Opt-in: the hosting edge
    /// calls this in an async context. It polls the store's liveness on the
    /// configured cadence and publishes the verdict the pre-dispatch gate reads.
    pub fn spawn_receipt_writer_watchdog(self: &std::sync::Arc<Self>) {
        // The watchdog polls on a `tokio::time::interval`, which panics in a
        // runtime built without a time driver. Skip the background poll in that
        // case rather than crash the host: the pre-dispatch gate already falls
        // back to sampling the store's writer liveness directly when no verdict
        // is published, so a timerless host stays fail-closed without the task.
        if !super::dispatch::dispatch_timer_available() {
            return;
        }
        let poll =
            std::time::Duration::from_millis(self.config.deadlines.receipt_writer_poll_ms.max(1));
        // Hold a weak reference between ticks. The kernel owns this task's join
        // handle, so a strong reference here would form a cycle (kernel -> handle
        // -> task -> kernel) that keeps the kernel and its receipt store alive
        // forever when the last external Arc is dropped without calling
        // shutdown(). Upgrade only to take a sample, then release before awaiting
        // the next tick, and exit once the kernel is gone.
        let kernel = std::sync::Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            loop {
                ticker.tick().await;
                let Some(kernel) = kernel.upgrade() else {
                    return;
                };
                let verdict = kernel.sample_receipt_writer_liveness();
                kernel.receipt_writer_watchdog.publish(verdict);
            }
        });
        self.receipt_writer_watchdog.set_join_handle(handle);
    }

    pub(crate) fn ensure_revocation_durability_ready(&self) -> Result<(), KernelError> {
        // A remote revocation view (federation/oracle) is consulted on every
        // delegated dispatch and is re-synced from its source after a restart, so
        // an installed view is itself a durable revocation source: it satisfies
        // the gate even when the local per-row store is the default in-memory one.
        if self.revocation_view.is_some() {
            return Ok(());
        }
        let ephemeral = self.with_revocation_store(|store| Ok(store.is_ephemeral()))?;
        if !ephemeral || self.config.allow_ephemeral_revocation_store {
            return Ok(());
        }
        Err(KernelError::Internal(
            "durable revocation state unavailable: no revocation store configured".to_string(),
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
        self.receipt_writer_watchdog.shutdown().await;
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
        // The handle is installed before recovery runs because the money-path
        // reconcile below emits signed reconciliation receipts through it.
        // Nothing serves yet (this method owns the kernel mutably), so no new
        // dispatch can journal an intent that interleaves with the boot pass.
        // Every fallible attach step follows; if any refuses, the handle and
        // any worker installed on the way are rolled back so a failed attach
        // never leaves a store serving (fail-closed), exactly as if the
        // attach had been refused up front.
        self.receipt_store = Some(Arc::clone(&receipt_store));
        if let Err(error) = self.finish_receipt_store_attach(receipt_store) {
            self.receipt_store = None;
            self.retention_maintenance = None;
            self.dispatch_intent_recovery = None;
            return Err(error);
        }
        Ok(())
    }

    fn finish_receipt_store_attach(
        &mut self,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        // Resolve the money path first: every incomplete payment-journal row
        // reaches a terminal outcome before the intent pass below runs, so
        // that pass consults settled journal state instead of racing it. No
        // priced call is in flight at attach time, so no grace horizon
        // applies.
        if self.payment_journal_active() {
            let journal_report = self.reconcile_payment_journal(0)?;
            if journal_report.resolved > 0 || journal_report.reconcile_failed > 0 {
                tracing::warn!(
                    resolved = journal_report.resolved,
                    reconcile_failed = journal_report.reconcile_failed,
                    "payment journal rows survived a restart; reconciled before serving"
                );
            }
        }
        // Resolve every dispatch intent that survived a restart: each one
        // marks a call whose effect may have run with no receipt.
        // Reconciliation runs strictly before any background worker starts,
        // and a reconcile failure refuses the attach outright (fail-closed)
        // instead of leaving a store serving with unresolved open intents.
        // Monetary orphans resolve through the payment journal when it is in
        // force; everything else dead-letters into durable, health-flipping
        // incidents (a side effect is never blindly replayed). A store
        // without the journal reports an empty pass, and a store shared
        // with a live sibling writer defers that sibling's in-flight
        // intents to their owner rather than claiming them as orphans.
        let report = if self.payment_journal_active() {
            receipt_store.reconcile_dispatch_intents(&crate::MonetaryDispatchIntentReconciler {
                kernel: self,
            })?
        } else {
            receipt_store.reconcile_dispatch_intents(&crate::DefaultDispatchIntentReconciler)?
        };
        if report.dead_lettered > 0 || report.monetary_reconciled > 0 {
            tracing::warn!(
                open = report.open,
                dead_lettered = report.dead_lettered,
                monetary_reconciled = report.monetary_reconciled,
                "dispatch intents survived a restart; incidents recorded for operator review"
            );
        }
        if report.deferred_to_live_writer > 0 {
            tracing::warn!(
                deferred = report.deferred_to_live_writer,
                "receipt store is shared with a live sibling writer; leaving its open dispatch \
                 intents for their owner (a later exclusive attach reconciles any true orphans)"
            );
        }
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
        // Spawn the retention maintenance worker only when retention is
        // configured; an unconfigured deployment gets no background thread.
        if let Some(config) = self.config.retention_config.clone() {
            // Fail-closed: prefix retention can only archive receipts already
            // covered by a kernel checkpoint (the archival watermark advances to
            // checkpoint boundaries). With automatic checkpointing disabled
            // (`checkpoint_batch_size == 0`) no background signer was installed
            // above, so the checkpoint chain can never advance past 0 and the
            // retention worker could never archive anything: the store would
            // serve forever under a policy it can never honor, silently retaining
            // every receipt. Reject the attach rather than run a retention policy
            // that can never advance its watermark.
            if self.checkpoint_batch_size == 0 {
                return Err(KernelError::Internal(
                    "KernelConfig.retention_config is set but automatic checkpointing is disabled \
                     (checkpoint_batch_size == 0); prefix retention can only archive \
                     checkpoint-covered receipts, so refusing to attach a store that could never \
                     advance its retention watermark"
                        .to_string(),
                ));
            }
            // Fail-closed: configured retention is a storage/compliance control.
            // A store whose rotate_receipts uses the default unsupported implementation would
            // attach and then only log "retention not supported" on every worker
            // interval, silently never archiving. Reject the attach rather than
            // serve traffic under a retention policy the store cannot honor.
            if !receipt_store.supports_retention() {
                return Err(KernelError::Internal(
                    "receipt store does not support retention but KernelConfig.retention_config \
                     is set; refusing to attach a store that cannot honor the configured \
                     retention policy"
                        .to_string(),
                ));
            }
            // Fail-closed: a tenant-scoped retention policy cannot be honored by a
            // prefix-watermark store (rotation archives a contiguous checkpointed
            // prefix of the whole log, not one tenant's rows), so its rotate call
            // fails closed and the worker would only log "tenant scope
            // unsupported" every interval and never archive. Reject the attach
            // rather than serve traffic under a policy the store cannot honor.
            if config.tenant_id.is_some() && !receipt_store.supports_tenant_scoped_retention() {
                return Err(KernelError::Internal(
                    "KernelConfig.retention_config sets a tenant scope but the receipt store does \
                     not support tenant-scoped retention; refusing to attach a store that cannot \
                     honor the configured retention policy"
                        .to_string(),
                ));
            }
            self.retention_maintenance =
                Some(crate::receipt_store::RetentionMaintenanceHandle::spawn(
                    Arc::clone(&receipt_store),
                    config,
                ));
        }
        // The attach-time reconcile pass above defers rows owned by live
        // sibling writers, and a sibling that crashes AFTER this attach
        // leaves rows no attach will ever revisit while this kernel stays
        // up. For stores that coordinate sibling writers, re-run
        // reconciliation on a fixed cadence: each pass claims only rows
        // whose owner is provably gone (never a live writer's, never this
        // instance's own), so a crashed sibling's orphans surface as
        // incidents even while other writers stay up. Assigned
        // unconditionally so replacing the store always retires the
        // previous store's worker.
        self.dispatch_intent_recovery =
            receipt_store.supports_dispatch_intent_recovery().then(|| {
                crate::receipt_store::DispatchIntentRecoveryHandle::spawn(
                    Arc::clone(&receipt_store),
                    crate::receipt_store::DISPATCH_INTENT_RECOVERY_INTERVAL,
                )
            });
        Ok(())
    }
}
