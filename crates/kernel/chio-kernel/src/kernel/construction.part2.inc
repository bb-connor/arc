impl ChioKernel {
    /// Resolve the active federation peer for
    /// `remote_kernel_id`, refusing stale pins fail-closed.
    pub fn federation_peer(
        &self,
        remote_kernel_id: &str,
        now: u64,
    ) -> Option<chio_federation::trust_establishment::FederationPeer> {
        let peers = self.federation_peers.load();
        let peer = peers.get(remote_kernel_id)?.clone();
        if peer.is_fresh(now) {
            Some(peer)
        } else {
            None
        }
    }

    /// Snapshot the currently-pinned federation peer set.
    pub fn federation_peers_snapshot(
        &self,
    ) -> Vec<chio_federation::trust_establishment::FederationPeer> {
        self.federation_peers.load().values().cloned().collect()
    }

    /// Look up a dual-signed receipt by the underlying
    /// [`chio_core::receipt::body::ChioReceipt`] id. Returns `None` when the
    /// receipt did not cross a federation boundary or when the
    /// co-signing hook has not yet produced a dual-signed artifact
    /// for it.
    pub fn dual_signed_receipt(
        &self,
        receipt_id: &str,
    ) -> Option<chio_federation::bilateral::DualSignedReceipt> {
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dual_receipts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(hit) = cache.get(&receipt_id.to_string(), now) {
                return Some(hit.clone());
            }
        }
        self.federation_artifact_store.as_ref().and_then(|store| {
            // A store READ error is not an admission gate (writes fail closed via
            // `?` elsewhere), but collapsing Err to None silently makes a transient
            // read failure indistinguishable from an absent artifact. Log it so the
            // read-through fallback is observable.
            match store.get_dual_signed(receipt_id) {
                Ok(hit) => hit,
                Err(error) => {
                    debug!(
                        receipt_id = %receipt_id,
                        reason = %redacted!(&error.to_string()),
                        "federation artifact-store dual-signed read failed; treating as absent"
                    );
                    None
                }
            }
        })
    }

    pub fn federation_dsse_envelope(
        &self,
        receipt_id: &str,
    ) -> Option<chio_federation::bilateral_dsse::DsseEnvelope> {
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dsse_envelopes.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(hit) = cache.get(&receipt_id.to_string(), now) {
                return Some(hit.clone());
            }
        }
        self.federation_artifact_store.as_ref().and_then(|store| {
            // As with the dual-signed read above: log a swallowed store read error
            // so a transient failure is not silently reported as an absent DSSE
            // envelope.
            match store.get_dsse(receipt_id) {
                Ok(hit) => hit,
                Err(error) => {
                    debug!(
                        receipt_id = %receipt_id,
                        reason = %redacted!(&error.to_string()),
                        "federation artifact-store DSSE read failed; treating as absent"
                    );
                    None
                }
            }
        })
    }

    /// Local kernel identifier used in bilateral co-signing. Falls back
    /// to the hex encoding of the signing public key.
    pub fn federation_local_kernel_id(&self) -> String {
        if let Some(id) = self.federation_local_kernel_id.load_full().as_ref() {
            return id.clone();
        }
        self.public_key().to_hex()
    }

    pub(super) fn treaty_dsse_extensions_from_receipt_metadata(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<Option<chio_federation::bilateral_dsse::BilateralPredicateExtensions>, KernelError>
    {
        let Some(metadata) = receipt.metadata.as_ref() else {
            return Ok(None);
        };
        let Some(value) = metadata
            .get("chio_runtime")
            .and_then(|runtime| runtime.get("federation_treaty_dsse"))
        else {
            return Ok(None);
        };
        let material: KernelFederationTreatyDsseMetadata = serde_json::from_value(value.clone())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty DSSE metadata is invalid: {error}"
                ))
            })?;
        let consistency_model = material.consistency_model.clone().ok_or_else(|| {
            KernelError::Internal(
                "federation treaty DSSE consistency model is missing from runtime material"
                    .to_string(),
            )
        })?;
        if consistency_model != material.treaty_binding_ref.consistency_model {
            return Err(KernelError::Internal(
                "federation treaty DSSE consistency model does not match treaty binding"
                    .to_string(),
            ));
        }
        let mut treaty_binding_ref = material.treaty_binding_ref;
        if treaty_binding_ref.request_sha256 != receipt.action.parameter_hash {
            return Err(KernelError::Internal(
                "federation treaty DSSE request hash does not match receipt action hash"
                    .to_string(),
            ));
        }
        treaty_binding_ref.outcome_sha256 = receipt.content_hash.clone();
        treaty_binding_ref.remote_receipt_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(receipt).map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty DSSE receipt canonicalization failed: {error}"
                ))
            })?,
        );
        Ok(Some(
            chio_federation::bilateral_dsse::BilateralPredicateExtensions {
                capability_lease_ref: Some(material.capability_lease_ref),
                policy_evaluation_summary: Some(material.policy_evaluation_summary),
                governance_receipt_ref: material.governance_receipt_ref,
                consistency_anchor: material.consistency_anchor,
                consistency_model: Some(consistency_model),
                cross_org_visibility: material.cross_org_visibility,
                treaty_binding_ref: Some(treaty_binding_ref),
            },
        ))
    }

    /// Post-sign hook. Invoked immediately after
    /// [`Self::build_and_sign_receipt`] so the local (tool-host)
    /// signature has already landed in the `ChioReceipt`. When
    /// `federated_origin_kernel_id` is set and the admission-time peer
    /// snapshot is available, this dispatches the receipt to the
    /// cosigner, assembles a [`chio_federation::bilateral::DualSignedReceipt`],
    /// and stashes it for retrieval via [`Self::dual_signed_receipt`].
    ///
    /// Fail-closed: any error from peer resolution or the cosigner is
    /// surfaced as a [`KernelError::Internal`] so operators see the
    /// federation drift rather than silently shipping a receipt without
    /// the remote signature. Production evaluate paths pass the
    /// admission-time snapshot; direct record callers still get a
    /// fresh-peer fallback. Non-federated requests (`None` origin) are a
    /// no-op.
    pub(crate) fn apply_federation_cosign(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &chio_core::receipt::body::ChioReceipt,
        admitted_peer: Option<&chio_federation::trust_establishment::FederationPeer>,
    ) -> Result<(), KernelError> {
        self.apply_federation_cosign_at_timestamp(
            request,
            receipt,
            admitted_peer,
            current_unix_timestamp().saturating_mul(1_000),
        )
    }

    pub(crate) fn apply_federation_cosign_at_timestamp(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &chio_core::receipt::body::ChioReceipt,
        admitted_peer: Option<&chio_federation::trust_establishment::FederationPeer>,
        timestamp_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let Some(origin_kernel_id) = request.federated_origin_kernel_id.as_ref() else {
            return Ok(());
        };
        let Some(cosigner) = self.federation_cosigner.as_ref() else {
            return Err(KernelError::Internal(format!(
                "federation cosigner missing for request {request_id} bound to origin kernel {origin_kernel_id}",
                request_id = request.request_id,
            )));
        };
        let peer = match admitted_peer {
            Some(peer) if peer.kernel_id == *origin_kernel_id => peer.clone(),
            _ => {
                let now = current_unix_timestamp();
                self.federation_peer(origin_kernel_id, now).ok_or_else(|| {
                    KernelError::Internal(format!(
                        "federation peer {origin_kernel_id} is not pinned fresh and no admission-time peer snapshot is in scope"
                    ))
                })?
            }
        };

        let local_kernel_id = self.federation_local_kernel_id();
        let extensions = match self.treaty_dsse_extensions_from_receipt_metadata(receipt)? {
            Some(extensions) => extensions,
            None => {
                // A federated request rejected before runtime treaty admission
                // ran (capability verification, time bounds, revocation, subject
                // binding) never produced the bilateral treaty material the
                // dual-sign path binds, and dispatched no cross-org outcome to
                // co-sign. Record such a deny single-signed, with no dual-signed
                // or DSSE artifact, matching the pre-dispatch denial contract in
                // federated_request_without_receipt_store_denies_before_dispatch_or_cosign.
                // An allowed federated outcome always carries treaty material, so
                // any non-deny receipt still fails closed here.
                if matches!(
                    receipt.decision,
                    Some(chio_core::receipt::decision::Decision::Deny { .. })
                ) {
                    return Ok(());
                }
                return Err(KernelError::Internal(
                    "federation runtime treaty material missing; refusing treaty-bound DSSE"
                        .to_string(),
                ));
            }
        };
        let dual = chio_federation::bilateral::co_sign_with_origin_backend(
            origin_kernel_id,
            &peer.public_key,
            &local_kernel_id,
            self.authority_signing_backend.as_ref(),
            receipt.clone(),
            cosigner.as_ref(),
        )
        .map_err(|e| KernelError::Internal(format!("bilateral co-sign failed: {e}")))?;
        let dsse_envelope =
            chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope_with_cosigner_backend(
                chio_federation::bilateral_dsse::BilateralDsseBackendCosigningInput {
                    invocation:
                        chio_federation::bilateral_dsse::BilateralDsseInvocationInput {
                            receipt,
                            org_a_kernel_id: origin_kernel_id,
                            org_b_kernel_id: &local_kernel_id,
                            tool_name: &request.tool_name,
                            timestamp_unix_ms,
                            extensions,
                        },
                    org_a_public_key: &peer.public_key,
                    org_b_signer: self.authority_signing_backend.as_ref(),
                    org_a_cosigner: cosigner.as_ref(),
                },
            )
            .map_err(|e| KernelError::Internal(format!("bilateral DSSE co-sign failed: {e}")))?;

        // Write through to the artifact store (if one is installed via
        // set_federation_artifact_store) BEFORE the bounded caches. An entry
        // evicted from a cache is only guaranteed resolvable when the store
        // DURABLY retains it: a bounded in-memory store can evict the same id the
        // caches did, so only a store that reports itself durable suppresses the
        // evidence-loss signal below.
        let durable_store_installed = self
            .federation_artifact_store
            .as_ref()
            .is_some_and(|store| store.is_durable());
        if let Some(store) = self.federation_artifact_store.as_ref() {
            store.put_dual_signed(&receipt.id, &dual)?;
            store.put_dsse(&receipt.id, &dsse_envelope)?;
        }
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dual_receipts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // An evicted entry survives only through a durable store. Without one
            // the drop is lossy by policy (bounded drop-oldest); log it so the
            // evidence loss is explicit for operators.
            if cache.insert(receipt.id.clone(), dual, now).is_some() && !durable_store_installed {
                debug!(
                    request_id = %request.request_id,
                    "dropping an evicted dual-signed co-sign artifact: bounded federation cache is full and no durable FederationArtifactStore is installed"
                );
            }
        }
        {
            let mut cache = match self.federation_dsse_envelopes.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cache
                .insert(receipt.id.clone(), dsse_envelope, now)
                .is_some()
                && !durable_store_installed
            {
                debug!(
                    request_id = %request.request_id,
                    "dropping an evicted co-sign DSSE envelope: bounded federation cache is full and no durable FederationArtifactStore is installed"
                );
            }
        }
        Ok(())
    }

    /// Engage the emergency kill switch.
    ///
    /// After this call, every `evaluate_tool_call*` path returns a signed
    /// deny receipt with reason `"kernel emergency stop active"` before
    /// touching capability validation or the guard pipeline. The kernel
    /// remains running so orchestrators and health probes see a live
    /// process; it is inert.
    ///
    /// The active capability set is NOT purged from the revocation store:
    /// the current `RevocationStore` trait has no bulk revoke API and
    /// capability expiration plus the kill-switch flag together
    /// cover this surface. When a future revision adds `revoke_all`,
    /// this method should call it; until then, capability revocation is
    /// delegated to natural expiration.
    pub fn emergency_stop(&self, reason: &str) -> Result<(), KernelError> {
        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;
        // Record the timestamp first so any concurrent reader that observes
        // `emergency_stopped == true` sees a non-zero `since` value.
        self.emergency_stopped_since.store(now, Ordering::SeqCst);
        self.emergency_stop_reason
            .store(Arc::new(Some(reason.to_string())));
        self.emergency_stopped.store(true, Ordering::SeqCst);

        warn!(
            reason = %redacted!(reason),
            timestamp = now,
            "emergency stop engaged -- all evaluations will be denied"
        );
        Ok(())
    }

    /// Disengage the emergency kill switch and resume normal operation.
    ///
    /// Subsequent `evaluate_tool_call*` calls follow the full validation
    /// pipeline again. Capabilities that naturally expired while the
    /// kernel was stopped remain expired; the kill switch does not
    /// retroactively grant anything.
    pub fn emergency_resume(&self) -> Result<(), KernelError> {
        self.emergency_stopped.store(false, Ordering::SeqCst);
        self.emergency_stopped_since.store(0, Ordering::SeqCst);

        warn!("emergency stop disengaged -- evaluations will resume");

        self.emergency_stop_reason
            .store(Arc::new(Option::<String>::None));
        Ok(())
    }

    /// Return `true` when the emergency kill switch is engaged.
    #[must_use]
    pub fn is_emergency_stopped(&self) -> bool {
        self.emergency_stopped.load(Ordering::SeqCst)
    }

    /// Return `true` when the RSS soft-ceiling sampler has flagged that process
    /// RSS crossed `memory_budget.rss_soft_limit_bytes`. A single relaxed atomic
    /// load on the admission fast path.
    #[must_use]
    pub fn is_rss_shedding(&self) -> bool {
        self.rss_shed.load(Ordering::Relaxed)
    }

    /// Enumerate each long-lived bounded structure's telemetry label and its
    /// current live entry count. This is the registry the size-metric convention
    /// and the soak harness read; adding a
    /// new long-lived collection without a gauge here fails the registry test.
    #[must_use]
    pub fn bounded_structure_gauges(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("receipt_mirror", self.receipt_mirror_gauge.get()),
            (
                "child_receipt_mirror",
                self.child_receipt_mirror_gauge.get(),
            ),
            (
                "federation_dual_receipts",
                self.federation_dual_receipts_gauge.get(),
            ),
            (
                "federation_dsse_envelopes",
                self.federation_dsse_envelopes_gauge.get(),
            ),
        ]
    }

    #[cfg(test)]
    pub(crate) fn set_rss_shed_for_test(&self, on: bool) {
        self.rss_shed.store(on, Ordering::Relaxed);
    }

    /// Return the unix timestamp (seconds) at which the kill switch was
    /// engaged, or `None` when the kernel is currently running normally.
    #[must_use]
    pub fn emergency_stopped_since(&self) -> Option<u64> {
        if !self.is_emergency_stopped() {
            return None;
        }
        let since = self.emergency_stopped_since.load(Ordering::SeqCst);
        if since == 0 {
            None
        } else {
            Some(since)
        }
    }

    /// Return the operator-supplied reason for the current emergency stop,
    /// or `None` when the kernel is running normally.
    #[must_use]
    pub fn emergency_stop_reason(&self) -> Option<String> {
        if !self.is_emergency_stopped() {
            return None;
        }
        self.emergency_stop_reason.load_full().as_ref().clone()
    }

    /// Install a DPoP nonce replay store and verification config.
    ///
    /// Once installed, any invocation whose matched grant has `dpop_required == Some(true)`
    /// must carry a valid `DpopProof` on the `ToolCallRequest`. Requests that lack a proof
    /// or whose proof fails verification are denied fail-closed.
    pub fn set_dpop_store(&mut self, nonce_store: dpop::DpopNonceStore, config: dpop::DpopConfig) {
        self.dpop_nonce_store = Some(nonce_store);
        self.dpop_config = Some(config);
    }

    /// Install an execution-nonce config and replay store.
    ///
    /// Once installed, every `Verdict::Allow` carries a short-lived signed
    /// nonce on `ToolCallResponse::execution_nonce`. Tool servers re-present
    /// that nonce via `ToolCallRequest::execution_nonce`, and the kernel
    /// verifies it through `verify_presented_execution_nonce` before executing.
    /// The free-standing verifier checks raw signatures only and must not
    /// replace this resolver-aware boundary in a keyring-backed runtime.
    ///
    /// Set `config.require_nonce = true` to put the kernel into strict mode:
    /// any call that reaches `require_presented_execution_nonce` without a
    /// nonce is denied. When `require_nonce == false` the feature is opt-in
    /// per tool server and non-nonce callers continue to work (backward
    /// compatibility).
    pub fn set_execution_nonce_store(
        &mut self,
        config: crate::execution_nonce::ExecutionNonceConfig,
        store: Box<dyn crate::execution_nonce::ExecutionNonceStore>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_threshold_deactivated_for_authority_change()?;
        if self.execution_nonce_store.is_some() {
            self.prepare_current_admission_authority_replacement()?;
        }
        self.execution_nonce_config = Some(config);
        self.execution_nonce_store = Some(store);
        Ok(())
    }

    /// Returns `true` when execution-nonce strict mode is active.
    ///
    /// Strict mode requires every presented tool call to carry a fresh,
    /// valid, single-use nonce. When `false` the kernel is either not
    /// minting nonces at all (no config installed) or is in opt-in mode
    /// where tool servers can verify presented nonces but non-nonce calls
    /// are not outright rejected.
    #[must_use]
    pub fn execution_nonce_required(&self) -> bool {
        self.execution_nonce_config
            .as_ref()
            .is_some_and(|cfg| cfg.require_nonce)
    }

    /// Compute the nonce binding for a call from the request, capability, and
    /// the canonical parameter hash. Used to mint the nonce before the receipt
    /// is signed so the receipt can record the nonce id (hold <-> nonce
    /// cross-binding).
    pub(crate) fn nonce_binding_for(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        parameter_hash: &str,
    ) -> crate::execution_nonce::NonceBinding {
        crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: parameter_hash.to_string(),
        }
    }

    /// Mint a signed execution nonce for an allow verdict.
    ///
    /// Returns `Ok(None)` when no config is installed (nonces disabled) or
    /// when this request already presented a nonce for execution. Otherwise
    /// returns `Ok(Some(nonce))` once configured. The nonce binding is
    /// derived from the capability subject, capability ID, target server/tool,
    /// and the canonical parameter hash embedded in the just-signed allow
    /// receipt so the verify-time check is always comparing apples to apples.
    pub(crate) fn mint_execution_nonce_for_allow(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        receipt: &ChioReceipt,
    ) -> Result<Option<Box<crate::execution_nonce::SignedExecutionNonce>>, KernelError> {
        self.mint_execution_nonce_for_allow_reserving(request, cap, receipt, None)
    }

    /// Mint an allow-verdict nonce that, when `reserved_hold_id` is `Some`,
    /// additionally binds the reserved budget hold and the reserving request id
    /// into the signed body. Only the pre-execution authorization-reserving path
    /// supplies a hold id; every other allow path passes `None` and mints a
    /// backward-compatible nonce carrying no hold identity.
    pub(crate) fn mint_execution_nonce_for_allow_reserving(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        receipt: &ChioReceipt,
        reserved_hold_id: Option<&str>,
    ) -> Result<Option<Box<crate::execution_nonce::SignedExecutionNonce>>, KernelError> {
        self.mint_execution_nonce_for_allow_reserving_parameter_hash(
            request,
            cap,
            &receipt.action.parameter_hash,
            reserved_hold_id,
        )
    }

    /// Mint a reserving nonce from the canonical action hash before the
    /// reservation receipt is signed. Operation-owned caller reservations use
    /// this ordering so the private nonce can stamp the exact hold expiry before
    /// invocation capture, while the later receipt records the durable
    /// `CallerReserved` projection.
    pub(crate) fn mint_execution_nonce_for_allow_reserving_parameter_hash(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        parameter_hash: &str,
        reserved_hold_id: Option<&str>,
    ) -> Result<Option<Box<crate::execution_nonce::SignedExecutionNonce>>, KernelError> {
        if request.execution_nonce.is_some() {
            return Ok(None);
        }
        let Some(config) = self.execution_nonce_config.as_ref() else {
            return Ok(None);
        };
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        let binding = self.nonce_binding_for(request, cap, parameter_hash);
        let (reserved_hold_id, reserving_request_id) = match reserved_hold_id {
            Some(hold_id) => (Some(hold_id.to_string()), Some(request.request_id.clone())),
            None => (None, None),
        };
        let signed = crate::execution_nonce::mint_execution_nonce_with_backend_and_reservation(
            self.authority_signing_backend.as_ref(),
            binding,
            reserved_hold_id,
            reserving_request_id,
            config,
            now,
        )?;
        Ok(Some(Box::new(signed)))
    }

    /// Verify a caller-presented execution nonce against the
    /// expected binding, consuming it in the replay store on success.
    ///
    /// Returns `Ok(())` when the nonce is fresh, correctly bound, signed
    /// by this kernel, and has not been consumed. Returns an error
    /// wrapping `ExecutionNonceError` on any failure (expired, tampered,
    /// replayed, binding mismatch, store unreachable).
    pub fn verify_presented_execution_nonce(
        &self,
        presented: &crate::execution_nonce::SignedExecutionNonce,
        expected: &crate::execution_nonce::NonceBinding,
    ) -> Result<(), crate::execution_nonce::ExecutionNonceError> {
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            crate::execution_nonce::ExecutionNonceError::Store(
                "execution nonce store is not installed".to_string(),
            )
        })?;
        self.verify_presented_execution_nonce_without_consuming(presented, expected)?;
        crate::execution_nonce::consume_verified_execution_nonce(presented, store)
    }

    fn verify_presented_execution_nonce_without_consuming(
        &self,
        presented: &crate::execution_nonce::SignedExecutionNonce,
        expected: &crate::execution_nonce::NonceBinding,
    ) -> Result<(), crate::execution_nonce::ExecutionNonceError> {
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        let claimed_issuer = self.public_key();
        crate::execution_nonce::verify_execution_nonce_stateless(
            presented,
            &claimed_issuer,
            expected,
            now,
        )?;
        self.verify_execution_nonce_artifact_trust(presented, &claimed_issuer)
    }

    /// Apply the installed current/historical authority resolver to one nonce.
    pub(crate) fn verify_execution_nonce_artifact_trust(
        &self,
        presented: &crate::execution_nonce::SignedExecutionNonce,
        claimed_issuer: &chio_core::PublicKey,
    ) -> Result<(), crate::execution_nonce::ExecutionNonceError> {
        let artifact = crate::execution_nonce::execution_nonce_signed_artifact(presented)?;
        match self.verify_trusted_authority_artifact_signature(
            &artifact,
            claimed_issuer,
            &presented.signature,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::execution_nonce::ExecutionNonceError::InvalidSignature),
            Err(error) => Err(crate::execution_nonce::ExecutionNonceError::AuthorityTrust(
                error.to_string(),
            )),
        }
    }

    /// Execution-nonce dispatch gate.
    ///
    /// Denies fail-closed when strict mode is configured and the request
    /// lacks a nonce. When strict mode is disabled, a request with no
    /// nonce remains backward-compatible. Any presented nonce is still
    /// verified and consumed so opt-in callers cannot bypass binding,
    /// expiry, signature, or replay checks.
    ///
    /// Returns `Ok(())` when:
    /// * no nonce is required and none was presented, OR
    /// * a nonce is presented, signed by this kernel, correctly bound,
    ///   non-expired, and has not been consumed.
    ///
    /// Returns `Err(KernelError::Internal(...))` fail-closed otherwise.
    pub fn require_presented_execution_nonce(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let presented = request.execution_nonce.as_ref();
        if !self.execution_nonce_required() && presented.is_none() {
            return Ok(());
        }
        let presented = presented.ok_or_else(|| {
            KernelError::Internal(
                "execution nonce required but not presented on tool call".to_string(),
            )
        })?;
        let expected = self.execution_nonce_binding(request, cap)?;
        self.verify_presented_execution_nonce(presented, &expected)
            .map_err(|e| KernelError::Internal(format!("{e}")))
    }

    /// Verify and reserve a presented nonce under one durable admission
    /// operation without anonymously consuming it. The operation's cleanup
    /// journal is persisted before this method is entered, so a crash before
    /// `CapturePending` can cancel the reservation idempotently and a crash
    /// after `CapturePending` can commit it idempotently.
    pub(crate) fn reserve_presented_execution_nonce_for_operation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        operation_id: &str,
    ) -> Result<(), KernelError> {
        let presented = request.execution_nonce.as_ref();
        if !self.execution_nonce_required() && presented.is_none() {
            return Ok(());
        }
        let presented = presented.ok_or_else(|| {
            KernelError::Internal(
                "execution nonce required but not presented on durable tool admission".to_string(),
            )
        })?;
        let expected = self.execution_nonce_binding(request, cap)?;
        self.verify_presented_execution_nonce_without_consuming(presented, &expected)
            .map_err(|error| KernelError::Internal(error.to_string()))?;

        let operation = self.load_ordinary_admission(operation_id)?;
        if operation.execution_nonce_id() != Some(presented.nonce_id()) {
            return Err(KernelError::Internal(
                "durable admission operation changed its execution nonce binding".to_string(),
            ));
        }
        if !matches!(
            operation.state(),
            crate::security_admission_operation::AdmissionOperationState::BudgetAuthorized
                | crate::security_admission_operation::AdmissionOperationState::ReadyToDispatch
                | crate::security_admission_operation::AdmissionOperationState::CapturePending
        ) {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "admission operation {} cannot reserve an execution nonce from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal(
                "durable execution nonce store is unavailable for ordinary admission".to_string(),
            )
        })?;
        if !store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "execution nonce store cannot coordinate the ordinary admission worker topology"
                    .to_string(),
            ));
        }
        let reservation = match store.reserve_nonce_for_operation(
            operation.operation_id(),
            presented.nonce_id(),
            presented.expires_at(),
        ) {
            Ok(reservation) => reservation,
            Err(error) => match store.get_nonce_reservation(operation.operation_id()) {
                Ok(Some(reservation)) => reservation,
                _ => {
                    return Err(KernelError::GovernedTransactionDenied(format!(
                        "ordinary execution nonce reservation failed: {error}"
                    )));
                }
            },
        };
        if reservation.operation_id() != operation.operation_id()
            || reservation.nonce_id() != presented.nonce_id()
            || reservation.signed_expires_at() != presented.expires_at()
            || reservation.state()
                == crate::security_admission_operation::ReplayReservationState::Cancelled
        {
            return Err(KernelError::GovernedTransactionDenied(
                "ordinary execution nonce reservation returned a different or cancelled binding"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn execution_nonce_binding(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<crate::execution_nonce::NonceBinding, KernelError> {
        let parameter_hash = chio_core::receipt::decision::ToolCallAction::from_parameters(
            request.arguments.clone(),
        )
        .map_err(|e| KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}")))?
        .parameter_hash;
        Ok(crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash,
        })
    }

    /// Strict-mode nonce issuance gate.
    ///
    /// In strict mode, a request that reaches evaluation without a presented
    /// nonce is an authorization preflight. It may receive a freshly signed
    /// nonce, but it must not execute the target tool. Actual execution
    /// presents that nonce on a later request and enters replay protection
    /// before dispatch. Durable admissions bind replay state to their operation
    /// so crash recovery can commit or cancel it without reopening the nonce.
    #[must_use]
    pub(crate) fn execution_nonce_preflight_required(&self, request: &ToolCallRequest) -> bool {
        self.execution_nonce_required() && request.execution_nonce.is_none()
    }

    pub fn requires_web3_evidence(&self) -> bool {
        self.config.require_web3_evidence
    }

    pub fn validate_web3_evidence_prerequisites(&self) -> Result<(), KernelError> {
        if !self.requires_web3_evidence() {
            return Ok(());
        }

        let Some(supports_kernel_signed_checkpoints) =
            self.with_receipt_store(|store| Ok(store.supports_kernel_signed_checkpoints()))?
        else {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require a durable receipt store".to_string(),
            ));
        };

        self.validate_web3_evidence_receipt_store(supports_kernel_signed_checkpoints)
    }

    /// Validate a prospective receipt store before installing it.
    pub fn validate_web3_evidence_receipt_store(
        &self,
        supports_kernel_signed_checkpoints: bool,
    ) -> Result<(), KernelError> {
        if !self.requires_web3_evidence() {
            return Ok(());
        }

        if self.checkpoint_batch_size == 0 {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require checkpoint_batch_size > 0".to_string(),
            ));
        }

        if !supports_kernel_signed_checkpoints {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require local receipt persistence with kernel-signed checkpoint support; append-only remote receipt mirrors are unsupported".to_string(),
            ));
        }

        Ok(())
    }

    /// Register a policy guard. Guards are evaluated in registration order.
    /// If any guard denies, the request is denied.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        // Guard registration remains copy-on-write for the async offload path.
        std::sync::Arc::make_mut(&mut self.guards).push(std::sync::Arc::from(guard));
    }

    /// Install a product-specific runtime admission hook. The hook runs after
    /// core authorization checks and guards, but before tool dispatch.
    pub fn set_runtime_admission_hook(&mut self, hook: Arc<dyn RuntimeAdmissionHook>) {
        self.runtime_admission_hook = Some(hook);
    }

    /// Remove the product-specific runtime admission hook.
    pub fn clear_runtime_admission_hook(&mut self) {
        self.runtime_admission_hook = None;
    }

    /// Configure whether authoritative security context and a pre-dispatch
    /// hook are mandatory before entering a tool connector.
    pub fn set_security_pre_dispatch_policy(&mut self, policy: SecurityPreDispatchPolicy) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.security_pre_dispatch_policy = policy;
    }

    #[must_use]
    pub const fn security_pre_dispatch_policy(&self) -> SecurityPreDispatchPolicy {
        self.security_pre_dispatch_policy
    }

    /// Install the last-moment security hook that commits authoritative flow
    /// state immediately before tool dispatch.
    pub fn set_security_pre_dispatch_hook(&mut self, hook: Arc<dyn SecurityPreDispatchHook>) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.security_pre_dispatch_hook = Some(hook);
    }

    #[must_use]
    pub fn security_pre_dispatch_hook_name(&self) -> Option<&str> {
        self.security_pre_dispatch_hook
            .as_ref()
            .map(|hook| hook.name())
    }

    /// Remove the last-moment security pre-dispatch hook.
    pub fn clear_security_pre_dispatch_hook(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.security_pre_dispatch_hook = None;
    }

    /// Register a tool server connection.
    pub fn register_tool_server(&mut self, connection: Box<dyn ToolServerConnection>) {
        let id = connection.server_id().to_owned();
        if self.has_atomic_security_runtime_publication() {
            match self.tool_servers.entry(id) {
                std::collections::hash_map::Entry::Occupied(route) => {
                    info!(server_id = %route.key(), "retaining frozen tool server route");
                }
                std::collections::hash_map::Entry::Vacant(route) => {
                    info!(server_id = %route.key(), "registering tool server");
                    route.insert(Arc::from(connection));
                }
            }
            return;
        }
        info!(server_id = %id, "registering tool server");
        self.tool_servers.insert(id, Arc::from(connection));
    }

    /// Register a resource provider.
    pub fn register_resource_provider(&mut self, provider: Box<dyn ResourceProvider>) {
        info!("registering resource provider");
        self.resource_providers.push(provider);
    }

    /// Register a prompt provider.
    pub fn register_prompt_provider(&mut self, provider: Box<dyn PromptProvider>) {
        info!("registering prompt provider");
        self.prompt_providers.push(provider);
    }
}
