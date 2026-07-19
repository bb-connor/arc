//! `ChioKernel` capability and budget validation.
//!
//! Holds capability issuance/revocation, tool-server event drains, portable
//! verdict helpers, and budget charge/reconcile helpers. Governed-admission
//! validation lives in `governed_validation.rs`.

use chio_log_redact::redacted;

use self::responses::{
    FinalizeToolOutputCostContext, FinalizeToolOutputRequest, PostInvocationHandling,
};
use super::kernel_struct::OperationOwnedDelegatedBudgetLease;
use super::*;
use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetEventAuthority,
    BudgetHoldMutationDecision, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReleaseHoldDecision, BudgetReleaseHoldRequest, BudgetReverseHoldDecision,
    BudgetReverseHoldRequest,
};

struct IssuedCapabilityPostconditions<'a> {
    expected_subject: &'a chio_core::PublicKey,
    expected_scope: &'a ChioScope,
    ttl_seconds: u64,
    authority_key: &'a chio_core::PublicKey,
    security_context: Option<&'a crate::CapabilityIssuanceContext>,
    now: u64,
}

impl ChioKernel {
    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        if self.capability_issuance_admission_authority.is_some() {
            return Err(KernelError::CapabilityIssuanceDenied(
                "authoritative tenant and lineage context is required for capability issuance"
                    .to_string(),
            ));
        }
        let capability = self.issue_capability_unrecorded(subject, &scope, ttl_seconds, None)?;
        self.record_observed_capability_snapshot(&capability)?;
        Ok(capability)
    }

    /// Issue a capability through the governed active-defense admission path.
    ///
    /// The trusted context is checked before signing and checked again when the
    /// resulting capability snapshot is transactionally made visible. The
    /// second boundary closes a concurrent fence-acquisition race.
    pub fn issue_capability_with_security_context(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        security_context: &SecurityInvocationContext,
    ) -> Result<CapabilityToken, KernelError> {
        let context = security_context.as_v1();
        let query = chio_security_types::ports::IssuanceFreezeAdmissionQuery {
            tenant_id: context.tenant_id().clone(),
            lineage_id: context.lineage_root_id().clone(),
            operation: chio_security_types::ports::CapabilityIssuanceOperation::Issue,
            parent_capability_id: None,
        };
        self.authorize_capability_issuance(&query)?;
        let issuance_context = crate::CapabilityIssuanceContext::authoritative_session(
            query.tenant_id.clone(),
            query.lineage_id.clone(),
            context.session_id().clone(),
            context.principal_id().clone(),
            context.isolation_epoch_id().clone(),
            context.context_generation(),
        );
        let capability = self.issue_capability_unrecorded(
            subject,
            &scope,
            ttl_seconds,
            Some(&issuance_context),
        )?;
        self.record_observed_capability_snapshot_for_dispatch(&capability, Some(security_context))?;
        Ok(capability)
    }

    fn issue_capability_unrecorded(
        &self,
        subject: &chio_core::PublicKey,
        scope: &ChioScope,
        ttl_seconds: u64,
        security_context: Option<&crate::CapabilityIssuanceContext>,
    ) -> Result<CapabilityToken, KernelError> {
        // Minting and its postcondition share one fallible snapshot. The scoped
        // value also reaches wrapped governed authorities without widening the
        // public CapabilityAuthority API.
        let now = crate::authority::capability_authority_now_unix_secs(
            self.capability_authority_clock.as_ref(),
        )?;
        let _clock_scope = scope_fixed_runtime_unix_secs_for_current_thread(now);
        let authority_key = self.capability_authority.authority_public_key();
        let capability = match security_context {
            Some(context) => self
                .capability_authority
                .issue_capability_with_security_context(
                    subject,
                    scope.clone(),
                    ttl_seconds,
                    None,
                    context,
                )?,
            None => {
                self.capability_authority
                    .issue_capability(subject, scope.clone(), ttl_seconds)?
            }
        };
        let capability = self.finalize_issued_capability(
            capability,
            IssuedCapabilityPostconditions {
                expected_subject: subject,
                expected_scope: scope,
                ttl_seconds,
                authority_key: &authority_key,
                security_context,
                now,
            },
        )?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            "issuing capability"
        );

        Ok(capability)
    }

    fn finalize_issued_capability(
        &self,
        capability: CapabilityToken,
        postconditions: IssuedCapabilityPostconditions<'_>,
    ) -> Result<CapabilityToken, KernelError> {
        let IssuedCapabilityPostconditions {
            expected_subject,
            expected_scope,
            ttl_seconds,
            authority_key,
            security_context,
            now,
        } = postconditions;
        let issuance_error =
            |reason: &str| KernelError::CapabilityIssuanceFailed(reason.to_string());
        let expected_scope_bytes = canonical_json_bytes(expected_scope).map_err(|error| {
            issuance_error(&format!("requested capability scope is invalid: {error}"))
        })?;
        let returned_scope_bytes = canonical_json_bytes(&capability.scope).map_err(|error| {
            issuance_error(&format!("issued capability scope is invalid: {error}"))
        })?;
        if &capability.issuer != authority_key
            || &capability.subject != expected_subject
            || returned_scope_bytes != expected_scope_bytes
        {
            return Err(issuance_error(
                "issued capability does not match the requested authority, subject, or scope",
            ));
        }
        capability.validate_schema().map_err(|error| {
            issuance_error(&format!("issued capability schema is invalid: {error}"))
        })?;
        let security_binding = capability.security_binding().map_err(|error| {
            issuance_error(&format!(
                "issued capability security binding is invalid: {error}"
            ))
        })?;
        let external_authority = authority_key != &self.authority_signing_backend.public_key();
        if external_authority && security_binding.is_none() {
            return Err(issuance_error(
                "external capability authority omitted the required signed security binding",
            ));
        }
        if let Some(binding) = security_binding.as_ref() {
            let context = security_context.ok_or_else(|| {
                issuance_error(
                    "security-bound capability was issued without an authoritative session context",
                )
            })?;
            let session_id = context.session_id.as_ref().ok_or_else(|| {
                issuance_error("security-bound capability context omitted its session")
            })?;
            let principal_id = context.principal_id.as_ref().ok_or_else(|| {
                issuance_error("security-bound capability context omitted its principal")
            })?;
            let isolation_epoch_id = context.isolation_epoch_id.as_ref().ok_or_else(|| {
                issuance_error("security-bound capability context omitted its isolation epoch")
            })?;
            let context_generation = context.context_generation.ok_or_else(|| {
                issuance_error("security-bound capability context omitted its generation")
            })?;
            if binding.tenant_id != context.tenant_id.as_str()
                || binding.lineage_id != context.lineage_id.as_str()
                || binding.session_id != session_id.as_str()
                || binding.principal_id != principal_id.as_str()
                || binding.isolation_epoch_id != isolation_epoch_id.as_str()
                || binding.context_generation != context_generation
            {
                return Err(issuance_error(
                    "issued capability security binding does not match the authoritative session context",
                ));
            }
        }
        if !capability.delegation_chain.is_empty()
            || capability
                .scope_attenuations
                .as_ref()
                .is_some_and(|attenuations| !attenuations.is_empty())
            || capability.attenuation_proof.is_some()
            || capability.budget_share_bps.is_some()
            || capability.aggregate_invocation_budget.is_some()
        {
            return Err(issuance_error(
                "direct issuance returned delegated or attenuated authority",
            ));
        }
        if !matches!(
            capability.expires_at.checked_sub(capability.issued_at),
            Some(lifetime) if lifetime > 0 && lifetime <= ttl_seconds
        ) {
            return Err(issuance_error(
                "issued capability lifetime is outside the requested bound",
            ));
        }
        if !capability.verify_signature_at(now).map_err(|error| {
            issuance_error(&format!("issued capability verification failed: {error}"))
        })? {
            return Err(issuance_error(
                "issued capability signature verification failed",
            ));
        }

        // The capability authority has already returned a complete signed
        // token and every authority, subject, exact-scope, direct-issuance,
        // lifetime, schema, validity, and signature postcondition above has
        // been checked. Re-signing here is cryptographically redundant and
        // would turn an external artifact signer into a capability-minting
        // oracle that bypasses contextual issuance policy and freeze checks.
        Ok(capability)
    }

    /// Revoke a capability and all descendants in its delegation subtree.
    ///
    /// When a root capability is revoked, every capability whose
    /// `delegation_chain` contains the revoked ID will also be rejected
    /// on presentation (the kernel checks all chain entries against the
    /// revocation store).
    pub fn revoke_capability(&self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let _ = self.with_revocation_store(|store| Ok(store.revoke(capability_id)?))?;
        Ok(())
    }

    /// Read-only access to the receipt log.
    pub fn receipt_log(&self) -> ReceiptLog {
        match self.receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn child_receipt_log(&self) -> ChildReceiptLog {
        match self.child_receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    #[must_use]
    pub fn guard_names(&self) -> Vec<&str> {
        self.guards.iter().map(|guard| guard.name()).collect()
    }

    #[must_use]
    pub fn post_invocation_hook_count(&self) -> usize {
        self.post_invocation_pipeline.len()
    }

    #[must_use]
    pub fn post_invocation_hook_names(&self) -> Vec<&str> {
        self.post_invocation_pipeline.names()
    }

    pub async fn drain_tool_server_events_async(
        &self,
    ) -> Result<Vec<ToolServerEvent>, KernelError> {
        let mut events = Vec::new();
        let mut first_error = None;
        for (server_id, server) in &self.tool_servers {
            match server.drain_events().await {
                Ok(mut server_events) => events.append(&mut server_events),
                Err(error) => {
                    warn!(
                        server_id = %server_id,
                        reason = %redacted!(&error),
                        "failed to drain tool server events"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if events.is_empty() {
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Ok(events)
    }

    pub fn try_drain_tool_server_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        block_on_async_tool_dispatch(self.drain_tool_server_events_async())
    }

    pub fn drain_tool_server_events(&self) -> Vec<ToolServerEvent> {
        match self.try_drain_tool_server_events() {
            Ok(events) => events,
            Err(error) => {
                warn!(
                    reason = %redacted!(&error),
                    "failed to drain tool server events"
                );
                Vec::new()
            }
        }
    }

    pub fn register_session_pending_url_elicitation(
        &self,
        session_id: &SessionId,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_pending_url_elicitation(elicitation_id, related_task_id);
            Ok(())
        })
    }

    pub fn register_session_required_url_elicitations(
        &self,
        session_id: &SessionId,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_required_url_elicitations(elicitations, related_task_id);
            Ok(())
        })
    }

    pub fn queue_session_elicitation_completion(
        &self,
        session_id: &SessionId,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_elicitation_completion(elicitation_id);
            Ok(())
        })
    }

    pub fn queue_session_late_event(
        &self,
        session_id: &SessionId,
        event: LateSessionEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_late_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_event(
        &self,
        session_id: &SessionId,
        event: ToolServerEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_tool_server_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_events(
        &self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.try_drain_tool_server_events()?;
        self.with_session_mut(session_id, |session| {
            for event in events {
                session.queue_tool_server_event(event);
            }
            Ok(())
        })
    }

    pub async fn queue_session_tool_server_events_async(
        &self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.drain_tool_server_events_async().await?;
        self.with_session_mut(session_id, |session| {
            for event in events {
                session.queue_tool_server_event(event);
            }
            Ok(())
        })
    }

    pub fn drain_session_late_events(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<LateSessionEvent>, KernelError> {
        self.with_session_mut(session_id, |session| Ok(session.take_late_events()))
    }

    pub fn ca_count(&self) -> usize {
        self.config.ca_public_keys.len()
    }

    pub fn public_key(&self) -> chio_core::PublicKey {
        self.authority_signing_backend.public_key()
    }

    /// Set the configured capability-token crypto floor.
    ///
    /// Boot paths that load `policy.crypto_floor` must call this before
    /// accepting traffic when they do not use [`Self::with_hybrid_signing_backend`].
    pub fn set_capability_crypto_floor(&mut self, floor: KernelCryptoFloor) {
        self.capability_crypto_floor = floor;
    }

    /// Check only statically configured issuer membership.
    ///
    /// Resolver-governed runtime keys require the complete signed artifact and
    /// therefore fail this issuer-only query closed.
    pub fn capability_issuer_is_trusted(&self, issuer: &chio_core::PublicKey) -> bool {
        if self.authority_artifact_trust_resolver.is_some() {
            return self.config.ca_public_keys.contains(issuer);
        }
        self.trusted_issuer_keys().contains(issuer)
    }

    /// Verify the capability's signature against the trusted CA keys or the
    /// kernel's own key (for locally-issued capabilities).
    /// Resolve the trusted-issuer set for capability verification.
    ///
    /// This combines the configured CA public keys, the capability
    /// authority's trusted keys, and the kernel's own public key. The
    /// method is also used by the chio-kernel-core delegation path
    /// so the portable TCB verifier sees the same trust set as the
    /// inline check.
    pub(crate) fn trusted_issuer_keys(&self) -> Vec<chio_core::PublicKey> {
        let mut trusted = self.config.ca_public_keys.clone();
        let kernel_pk = self.public_key();
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }
        trusted
    }

    /// Verify an authority artifact under either the live runtime key or a
    /// keyring-backed current- or historical-key decision with trusted time.
    pub fn verify_trusted_authority_artifact_signature(
        &self,
        artifact: &[u8],
        claimed_issuer: &chio_core::PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<bool, KernelError> {
        if !claimed_issuer.verify(artifact, signature) {
            return Ok(false);
        }
        match self.authority_artifact_trust_resolver.as_ref() {
            Some(resolver) => {
                let trusted = resolver
                    .trusted_issuer_for_artifact(artifact, claimed_issuer, signature)
                    .map_err(|error| {
                        KernelError::Internal(format!(
                            "authority artifact trust resolution failed: {error}"
                        ))
                    })?;
                Ok(trusted.as_ref() == Some(claimed_issuer))
            }
            None => Ok(claimed_issuer == &self.public_key()),
        }
    }

    pub fn verify_trusted_receipt(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<bool, KernelError> {
        if !receipt
            .verify_signature()
            .map_err(|error| KernelError::Internal(error.to_string()))?
        {
            return Ok(false);
        }
        let signing_body = chio_core::receipt::signing::ChioReceiptSigningBody::from_body_and_bbs(
            &receipt.body(),
            receipt.bbs_signature.as_ref(),
        );
        let artifact = canonical_json_bytes(&signing_body)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(
            &artifact,
            &receipt.kernel_key,
            &receipt.signature,
        )
    }

    pub fn verify_trusted_child_receipt(
        &self,
        receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<bool, KernelError> {
        if !receipt
            .verify_signature()
            .map_err(|error| KernelError::Internal(error.to_string()))?
        {
            return Ok(false);
        }
        let artifact = canonical_json_bytes(&receipt.body())
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(
            &artifact,
            &receipt.kernel_key,
            &receipt.signature,
        )
    }

    pub fn verify_trusted_session_anchor(
        &self,
        anchor: &chio_core::session::SessionAnchor,
    ) -> Result<bool, KernelError> {
        if !anchor
            .verify_signature()
            .map_err(|error| KernelError::Internal(error.to_string()))?
        {
            return Ok(false);
        }
        let artifact = canonical_json_bytes(&anchor.body())
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(
            &artifact,
            &anchor.kernel_key,
            &anchor.signature,
        )
    }

    pub fn verify_trusted_kernel_checkpoint(
        &self,
        checkpoint: &crate::checkpoint::KernelCheckpoint,
    ) -> Result<bool, KernelError> {
        crate::checkpoint::validate_checkpoint(checkpoint)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let artifact = canonical_json_bytes(&checkpoint.body)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(
            &artifact,
            &checkpoint.body.kernel_key,
            &checkpoint.signature,
        )
    }

    pub fn verify_trusted_bilateral_signature(
        &self,
        body: &chio_federation::bilateral::CoSigningBody,
        claimed_issuer: &chio_core::PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<bool, KernelError> {
        let artifact = body
            .canonical_bytes()
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(&artifact, claimed_issuer, signature)
    }

    pub fn verify_trusted_dsse_signature(
        &self,
        envelope: &chio_federation::bilateral_dsse::DsseEnvelope,
        claimed_issuer: &chio_core::PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<bool, KernelError> {
        let artifact = envelope
            .pae_bytes()
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        self.verify_trusted_authority_artifact_signature(&artifact, claimed_issuer, signature)
    }

    pub(crate) fn trusted_issuer_keys_for(
        &self,
        capability: &CapabilityToken,
        _now: u64,
    ) -> Result<Vec<chio_core::PublicKey>, String> {
        let mut trusted = self.config.ca_public_keys.clone();
        if trusted.contains(&capability.issuer) {
            return Ok(trusted);
        }
        let Some(resolver) = self.authority_artifact_trust_resolver.as_ref() else {
            let runtime_issuer = self.public_key();
            if !trusted.contains(&runtime_issuer) {
                trusted.push(runtime_issuer);
            }
            return Ok(trusted);
        };
        capability
            .validate_schema()
            .map_err(|error| error.to_string())?;
        let schema_aware_artifact =
            canonical_json_bytes(&capability.signing_body()).map_err(|error| error.to_string())?;
        let artifact = if capability
            .issuer
            .verify(&schema_aware_artifact, &capability.signature)
        {
            schema_aware_artifact
        } else if capability
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            canonical_json_bytes(&capability.body()).map_err(|error| error.to_string())?
        } else {
            return Err(
                "capability signature does not verify over a supported preimage".to_string(),
            );
        };
        let resolved = resolver.trusted_issuer_for_artifact(
            &artifact,
            &capability.issuer,
            &capability.signature,
        )?;
        match resolved {
            Some(issuer) => {
                if issuer != capability.issuer {
                    return Err(
                        "artifact trust resolver returned a key that does not match the capability issuer"
                            .to_string(),
                    );
                }
                trusted.push(issuer);
            }
            None => {
                return Err(
                    "artifact trust resolver rejected the runtime capability issuer".to_string(),
                );
            }
        }
        Ok(trusted)
    }

    /// Spec: PROTOCOL.md requires production kernels to route every
    /// capability admission through `verify_capability_full`; this wrapper
    /// is the kernel-side enforcement of that MUST.
    pub(crate) fn verify_capability_full_pre_admit(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let trusted = self.trusted_issuer_keys_for(cap, now)?;
        let clock = chio_kernel_core::FixedClock::new(now);
        let peer_profile = self.capability_negotiation_for_remote(remote_kernel_id, now)?;
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let mut budgets = chio_kernel_core::NoopBudgetRegistry;

        chio_kernel_core::verify_capability_full(
            cap,
            &trusted,
            &clock,
            capability_crypto_floor(self.capability_crypto_floor),
            &peer_profile,
            &trust_resolver,
            &mut budgets,
        )
        .map(|_| ())
        .map_err(|error| chio_kernel_core::KernelCoreError::InvalidCapability(error).deny_reason())
    }

    /// The hosted `evaluate_tool_call_*` paths route the full chain
    /// through [`Self::verify_capability_full_pre_admit`], which runs
    /// the production verifier with `NoopBudgetRegistry` so a token
    /// that subsequently fails any other check does not consume the
    /// parent's share. This method then performs the deferred admit
    /// against the kernel's long-lived `budget_registry`. The lock is
    /// held only for the duration of the admit call, matching the
    /// portable hot path.
    ///
    /// Errors are returned as plain strings so the caller can route
    /// them through the existing deny-response paths without taking
    /// a `KernelError` dependency on the verifier shape.
    ///
    /// The split between pre-admit verification and budget admission
    /// enforces the ordering rule "signature first, admit last", so a
    /// denied request never starves later valid siblings.
    /// Admit `cap`'s sibling-sum budget share under its parent, acquiring one
    /// per-evaluation holder lease on the child admission edge.
    ///
    /// Returns `Ok(true)` when THIS evaluation acquired a lease: the capability
    /// has a parent and the admit succeeded, whether it INSERTED a fresh edge
    /// or took an additional holder on an edge an overlapping evaluation
    /// already inserted (an idempotent re-admit). Returns `Ok(false)` only when
    /// the capability has no parent to admit against (no lease exists to
    /// release). A failed admit (oversubscribe / cap-exceed / different share)
    /// acquires NO lease and returns `Err`.
    ///
    /// The lease increment happens inside `try_admit_child` under the registry
    /// lock, so it is atomic with the insert/holder decision (no TOCTOU). The
    /// boolean tells a pre-dispatch cleanup path whether THIS evaluation holds a
    /// lease it must release: exactly the evaluations that acquired a lease
    /// release one (via `release_admitted_capability_budget`), and the edge is
    /// freed only when the last holder releases. Reference counting - rather
    /// than a "newly inserted" owner flag - is required because overlapping
    /// evaluations of the same delegated capability concurrently depend on the
    /// single registry edge; freeing it on the inserting evaluation's cleanup
    /// would return a re-admitting sibling's live share and let an
    /// oversubscribing sibling bypass the parent cap.
    pub(crate) fn admit_capability_budget(&self, cap: &CapabilityToken) -> Result<bool, String> {
        if let Some(parent_link) = cap.delegation_chain.last() {
            use chio_kernel_core::BudgetRegistry;
            let proposed_share = cap
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            budgets
                .try_admit_child(
                    parent_link.capability_id.as_str(),
                    cap.id.clone(),
                    proposed_share,
                )
                .map_err(|err| err.to_string())?;
            // The admit succeeded against a parent link, so this evaluation now
            // holds a lease it is responsible for releasing on cleanup.
            return Ok(true);
        }

        Ok(false)
    }

    pub(crate) fn release_admitted_capability_budget(
        &self,
        cap: &CapabilityToken,
    ) -> Result<(), String> {
        if let Some(parent_link) = cap.delegation_chain.last() {
            use chio_kernel_core::BudgetRegistry;
            let proposed_share = cap
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            budgets
                .release_child(
                    parent_link.capability_id.as_str(),
                    cap.id.as_str(),
                    proposed_share,
                )
                .map_err(|err| err.to_string())?;
        }

        Ok(())
    }

    /// Verify a persisted capability before a runtime reuses it after restart.
    ///
    /// This routes current and historical runtime issuers through the installed
    /// artifact resolver and applies the same signature, time, crypto-floor,
    /// and delegation checks as ordinary pre-admission verification.
    pub fn verify_stored_capability_for_reuse(
        &self,
        capability: &CapabilityToken,
        now: u64,
    ) -> Result<(), String> {
        self.verify_capability_full_pre_admit(capability, None, now)
    }

    pub(super) fn reserve_threshold_delegated_budget(
        &self,
        cap: &CapabilityToken,
        operation: &AdmissionOperation,
    ) -> Result<bool, KernelError> {
        if operation.capability_id() != cap.id {
            return Err(KernelError::DelegationInvalid(
                "threshold delegated budget operation does not match the capability".to_string(),
            ));
        }
        let Some(parent_link) = cap.delegation_chain.last() else {
            return Ok(false);
        };
        let proposed_share = cap
            .budget_share_bps
            .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
        let expected = OperationOwnedDelegatedBudgetLease {
            request_binding_hash: operation.request_binding_hash().to_string(),
            parent_capability_id: parent_link.capability_id.clone(),
            child_capability_id: cap.id.clone(),
            budget_share_bps: proposed_share,
        };
        let mut leases = match self.threshold_delegated_budget_leases.lock() {
            Ok(leases) => leases,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(existing) = leases.get(operation.operation_id()) {
            if existing == &expected {
                return Ok(true);
            }
            return Err(KernelError::DelegationInvalid(
                "threshold delegated budget operation is bound to a different lease".to_string(),
            ));
        }

        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(budgets) => budgets,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets
            .try_admit_child(
                parent_link.capability_id.as_str(),
                cap.id.clone(),
                proposed_share,
            )
            .map_err(|error| {
                KernelError::DelegationInvalid(format!(
                    "sibling-sum budget admission failed: {error}"
                ))
            })?;
        leases.insert(operation.operation_id().to_string(), expected);
        Ok(true)
    }

    pub(super) fn release_threshold_delegated_budget(
        &self,
        cap: &CapabilityToken,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        let mut leases = match self.threshold_delegated_budget_leases.lock() {
            Ok(leases) => leases,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(existing) = leases.get(operation.operation_id()).cloned() else {
            return Ok(());
        };
        if existing.request_binding_hash != operation.request_binding_hash()
            || existing.child_capability_id != cap.id
        {
            return Err(KernelError::DelegationInvalid(
                "threshold delegated budget release does not match operation ownership".to_string(),
            ));
        }
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(budgets) => budgets,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets
            .release_child(
                existing.parent_capability_id.as_str(),
                existing.child_capability_id.as_str(),
                existing.budget_share_bps,
            )
            .map_err(|error| KernelError::DelegationInvalid(error.to_string()))?;
        leases.remove(operation.operation_id());
        Ok(())
    }

    pub(super) fn release_pre_dispatch_delegated_budget(
        &self,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
    ) -> Result<(), KernelError> {
        if let Some(operation) = self.threshold_operation_for_budget_mutation(budget_mutation)? {
            return self.release_threshold_delegated_budget(cap, &operation);
        }
        self.release_admitted_capability_budget(cap)
            .map_err(KernelError::DelegationInvalid)
    }

    pub(super) fn threshold_operation_for_budget_mutation(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        let Some(admission) = budget_mutation.ordinary_admission() else {
            return Ok(None);
        };
        let operation = self
            .admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "operation-owned delegated budget release requires an admission store"
                        .to_string(),
                )
            })?
            .load(admission.operation_id())?
            .ok_or_else(|| {
                KernelError::Internal(
                    "operation-owned delegated budget release lost its admission operation"
                        .to_string(),
                )
            })?;
        Ok(operation.approval_set_hash().is_some().then_some(operation))
    }

    /// Run the portable pure-compute verdict path provided by
    /// `chio-kernel-core`.
    ///
    /// This exposes the same synchronous checks the core kernel performs
    /// (capability signature, issuer trust, time bounds, subject binding,
    /// scope match, sync guard pipeline) in isolation from the
    /// `chio-kernel`-only concerns (budget mutation, revocation lookup,
    /// governed-transaction evaluation, tool dispatch, receipt
    /// persistence).
    ///
    /// Adapters that run the kernel on constrained platforms (wasm32,
    /// edge workers, mobile via FFI) should prefer this entry point --
    /// it does not require a tokio runtime, a sqlite database, or any
    /// IO adapter. The full `evaluate_tool_call_*` API remains the
    /// authoritative path for the desktop sidecar.
    ///
    /// Verified-core boundary note:
    /// `formal/proof-manifest.toml` treats this shell method as the one
    /// `chio-kernel` entrypoint inside the current bounded verified core,
    /// because it delegates directly to `chio_kernel_core::evaluate` after
    /// supplying trusted issuers and portable guard/context wiring.
    pub fn evaluate_portable_verdict<'a>(
        &self,
        capability: &'a CapabilityToken,
        request: &chio_kernel_core::PortableToolCallRequest,
        guards: &'a [&'a dyn chio_kernel_core::Guard],
        clock: &'a dyn chio_kernel_core::Clock,
        session_filesystem_roots: Option<&'a [String]>,
    ) -> chio_kernel_core::EvaluationVerdict {
        let trusted = match self.trusted_issuer_keys_for(capability, clock.now_unix_secs()) {
            Ok(trusted) => trusted,
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(format!(
                        "capability artifact trust resolution failed; denying fail-closed: {reason}"
                    )),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let peer_profile = match self.capability_negotiation_for_remote(None, clock.now_unix_secs())
        {
            Ok(profile) => profile,
            // Fail closed: a negotiation error denies rather than falling back
            // to the permissive default profile.
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(format!(
                        "capability negotiation failed; denying fail-closed: {reason}"
                    )),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        chio_kernel_core::evaluate_with_full_floor(
            chio_kernel_core::EvaluateInput {
                request,
                capability,
                trusted_issuers: &trusted,
                clock,
                guards,
                session_filesystem_roots,
            },
            capability_crypto_floor(self.capability_crypto_floor),
            &peer_profile,
            &trust_resolver,
            &mut *budgets,
        )
    }

    pub fn register_budget_parent(
        &self,
        parent_token_id: String,
        parent_share_bps: u16,
    ) -> Result<(), chio_kernel_core::BudgetSplitError> {
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets.register_parent(parent_token_id, parent_share_bps)
    }

    pub fn evict_budget_parent(&self, parent_token_id: &str) {
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets.evict_parent(parent_token_id);
    }

    /// Check the revocation store for the capability and its entire
    /// delegation chain. If any ancestor is revoked, the capability is
    /// rejected.
    pub(crate) fn check_revocation(&self, cap: &CapabilityToken) -> Result<(), KernelError> {
        if self.with_revocation_store(|store| Ok(store.is_revoked(&cap.id)?))? {
            return Err(KernelError::CapabilityRevoked(cap.id.clone()));
        }
        for link in &cap.delegation_chain {
            if self.with_revocation_store(|store| Ok(store.is_revoked(&link.capability_id)?))? {
                return Err(KernelError::DelegationChainRevoked(
                    link.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_delegation_admission(
        &self,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        // When the `delegation` feature is on, consult the installed
        // `RevocationView` snapshot before re-running the validation chain
        // validation. Fail-closed: a revoked ancestor or leaf denies
        // dispatch even if the chain is otherwise valid. This is a
        // no-op (`Ok(())`) when no view is installed.
        #[cfg(feature = "delegation")]
        delegation::consult_revocation_view(cap, self.revocation_view.as_ref())?;

        if cap.delegation_chain.is_empty() {
            return Ok(());
        }

        chio_core::capability::attenuation::validate_delegation_chain(
            &cap.delegation_chain,
            Some(self.config.max_delegation_depth),
        )
        .map_err(|error| KernelError::DelegationInvalid(error.to_string()))?;

        let Some(last_link) = cap.delegation_chain.last() else {
            return Err(KernelError::DelegationInvalid(
                "delegation chain disappeared after validation".to_string(),
            ));
        };
        if last_link.delegatee != cap.subject {
            return Err(KernelError::DelegationInvalid(format!(
                "leaf capability subject {} does not match final delegation delegatee {}",
                cap.subject.to_hex(),
                last_link.delegatee.to_hex()
            )));
        }

        let mut ancestor_snapshots = Vec::with_capacity(cap.delegation_chain.len());
        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let snapshot = self
                .with_receipt_store(
                    |store| Ok(store.get_capability_snapshot(&link.capability_id)?),
                )?
                .flatten()
                .ok_or_else(|| {
                    KernelError::DelegationInvalid(format!(
                        "missing capability snapshot for delegation ancestor {} at link index {}",
                        link.capability_id, index
                    ))
                })?;
            let expected_depth = index as u64;
            if snapshot.delegation_depth != expected_depth {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} has stored depth {}, expected {}",
                    snapshot.capability_id, index, snapshot.delegation_depth, expected_depth
                )));
            }

            let expected_parent_capability_id = index
                .checked_sub(1)
                .map(|parent_index| cap.delegation_chain[parent_index].capability_id.as_str());
            if snapshot.parent_capability_id.as_deref() != expected_parent_capability_id {
                let observed_parent = snapshot.parent_capability_id.as_deref().unwrap_or("<root>");
                let expected_parent = expected_parent_capability_id.unwrap_or("<root>");
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} is lineage-linked to {}, expected {}",
                    snapshot.capability_id, index, observed_parent, expected_parent
                )));
            }

            ancestor_snapshots.push(snapshot);
        }

        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let parent_snapshot = &ancestor_snapshots[index];
            let parent_scope = scope_from_capability_snapshot(parent_snapshot)?;

            if parent_snapshot.subject_key != link.delegator.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegator {} does not match parent capability subject {}",
                    index,
                    link.delegator.to_hex(),
                    parent_snapshot.subject_key
                )));
            }
            if link.timestamp < parent_snapshot.issued_at
                || link.timestamp >= parent_snapshot.expires_at
            {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} timestamp {} is outside parent capability {} validity window [{} , {})",
                    index,
                    link.timestamp,
                    parent_snapshot.capability_id,
                    parent_snapshot.issued_at,
                    parent_snapshot.expires_at
                )));
            }

            let (
                child_capability_id,
                child_subject_key,
                child_scope,
                child_issued_at,
                child_expires_at,
                child_parent_capability_id,
            ) = if let Some(next_snapshot) = ancestor_snapshots.get(index + 1) {
                (
                    next_snapshot.capability_id.clone(),
                    next_snapshot.subject_key.clone(),
                    scope_from_capability_snapshot(next_snapshot)?,
                    next_snapshot.issued_at,
                    next_snapshot.expires_at,
                    next_snapshot.parent_capability_id.clone(),
                )
            } else {
                (
                    cap.id.clone(),
                    cap.subject.to_hex(),
                    cap.scope.clone(),
                    cap.issued_at,
                    cap.expires_at,
                    Some(link.capability_id.clone()),
                )
            };

            if child_subject_key != link.delegatee.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegatee {} does not match child capability subject {}",
                    index,
                    link.delegatee.to_hex(),
                    child_subject_key
                )));
            }
            if child_parent_capability_id.as_deref() != Some(link.capability_id.as_str()) {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} is not lineage-linked to parent capability {}",
                    child_capability_id, link.capability_id
                )));
            }
            if child_issued_at < link.timestamp {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} was issued before delegation link {} timestamp",
                    child_capability_id, index
                )));
            }
            if child_issued_at < parent_snapshot.issued_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} predates parent capability {} issuance",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }
            if child_expires_at > parent_snapshot.expires_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} expires after parent capability {}",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }

            validate_delegation_scope_step(
                &parent_snapshot.capability_id,
                &child_capability_id,
                &parent_scope,
                &child_scope,
                child_expires_at,
                link,
            )?;
        }

        Ok(())
    }

    pub(crate) fn local_budget_event_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: format!("kernel:{}", self.public_key().to_hex()),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        }
    }

    pub(crate) fn budget_backend_receipt_metadata(&self) -> Result<serde_json::Value, KernelError> {
        let (guarantee_level, authority_profile, metering_profile) =
            self.with_budget_store(|store| {
                Ok((
                    store.budget_guarantee_level().as_str().to_string(),
                    store.budget_authority_profile().as_str().to_string(),
                    store.budget_metering_profile().as_str().to_string(),
                ))
            })?;
        Ok(serde_json::json!({
            "budget_authority": {
                "guarantee_level": guarantee_level,
                "authority_profile": authority_profile,
                "metering_profile": metering_profile,
            }
        }))
    }

    pub(crate) fn budget_execution_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        terminal_event: Option<(&str, &BudgetHoldMutationDecision)>,
    ) -> serde_json::Value {
        let mut budget_authority = serde_json::Map::new();
        budget_authority.insert(
            "guarantee_level".to_string(),
            serde_json::json!(charge.authorize_metadata.guarantee_level.as_str()),
        );
        budget_authority.insert(
            "authority_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.budget_profile.as_str()),
        );
        budget_authority.insert(
            "metering_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.metering_profile.as_str()),
        );
        budget_authority.insert(
            "hold_id".to_string(),
            serde_json::json!(&charge.budget_hold_id),
        );
        if let Some(budget_term) = charge.authorize_metadata.budget_term() {
            budget_authority.insert("budget_term".to_string(), serde_json::json!(budget_term));
        }
        if let Some(authority) = charge.authorize_metadata.authority.as_ref() {
            budget_authority.insert(
                "authority".to_string(),
                serde_json::json!({
                    "authority_id": &authority.authority_id,
                    "lease_id": &authority.lease_id,
                    "lease_epoch": authority.lease_epoch,
                }),
            );
        }

        let mut authorize = serde_json::Map::new();
        if let Some(event_id) = charge.authorize_metadata.event_id.as_ref() {
            authorize.insert("event_id".to_string(), serde_json::json!(event_id));
        }
        if let Some(commit_index) = charge.authorize_metadata.budget_commit_index {
            authorize.insert(
                "budget_commit_index".to_string(),
                serde_json::json!(commit_index),
            );
        }
        authorize.insert(
            "exposure_units".to_string(),
            serde_json::json!(charge.cost_charged),
        );
        authorize.insert(
            "committed_cost_units_after".to_string(),
            serde_json::json!(charge.new_committed_cost_units),
        );
        budget_authority.insert(
            "authorize".to_string(),
            serde_json::Value::Object(authorize),
        );

        if let Some((disposition, terminal_event)) = terminal_event {
            let mut terminal = serde_json::Map::new();
            terminal.insert("disposition".to_string(), serde_json::json!(disposition));
            if let Some(event_id) = terminal_event.metadata.event_id.as_ref() {
                terminal.insert("event_id".to_string(), serde_json::json!(event_id));
            }
            if let Some(commit_index) = terminal_event.metadata.budget_commit_index {
                terminal.insert(
                    "budget_commit_index".to_string(),
                    serde_json::json!(commit_index),
                );
            }
            terminal.insert(
                "exposure_units".to_string(),
                serde_json::json!(terminal_event.exposure_units),
            );
            terminal.insert(
                "realized_spend_units".to_string(),
                serde_json::json!(terminal_event.realized_spend_units),
            );
            terminal.insert(
                "committed_cost_units_after".to_string(),
                serde_json::json!(terminal_event.committed_cost_units_after),
            );
            budget_authority.insert("terminal".to_string(), serde_json::Value::Object(terminal));
        }

        serde_json::json!({ "budget_authority": budget_authority })
    }

    pub(crate) fn merge_budget_receipt_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
        budget_metadata: serde_json::Value,
    ) -> Option<serde_json::Value> {
        let mut merged = match extra_metadata {
            Some(serde_json::Value::Object(mut metadata)) => {
                // budget_authority is a kernel-reserved namespace. Discard the
                // entire caller-supplied block before inserting verified store
                // and kernel state so omitted authoritative fields cannot be
                // inherited from untrusted metadata.
                metadata.remove("budget_authority");
                metadata
            }
            _ => serde_json::Map::new(),
        };

        if let serde_json::Value::Object(authoritative) = budget_metadata {
            for (key, value) in authoritative {
                merged.insert(key, value);
            }
        }

        Some(serde_json::Value::Object(merged))
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns the matched grant index and the exact pre-execution budget mutation.
    pub(crate) fn check_and_increment_budget(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        let mut saw_exhausted_budget = false;

        for matching in matching_grants {
            let grant = matching.grant;
            if cap.aggregate_invocation_budget.is_some()
                || request.supplemental_authorization.is_some()
            {
                let mutation = self.coordinate_ordinary_protocol_admission(
                    request,
                    cap,
                    matching.index,
                    grant,
                    current_unix_timestamp(),
                )?;
                return Ok((matching.index, mutation));
            }
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary {
                // Use worst-case max_cost_per_invocation as the pre-execution debit.
                let cost_units = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.units)
                    .unwrap_or(0);
                let currency = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.currency.clone())
                    .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                    .unwrap_or_else(|| "USD".to_string());
                let max_total = grant.max_total_cost.as_ref().map(|m| m.units);
                let max_per = grant.max_cost_per_invocation.as_ref().map(|m| m.units);
                let budget_total = max_total.unwrap_or(u64::MAX);
                let budget_hold_id = format!(
                    "budget-hold:{}:{}:{}",
                    request.request_id, cap.id, matching.index
                );
                let authorize_event_id = format!("{budget_hold_id}:authorize");
                let authority = self.local_budget_event_authority();

                let decision = self.with_budget_store(|store| {
                    Ok(
                        store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                            cap.id.clone(),
                            matching.index,
                            grant.max_invocations,
                            cost_units,
                            max_per,
                            max_total,
                            Some(budget_hold_id.clone()),
                            Some(authorize_event_id),
                            Some(authority.clone()),
                        ))?,
                    )
                })?;
                match decision {
                    BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                        let charge = BudgetChargeResult {
                            grant_index: matching.index,
                            cost_charged: cost_units,
                            currency,
                            budget_total,
                            new_committed_cost_units: authorized.committed_cost_units_after,
                            budget_hold_id: authorized
                                .hold_id
                                .unwrap_or_else(|| budget_hold_id.clone()),
                            authorize_metadata: authorized.metadata,
                            admission_operation: None,
                        };
                        return Ok((
                            matching.index,
                            PreExecutionBudgetMutation::Charge(Box::new(charge)),
                        ));
                    }
                    BudgetAuthorizeHoldDecision::Denied(_) => {
                        saw_exhausted_budget = true;
                    }
                }
            } else {
                if grant.max_invocations.is_none() {
                    return Ok((matching.index, PreExecutionBudgetMutation::None));
                }

                if self.with_budget_store(|store| {
                    Ok(store.try_increment(&cap.id, matching.index, grant.max_invocations)?)
                })? {
                    return Ok((
                        matching.index,
                        PreExecutionBudgetMutation::Invocation {
                            grant_index: matching.index,
                        },
                    ));
                }
                saw_exhausted_budget = true;
            }
        }

        if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok((first_index, PreExecutionBudgetMutation::None))
        }
    }

    pub(crate) fn reverse_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReverseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                reversed_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reverse_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?)
        })
    }

    pub(crate) fn release_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReleaseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                released_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.release_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?)
        })
    }

    pub(crate) fn reverse_pre_execution_budget_mutation(
        &self,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => {
                self.reverse_budget_charge(&cap.id, charge).map(Some)
            }
            PreExecutionBudgetMutation::Invocation { grant_index } => {
                self.with_budget_store(|store| {
                    Ok(store.reverse_charge_cost(&cap.id, *grant_index, 0)?)
                })?;
                Ok(None)
            }
            PreExecutionBudgetMutation::Admission(admission) => self
                .reverse_ordinary_protocol_admission(cap, admission.as_ref())
                .map(Some),
            PreExecutionBudgetMutation::None => Ok(None),
        }
    }
}

include!("validation_finalize_and_payment.inc");
