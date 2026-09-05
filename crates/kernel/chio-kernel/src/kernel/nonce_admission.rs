//! Kernel nonce configuration, validation and replay-store mediation.

use super::*;

impl ChioKernel {
    /// Install an execution-nonce config and replay store.
    ///
    /// Once installed, every `Verdict::Allow` carries a short-lived signed
    /// nonce on `ToolCallResponse::execution_nonce`. Tool servers re-present
    /// that nonce via `ToolCallRequest::execution_nonce` and the kernel's
    /// `verify_presented_execution_nonce` helper (or directly via the
    /// free-standing `verify_execution_nonce` function) before executing.
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
    ) {
        self.execution_nonce_config = Some(config);
        self.execution_nonce_store = Some(store);
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

    pub(crate) fn mint_execution_nonce_for_allow_reserving(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        receipt: &ChioReceipt,
        reserved_hold_id: Option<&str>,
    ) -> Result<Option<Box<crate::execution_nonce::SignedExecutionNonce>>, KernelError> {
        if request.execution_nonce.is_some() {
            return Ok(None);
        }
        let Some(config) = self.execution_nonce_config.as_ref() else {
            return Ok(None);
        };
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        let binding = crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            request_id: request.request_id.clone(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        };
        let reserving_request_id = reserved_hold_id.map(|_| request.request_id.clone());
        let signed = crate::execution_nonce::mint_execution_nonce_with_reservation(
            &self.config.keypair,
            binding,
            reserved_hold_id.map(str::to_string),
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
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        crate::execution_nonce::verify_execution_nonce(
            presented,
            &self.config.keypair.public_key(),
            expected,
            now,
            store,
        )
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
        self.reserve_presented_execution_nonce(request, cap)
    }

    pub(crate) fn validate_required_execution_nonce(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        self.validate_execution_nonce_non_consuming(request, cap, current_unix_timestamp())
            .map(|_| ())
    }

    pub(crate) fn reserve_presented_execution_nonce(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let Some(validated) =
            self.validate_execution_nonce_non_consuming(request, cap, current_unix_timestamp())?
        else {
            return Ok(());
        };
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal("execution nonce store is not installed".to_string())
        })?;
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        crate::execution_nonce::reserve_execution_nonce(&validated, store, now)
            .map_err(|e| KernelError::Internal(format!("{e}")))
    }

    /// Strict-mode nonce issuance gate.
    ///
    /// In strict mode, a request that reaches evaluation without a presented
    /// nonce is an authorization preflight. It may receive a freshly signed
    /// nonce, but it must not execute the target tool. Actual execution
    /// presents that nonce on a later request and consumes it immediately
    /// before dispatch.
    #[must_use]
    pub(crate) fn execution_nonce_preflight_required(&self, request: &ToolCallRequest) -> bool {
        self.execution_nonce_required() && request.execution_nonce.is_none()
    }

    pub(crate) fn validate_execution_nonce_non_consuming<'a>(
        &self,
        request: &'a ToolCallRequest,
        cap: &CapabilityToken,
        now: u64,
    ) -> Result<Option<crate::execution_nonce::ValidatedExecutionNonce<'a>>, KernelError> {
        let presented = request.execution_nonce.as_ref();
        if !self.execution_nonce_required() && presented.is_none() {
            return Ok(None);
        }
        let presented = presented.ok_or_else(|| {
            KernelError::Internal(
                "execution nonce required but not presented on tool call".to_string(),
            )
        })?;
        let _store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal("execution nonce store is not installed".to_string())
        })?;
        let parameter_hash = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(|error| {
                KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {error}"))
            })?
            .parameter_hash;
        let expected = crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            request_id: request.request_id.clone(),
            parameter_hash,
        };
        crate::execution_nonce::validate_execution_nonce(
            presented,
            &self.config.keypair.public_key(),
            &expected,
            i64::try_from(now).unwrap_or(i64::MAX),
        )
        .map(Some)
        .map_err(|error| KernelError::Internal(error.to_string()))
    }
}
