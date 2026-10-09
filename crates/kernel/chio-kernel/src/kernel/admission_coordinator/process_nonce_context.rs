//! Immutable original nonce evidence acquired from the actual Native owner.
//! No constructor accepts an operation id, issuer, decoded artifact or DATA.

use super::*;
use crate::admission_operation::{
    AdmissionExecutionNonceReservationV1, RetainedToolAdmissionRequestV1,
};
use crate::execution_nonce::SignedExecutionNonce;

/// Historical evidence from the installed qualified admission store. This
/// value owns no lock and grants no fresh admission, dispatch, loan or capture.
/// It cannot be constructed, cloned or deserialized by a Process caller.
pub struct OriginalProcessNonceContext {
    authority: String,
    operation: AdmissionOperationV1,
    original: RetainedToolAdmissionRequestV1,
    issuance: AdmissionExecutionNonceReservationV1,
    digest: String,
}

impl fmt::Debug for OriginalProcessNonceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalProcessNonceContext([redacted])")
    }
}

impl ChioKernel {
    /// Read immutable original evidence before entering the Process store.
    /// Request id is only a selector. The qualified owner authenticates the
    /// original binding, request and issuance; ambiguous namespaces refuse.
    /// No provider, policy, issuance or replay-consumption callback runs here.
    pub fn read_original_process_nonce_context(
        &self,
        request: &ToolCallRequest,
    ) -> Result<Option<OriginalProcessNonceContext>, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let selector = AdmissionIdentifier::try_new("request_id", request.request_id.clone())?;
        let Some((operation, original)) = runtime
            .store
            .load_unambiguous_retained_tool_request(&selector, &runtime.fence, now)
            .map_err(durable_store_error)?
        else {
            return Ok(None);
        };
        original
            .validate_binding(operation.binding())
            .map_err(durable_store_error)?;
        original
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        if operation.binding().coordinator_authority_id().as_str() != runtime.fence.store_uuid {
            return Err(nonce_context_error(
                "original nonce belongs to another authority",
            ));
        }
        // Do not use the coordinator helper's absent-attachment shortcut: the
        // actual owner must detect orphaned, missing and corrupt issuance rows.
        let issuance = runtime
            .store
            .load_execution_nonce_issuance(operation.binding().operation_id(), &runtime.fence, now)
            .map_err(durable_store_error)?;
        let Some(issuance) = issuance else {
            if operation.execution_nonce_issuance_digest().is_some() {
                return Err(nonce_context_error("original nonce issuance disappeared"));
            }
            return Ok(None);
        };
        issuance
            .require_operation_bound_profile()
            .map_err(durable_store_error)?;
        if operation
            .execution_nonce_issuance_digest()
            .map(AdmissionDigest::as_str)
            != Some(sha256_hex(issuance.canonical_bytes()).as_str())
        {
            return Err(nonce_context_error(
                "original nonce read changed immutable issuance",
            ));
        }
        // Both owner reads authenticate immutable attachments. Comparing their
        // exact digest joins them without claiming a current Native state cut.
        // Historical signer/time validation belongs to the issuance reader's
        // original commit, never to today's key or the nonce's claimed time.
        let digest = sha256_hex(
            &canonical_json_bytes(&(
                "chio.original-process-nonce-context.v1",
                &runtime.fence.store_uuid,
                operation.binding().to_persisted(),
                sha256_hex(original.canonical_bytes()),
                sha256_hex(issuance.canonical_bytes()),
            ))
            .map_err(|error| nonce_context_error(&error.to_string()))?,
        );
        if request
            .execution_nonce
            .as_ref()
            .is_some_and(|nonce| nonce != issuance.signed_nonce())
        {
            return Err(nonce_context_error(
                "presented nonce differs from original Native issuance",
            ));
        }
        Ok(Some(OriginalProcessNonceContext {
            authority: runtime.fence.store_uuid.clone(),
            operation,
            original,
            issuance,
            digest,
        }))
    }
}

impl OriginalProcessNonceContext {
    /// Pure equality/rebinding of already authenticated history. Safe inside
    /// the Process transaction: no owner handle, lock, clock or callback lives
    /// in this capsule. Fresh authorization remains a separate Native check.
    pub fn verify_retained_nonce(
        &self,
        authority: &str,
        request: &ToolCallRequest,
        nonce: &SignedExecutionNonce,
    ) -> Result<(), KernelError> {
        if authority != self.authority
            || self.operation.binding().request_id().as_str() != request.request_id
            || self.issuance.signed_nonce() != nonce
            || request
                .execution_nonce
                .as_ref()
                .is_some_and(|presented| presented != nonce)
        {
            return Err(nonce_context_error(
                "Process nonce differs from original Native issuance",
            ));
        }
        self.original
            .validate_request_material(request)
            .map_err(durable_store_error)
    }

    /// Compare stable historical context only. Mutable flow observations are
    /// still DATA and must be refreshed by Native before any new effect.
    pub fn verify_security_context(
        &self,
        context: Option<&SecurityInvocationContext>,
    ) -> Result<(), KernelError> {
        match self.original.security_binding() {
            Some(binding) => binding
                .validate_historical_context(context)
                .map_err(durable_store_error),
            None if context.is_none() => Ok(()),
            None => Err(nonce_context_error(
                "Process context differs from original Native context",
            )),
        }
    }

    /// Stable commitment to original binding/profile/issuer/issuance DATA.
    pub fn evidence_digest(&self) -> &str {
        &self.digest
    }
}

fn nonce_context_error(detail: &str) -> KernelError {
    KernelError::DurableAdmission(detail.to_owned())
}
