//! Bounded storage framing for the kernel's frozen caller-dispatch context.
//!
//! Decoding proves canonical framing and operation binding, not kernel-context
//! semantics or provenance. The owning kernel must validate its payload schema;
//! a fenced, commit-bound authority read must establish storage provenance.

use super::*;

const SCHEMA: &str = "chio.admission-caller-dispatch-context.v1";
const MAX_BYTES: usize = 1024 * 1024;

/// Immutable storage material, never an external execution permit. The private
/// payload is returned only to the owning kernel's context decoder. It must not
/// be copied into public receipts or treated as authority after deserialization.
#[derive(Clone)]
pub struct AdmissionCallerDispatchContextV1 {
    wire: ContextWire,
    canonical: Vec<u8>,
    digest: AdmissionDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextWire {
    schema: String,
    operation_id: AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    capture_pending_operation_version: u64,
    provider_attempt: ProviderAttemptBindingV1,
    execution_nonce_id: AdmissionIdentifier,
    budget_hold_id: AdmissionIdentifier,
    retained_request_digest: AdmissionDigest,
    kernel_context_json: String,
}

impl std::fmt::Debug for AdmissionCallerDispatchContextV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionCallerDispatchContextV1")
            .field("encoded_bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}

impl AdmissionCallerDispatchContextV1 {
    pub(crate) const MAX_KERNEL_CONTEXT_BYTES: usize = MAX_BYTES / 2;

    /// Frame the kernel-produced canonical payload for one capture-pending caller.
    /// This validates binding and size only; it neither grants provenance nor
    /// changes the operation. Context, quota capture and dispatch must commit together.
    pub fn prepare(
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        kernel_context_json: &[u8],
    ) -> Result<Self, AdmissionOperationStoreError> {
        if operation.state() != AdmissionOperationState::CapturePending
            || operation.caller_dispatch_context_digest().is_some()
        {
            return Err(invalid(
                "caller context requires an unbound CapturePending operation",
            ));
        }
        validate_payload(kernel_context_json)?;
        let wire =
            ContextWire {
                schema: SCHEMA.into(),
                operation_id: operation.binding().operation_id().clone(),
                request_binding_hash: operation.binding().request_binding_hash().clone(),
                capture_pending_operation_version: operation.version(),
                provider_attempt: operation.provider_attempt().cloned().ok_or_else(|| {
                    invalid("caller context requires its retained provider attempt")
                })?,
                execution_nonce_id: operation.execution_nonce_id().cloned().ok_or_else(|| {
                    invalid("caller context requires its reserved execution nonce")
                })?,
                budget_hold_id: operation
                    .budget_hold_id()
                    .cloned()
                    .ok_or_else(|| invalid("caller context requires its executable budget hold"))?,
                retained_request_digest: request_digest(original)?,
                kernel_context_json: std::str::from_utf8(kernel_context_json)
                    .map_err(invalid)?
                    .to_owned(),
            };
        Self::from_canonical_bytes(
            &canonical_json_bytes(&wire).map_err(invalid)?,
            operation,
            original,
        )
    }

    /// Validate an untrusted frame against independently loaded operation and
    /// original request material. A matching frame is not an authority read.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid("caller context exceeds its artifact bound"));
        }
        operation.validate()?;
        original.validate_binding(operation.binding())?;
        let wire: ContextWire = serde_json::from_slice(bytes).map_err(invalid)?;
        let requirements = operation.binding().participant_requirements();
        if wire.schema != SCHEMA
            || !requirements.budget_capture
            || !requirements.execution_nonce
            || !requirements.broker_attempt
            || !wire.provider_attempt.is_caller_report()
            || wire.operation_id != *operation.binding().operation_id()
            || wire.request_binding_hash != *operation.binding().request_binding_hash()
            || Some(&wire.provider_attempt) != operation.provider_attempt()
            || Some(&wire.execution_nonce_id) != operation.execution_nonce_id()
            || Some(&wire.budget_hold_id) != operation.budget_hold_id()
            || wire.retained_request_digest != request_digest(original)?
            || wire.capture_pending_operation_version == 0
            || wire.capture_pending_operation_version > operation.version()
        {
            return Err(invalid(
                "caller context does not match its retained operation",
            ));
        }
        validate_payload(wire.kernel_context_json.as_bytes())?;
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        if canonical != bytes {
            return Err(invalid("caller context is not exact typed canonical JSON"));
        }
        let digest =
            AdmissionDigest::try_new("caller_dispatch_context_digest", sha256_hex(&canonical))?;
        match operation.caller_dispatch_context_digest() {
            Some(retained)
                if retained == &digest
                    && operation.version() > wire.capture_pending_operation_version => {}
            None if operation.state() == AdmissionOperationState::CapturePending
                && operation.version() == wire.capture_pending_operation_version => {}
            _ => {
                return Err(invalid(
                    "caller context lost its immutable operation attachment",
                ))
            }
        }
        Ok(Self {
            wire,
            canonical,
            digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &AdmissionDigest {
        &self.digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Canonical payload for the kernel's typed decoder, not verified authority.
    #[must_use]
    pub fn kernel_context_json(&self) -> &[u8] {
        self.wire.kernel_context_json.as_bytes()
    }

    #[must_use]
    pub fn capture_pending_operation_version(&self) -> u64 {
        self.wire.capture_pending_operation_version
    }
}

fn validate_payload(bytes: &[u8]) -> Result<(), AdmissionOperationStoreError> {
    if bytes.is_empty() || bytes.len() > AdmissionCallerDispatchContextV1::MAX_KERNEL_CONTEXT_BYTES
    {
        return Err(invalid("kernel caller context exceeds its payload bound"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(invalid)?;
    if !value.is_object() || canonical_json_bytes(&value).map_err(invalid)? != bytes {
        return Err(invalid(
            "kernel caller context must be a canonical JSON object",
        ));
    }
    Ok(())
}

fn request_digest(
    original: &RetainedToolAdmissionRequestV1,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    AdmissionDigest::try_new(
        "retained_request_digest",
        sha256_hex(original.canonical_bytes()),
    )
    .map_err(Into::into)
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}
