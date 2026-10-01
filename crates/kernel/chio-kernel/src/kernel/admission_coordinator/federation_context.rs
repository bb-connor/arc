//! Private federation context for the already admitted invocation.
//!
//! Only the qualified outcome read can establish retained provenance. Canonical
//! decoding and re-verifying signatures are not independent admission authority.

use super::*;
use crate::admission_operation::{AdmissionOperationId, RetainedToolAdmissionRequestV1};
use crate::kernel::verified_treaty::TreatyVerificationEvidence;
use serde::Deserialize;

const SCHEMA: &str = "chio.frozen-federation-admission.v1";
const MAX_BYTES: usize = crate::tool_outcome::MAX_EVIDENCE_ARTIFACT_BYTES;

pub(super) struct FrozenFederationContext {
    canonical: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FederationWire {
    schema: String,
    operation_id: AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    request_material_digest: AdmissionDigest,
    admitted_at_unix_ms: u64,
    local_kernel_id: String,
    local_public_key: chio_core::PublicKey,
    peer: chio_federation::trust_establishment::FederationPeer,
    treaty_evidence: TreatyVerificationEvidence,
}

impl FrozenFederationContext {
    pub(super) fn canonical_json(&self) -> &str {
        &self.canonical
    }
}

impl ChioKernel {
    /// Decode only after a qualified caller-context read (or the local freeze).
    /// Signature validation alone never establishes durable provenance.
    pub(super) fn restore_frozen_federation_return_context(
        &self,
        canonical: String,
        operation: &AdmissionOperationV1,
        request: &ToolCallRequest,
        observed_at_unix_ms: u64,
    ) -> Result<FrozenFederationContext, KernelError> {
        self.decode_retained_federation_context(
            canonical.as_bytes(),
            operation,
            request,
            observed_at_unix_ms,
        )?;
        Ok(FrozenFederationContext { canonical })
    }

    pub(super) fn freeze_federation_return_context(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        admitted_at_unix_ms: u64,
    ) -> Result<Option<FrozenFederationContext>, KernelError> {
        let Some(remote) = request.federated_origin_kernel_id.as_deref() else {
            return Ok(None);
        };
        let snapshot = self
            .receipt_federation_admission_for_request(&request.request_id, Some(remote))
            .ok_or_else(|| invalid("admitted federation snapshot is missing"))?;
        let peer = snapshot
            .peer
            .ok_or_else(|| invalid("admitted federation peer is missing"))?;
        let material = snapshot
            .verified_treaty_material
            .ok_or_else(|| invalid("verified federation treaty is missing before dispatch"))?;
        let local_kernel_id = self.federation_local_kernel_id();
        let local_public_key = self.config.keypair.public_key();
        material.validate_cosign_participants(
            remote,
            &peer.public_key,
            &local_kernel_id,
            &local_public_key,
        )?;
        let wire = FederationWire {
            schema: SCHEMA.into(),
            operation_id: admission.operation.binding().operation_id().clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            request_material_digest: RetainedToolAdmissionRequestV1::request_material_digest(
                request,
            )
            .map_err(durable_store_error)?,
            admitted_at_unix_ms,
            local_kernel_id,
            local_public_key,
            peer,
            treaty_evidence: material.verification_evidence,
        };
        let bytes = canonical_json_bytes(&wire).map_err(|error| invalid(&error.to_string()))?;
        // Exercise the same binding and signature checks before the effect.
        self.decode_retained_federation_context(
            &bytes,
            &admission.operation,
            request,
            admitted_at_unix_ms,
        )?;
        let canonical = String::from_utf8(bytes).map_err(|error| invalid(&error.to_string()))?;
        Ok(Some(FrozenFederationContext { canonical }))
    }

    /// Establish the outcome's content-address binding before reading any
    /// authority-bearing snapshot. Callers obtain these records only through
    /// the configured qualified outcome authority, never from report DTOs.
    pub(super) fn scope_retained_federation_return(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
    ) -> Result<Option<ScopedKernelReceiptFederationAdmission>, KernelError> {
        let Some(bytes) = raw.federation_context_json() else {
            // Legacy outcomes have no invented snapshot. Their existing
            // in-flight scope may still be used, but no history is synthesized.
            return Ok(None);
        };
        let blob = raw.canonical_blob().map_err(tool_outcome_error)?;
        outcome
            .validate_canonical_blob(&admission.operation, &blob)
            .map_err(tool_outcome_error)?;
        let snapshot = self.decode_retained_federation_context(
            bytes.as_bytes(),
            &admission.operation,
            request,
            outcome.recorded_at_unix_ms(),
        )?;
        Ok(Some(self.scope_receipt_federation_admission_for_request(
            &request.request_id,
            snapshot,
        )))
    }

    fn decode_retained_federation_context(
        &self,
        bytes: &[u8],
        operation: &AdmissionOperationV1,
        request: &ToolCallRequest,
        observed_at_unix_ms: u64,
    ) -> Result<ReceiptFederationAdmission, KernelError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid("retained federation context exceeds its bound"));
        }
        let wire: FederationWire =
            serde_json::from_slice(bytes).map_err(|error| invalid(&error.to_string()))?;
        if canonical_json_bytes(&wire).map_err(|error| invalid(&error.to_string()))? != bytes {
            return Err(invalid(
                "retained federation context is not exact typed canonical JSON",
            ));
        }
        if wire.schema != SCHEMA
            || &wire.operation_id != operation.binding().operation_id()
            || &wire.request_binding_hash != operation.binding().request_binding_hash()
            || wire.request_material_digest
                != RetainedToolAdmissionRequestV1::request_material_digest(request)
                    .map_err(durable_store_error)?
            || wire.admitted_at_unix_ms == 0
            || wire.admitted_at_unix_ms > I_JSON_MAX_SAFE_INTEGER
            || wire.admitted_at_unix_ms > observed_at_unix_ms
            || request.federated_origin_kernel_id.as_deref() != Some(wire.peer.kernel_id.as_str())
            || wire.local_kernel_id != self.federation_local_kernel_id()
            || wire.local_public_key != self.config.keypair.public_key()
            || !wire.peer.is_fresh(wire.admitted_at_unix_ms / 1_000)
            || wire.peer.established_at > wire.admitted_at_unix_ms / 1_000
        {
            return Err(invalid(
                "retained federation context does not match its admission",
            ));
        }
        let material = wire.treaty_evidence.reverify(
            request,
            [&wire.peer.kernel_id, &wire.local_kernel_id],
            [&wire.peer.public_key, &wire.local_public_key],
            wire.admitted_at_unix_ms,
        )?;
        Ok(ReceiptFederationAdmission {
            remote_kernel_id: Some(wire.peer.kernel_id.clone()),
            peer: Some(wire.peer),
            verified_treaty_material: Some(material),
        })
    }
}

fn invalid(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.to_owned())
}
