//! Original request material, not a collection or execution authorization token.

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::ToolGrant;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

use super::{
    AdmissionAuthorityProfileV1, AdmissionDigest, AdmissionOperationBindingV1,
    AdmissionOperationStoreError, NativeSecurityAuthorityBindingV1,
};
use crate::kernel::MatchingGrant;
use crate::tool_outcome::{FrozenEvaluationStepV1, FrozenReceiptSigningIdentityV1};
use crate::ToolCallRequest;

/// Caller-supplied receipt metadata admitted with the original request.
pub type AdmittedReceiptMetadata = serde_json::Map<String, serde_json::Value>;

/// The admitted metadata entries that are evidence of the presenting attempt
/// rather than request identity: the native launch serving the call and the
/// worker container launch presenting it. They are excluded from the immutable
/// request hash and from replay equality; every other admitted field stays
/// bound.
pub const ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS: [&[&str]; 2] =
    [&["native_launch"], &["chio_process", "worker_profile"]];

fn attempt_scoped_entry<'a>(
    metadata: &'a AdmittedReceiptMetadata,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    let (last, parents) = path.split_last()?;
    let mut object = metadata;
    for parent in parents {
        object = object.get(*parent)?.as_object()?;
    }
    object.get(*last)
}

/// Admitted metadata without its attempt-scoped evidence.
fn identity_receipt_metadata(
    metadata: Option<&AdmittedReceiptMetadata>,
) -> Option<AdmittedReceiptMetadata> {
    let mut identity = metadata?.clone();
    for path in ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS {
        let Some((last, parents)) = path.split_last() else {
            continue;
        };
        let mut object = Some(&mut identity);
        for parent in parents {
            object = object
                .and_then(|object| object.get_mut(*parent))
                .and_then(serde_json::Value::as_object_mut);
        }
        if let Some(object) = object {
            object.remove(*last);
        }
    }
    (!identity.is_empty()).then_some(identity)
}

const SCHEMA: &str = "chio.retained-tool-admission-request.v1";
const MAX_BYTES: usize = 262_144;

mod security_binding;

#[cfg(test)]
mod tests;
pub(crate) use security_binding::AdmissionSecurityBindingV1;

/// Bounded original capability and immutable request material retained by the
/// admission store. Construction and decoding check structure, not authority.
/// Only a fenced store read can establish provenance; current capability,
/// revocation, policy, submitter and request checks remain mandatory.
///
/// One-shot credentials and approval artifacts are deliberately not retained.
/// This record must not be exposed on a public receipt or collector response.
/// The current format requires explicit original authority selections. Retained
/// data establishes neither a current trusted host context nor claim authority.
#[derive(Clone)]
pub struct RetainedToolAdmissionRequestV1 {
    // Heap ownership bounds stack use during custody validation.
    wire: Box<RetainedRequestWire>,
    canonical: Vec<u8>,
}

impl std::fmt::Debug for RetainedToolAdmissionRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedToolAdmissionRequestV1")
            .field("encoded_bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedRequestWire {
    schema: String,
    request: Box<ToolCallRequest>,
    matching_grant_indices: Vec<usize>,
    post_return_steps: Vec<FrozenEvaluationStepV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    security_binding: Option<AdmissionSecurityBindingV1>,
    authority_profile: AdmissionAuthorityProfileV1,
    frozen_receipt_signing_identity: FrozenReceiptSigningIdentityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admitted_receipt_metadata: Option<AdmittedReceiptMetadata>,
}

#[derive(Serialize)]
struct ImmutableToolAdmissionRequest<'a> {
    schema: &'static str,
    server_id: &'a str,
    tool_name: &'a str,
    agent_id: &'a str,
    arguments: &'a serde_json::Value,
    governed_intent: &'a Option<chio_core::capability::governance::GovernedTransactionIntent>,
    model_metadata: &'a Option<chio_core::capability::scope::ModelMetadata>,
    federated_origin_kernel_id: &'a Option<String>,
    matching_grants: Vec<ImmutableMatchingGrant<'a>>,
    post_return_steps: &'a [FrozenEvaluationStepV1],
    security_binding: Option<&'a AdmissionSecurityBindingV1>,
    authority_profile: &'a AdmissionAuthorityProfileV1,
    frozen_receipt_signing_identity: &'a FrozenReceiptSigningIdentityV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    admitted_receipt_metadata: Option<&'a AdmittedReceiptMetadata>,
}

#[derive(Serialize)]
struct ImmutableMatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
}

pub(crate) fn immutable_tool_request_hash(
    request: &ToolCallRequest,
    matching_grants: &[MatchingGrant<'_>],
    post_return_steps: &[FrozenEvaluationStepV1],
    security_binding: Option<&AdmissionSecurityBindingV1>,
    authority_profile: &AdmissionAuthorityProfileV1,
    frozen_receipt_signing_identity: &FrozenReceiptSigningIdentityV1,
    admitted_receipt_metadata: Option<&AdmittedReceiptMetadata>,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    if admitted_receipt_metadata.is_some_and(serde_json::Map::is_empty) {
        return Err(invalid("admitted receipt metadata must not be empty"));
    }
    if let Some(security_binding) = security_binding {
        security_binding.validate()?;
    }
    frozen_receipt_signing_identity
        .validate()
        .map_err(|_| invalid("retained request receipt signing identity is invalid"))?;
    let identity_metadata = identity_receipt_metadata(admitted_receipt_metadata);
    let immutable = ImmutableToolAdmissionRequest {
        schema: "chio.tool-admission-request.v1",
        server_id: &request.server_id,
        tool_name: &request.tool_name,
        agent_id: &request.agent_id,
        arguments: &request.arguments,
        governed_intent: &request.governed_intent,
        model_metadata: &request.model_metadata,
        federated_origin_kernel_id: &request.federated_origin_kernel_id,
        matching_grants: matching_grants
            .iter()
            .map(|matching| ImmutableMatchingGrant {
                index: matching.index,
                grant: matching.grant,
            })
            .collect(),
        post_return_steps,
        security_binding,
        authority_profile,
        frozen_receipt_signing_identity,
        admitted_receipt_metadata: identity_metadata.as_ref(),
    };
    let bytes = canonical_json_bytes(&immutable).map_err(invalid)?;
    AdmissionDigest::try_new("immutable_request_hash", sha256_hex(&bytes)).map_err(Into::into)
}

impl RetainedToolAdmissionRequestV1 {
    pub(crate) fn request_without_transient_credentials(
        request: &ToolCallRequest,
    ) -> ToolCallRequest {
        // Explicit construction makes additions to ToolCallRequest require a
        // retention decision. Do not clone credentials and then redact them.
        ToolCallRequest {
            request_id: request.request_id.clone(),
            capability: request.capability.clone(),
            tool_name: request.tool_name.clone(),
            server_id: request.server_id.clone(),
            agent_id: request.agent_id.clone(),
            arguments: request.arguments.clone(),
            governed_intent: request.governed_intent.clone(),
            model_metadata: request.model_metadata.clone(),
            federated_origin_kernel_id: request.federated_origin_kernel_id.clone(),
            dpop_proof: None,
            execution_nonce: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            declassification_grant: None,
        }
    }

    /// In-memory equality binding, not a retained artifact or authorization.
    pub(crate) fn request_material_digest(
        request: &ToolCallRequest,
    ) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        #[derive(Serialize)]
        struct RequestMaterial {
            schema: &'static str,
            request: ToolCallRequest,
        }
        let material = RequestMaterial {
            schema: "chio.frozen-tool-request-material.v1",
            request: Self::request_without_transient_credentials(request),
        };
        let canonical = canonical_json_bytes(&material).map_err(invalid)?;
        AdmissionDigest::try_new("request_material_digest", sha256_hex(&canonical))
            .map_err(Into::into)
    }

    pub(crate) fn from_admission(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: &AdmissionAuthorityProfileV1,
        frozen_receipt_signing_identity: &FrozenReceiptSigningIdentityV1,
        admitted_receipt_metadata: Option<&AdmittedReceiptMetadata>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let request = Self::request_without_transient_credentials(request);
        let wire = RetainedRequestWire {
            schema: SCHEMA.to_owned(),
            request: Box::new(request),
            matching_grant_indices: matching_grants.iter().map(|grant| grant.index).collect(),
            post_return_steps: post_return_steps.to_vec(),
            security_binding: security_binding.cloned(),
            authority_profile: authority_profile.clone(),
            frozen_receipt_signing_identity: frozen_receipt_signing_identity.clone(),
            admitted_receipt_metadata: admitted_receipt_metadata.cloned(),
        };
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        Self::from_canonical_bytes(&canonical)
    }

    /// Decode untrusted stored bytes without granting provenance or authority.
    /// Exact typed canonical re-encoding also rejects ignored nested fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdmissionOperationStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid("retained request exceeds its artifact bound"));
        }
        let wire: Box<RetainedRequestWire> =
            chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_BYTES)?
                .decode_canonical()?;
        let request = &wire.request;
        if wire.schema != SCHEMA
            || request.dpop_proof.is_some()
            || request.execution_nonce.is_some()
            || request.approval_token.is_some()
            || !request.approval_tokens.is_empty()
            || request.threshold_approval_proposal.is_some()
            || request.supplemental_authorization.is_some()
            || request.declassification_grant.is_some()
        {
            return Err(invalid(
                "retained request contains unsupported authority material",
            ));
        }
        wire.frozen_receipt_signing_identity
            .validate()
            .map_err(|_| invalid("retained request receipt signing identity is invalid"))?;
        if wire
            .admitted_receipt_metadata
            .as_ref()
            .is_some_and(serde_json::Map::is_empty)
        {
            return Err(invalid("admitted receipt metadata must not be empty"));
        }
        if let Some(binding) = wire.security_binding.as_ref() {
            binding.validate()?;
        }
        let retained = Self {
            wire,
            canonical: bytes.to_vec(),
        };
        retained.matching_grants()?;
        Ok(retained)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Whether `candidate` re-presents this admission. Equality covers every
    /// retained field; attempt-scoped launch evidence may differ, but evidence
    /// retained at admission must be presented again.
    pub fn matches_replay(&self, candidate: &Self) -> Result<bool, AdmissionOperationStoreError> {
        if self.canonical == candidate.canonical {
            return Ok(true);
        }
        let presented = |request: &Self, path: &[&str]| {
            request
                .wire
                .admitted_receipt_metadata
                .as_ref()
                .and_then(|metadata| attempt_scoped_entry(metadata, path))
                .is_some()
        };
        if ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS
            .iter()
            .any(|path| presented(self, path) != presented(candidate, path))
        {
            return Ok(false);
        }
        Ok(self.identity_bytes()? == candidate.identity_bytes()?)
    }

    fn identity_bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let mut identity = (*self.wire).clone();
        identity.admitted_receipt_metadata =
            identity_receipt_metadata(self.wire.admitted_receipt_metadata.as_ref());
        canonical_json_bytes(&identity).map_err(invalid)
    }

    /// Historical binding from retained bytes, not a current host context.
    pub(crate) fn security_binding(&self) -> Option<&AdmissionSecurityBindingV1> {
        self.wire.security_binding.as_ref()
    }

    /// Original configured selections only, not activation or mutable policy.
    #[must_use]
    pub fn authority_profile(&self) -> &AdmissionAuthorityProfileV1 {
        &self.wire.authority_profile
    }

    pub(crate) fn frozen_receipt_signing_identity(&self) -> &FrozenReceiptSigningIdentityV1 {
        &self.wire.frozen_receipt_signing_identity
    }

    /// Post-return evaluation steps frozen at admission.
    pub(crate) fn post_return_steps(&self) -> &[FrozenEvaluationStepV1] {
        &self.wire.post_return_steps
    }

    /// Caller receipt metadata bound into the original admission. Every
    /// canonical refusal signed for this operation carries it unchanged.
    #[must_use]
    pub fn admitted_receipt_metadata(&self) -> Option<&AdmittedReceiptMetadata> {
        self.wire.admitted_receipt_metadata.as_ref()
    }

    /// Historical authority selection only. It cannot authorize a new write.
    #[must_use]
    pub fn native_security_authority_binding(&self) -> Option<&NativeSecurityAuthorityBindingV1> {
        self.security_binding()
            .and_then(AdmissionSecurityBindingV1::native_authority)
    }

    /// Require the exact original native selection before a mutation.
    pub fn validate_native_security_authority(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.native_security_authority_binding() != Some(binding) {
            return Err(invalid(
                "native authority differs from original admission selection",
            ));
        }
        Ok(())
    }

    /// Compare trusted host context with the original stable admission identity.
    /// This authenticates no caller and grants no execution authority. Native
    /// participant stores must also check the retained request's operation
    /// binding and the actual current recovery lease in their transaction.
    pub fn validate_native_security_context(
        &self,
        context: &crate::SecurityInvocationContext,
    ) -> Result<(), AdmissionOperationStoreError> {
        let expected = AdmissionSecurityBindingV1::from_trusted_selection(
            Some(context),
            true,
            true,
            self.native_security_authority_binding().cloned(),
        )?;
        self.validate_security_binding(expected.as_ref())
    }

    /// Request data for fresh authority validation, never a dispatch permit.
    /// One-shot credentials must be supplied and verified afresh at execution.
    #[must_use]
    pub fn request_for_revalidation(&self) -> &ToolCallRequest {
        &self.wire.request
    }

    /// Retained matching-grant data, not current grant authorization.
    #[must_use]
    pub fn retained_matching_grant(&self, index: usize) -> Option<&ToolGrant> {
        self.wire
            .matching_grant_indices
            .contains(&index)
            .then(|| self.wire.request.capability.scope.grants.get(index))
            .flatten()
    }

    /// Original aggregate credential requirement. Selecting another matching
    /// grant must not downgrade a proof required by any original match.
    #[must_use]
    pub fn matching_grants_require_dpop(&self) -> bool {
        self.wire.matching_grant_indices.iter().any(|index| {
            self.retained_matching_grant(*index)
                .is_some_and(|grant| grant.dpop_required == Some(true))
        })
    }

    /// Check immutable request equality using the original grant selection and
    /// post-return plan. Transient credentials are intentionally not replayed or
    /// compared here. This is a binding check, not fresh execution authority.
    pub fn validate_request_material(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), AdmissionOperationStoreError> {
        let candidate = Self::from_admission(
            request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
            self.wire.security_binding.as_ref(),
            &self.wire.authority_profile,
            &self.wire.frozen_receipt_signing_identity,
            self.wire.admitted_receipt_metadata.as_ref(),
        )?;
        if candidate.canonical != self.canonical {
            return Err(invalid(
                "request differs from its retained admission material",
            ));
        }
        Ok(())
    }

    /// Equality against freshly resolved trusted identity/configuration. The
    /// retained value alone cannot supply authority to a new invocation.
    pub(crate) fn validate_security_binding(
        &self,
        binding: Option<&AdmissionSecurityBindingV1>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.wire.security_binding.as_ref() != binding {
            return Err(invalid(
                "security identity or requirements differ from admission",
            ));
        }
        Ok(())
    }

    pub fn validate_binding(
        &self,
        binding: &AdmissionOperationBindingV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        Self::validate_request_binding(
            binding,
            &self.wire.request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
            self.wire.security_binding.as_ref(),
            &self.wire.authority_profile,
            &self.wire.frozen_receipt_signing_identity,
            self.wire.admitted_receipt_metadata.as_ref(),
        )
    }

    pub(crate) fn validate_request_binding(
        binding: &AdmissionOperationBindingV1,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: &AdmissionAuthorityProfileV1,
        frozen_receipt_signing_identity: &FrozenReceiptSigningIdentityV1,
        admitted_receipt_metadata: Option<&AdmittedReceiptMetadata>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let capability_hash =
            sha256_hex(&canonical_json_bytes(&request.capability).map_err(invalid)?);
        let action_hash = sha256_hex(&canonical_json_bytes(&request.arguments).map_err(invalid)?);
        let request_hash = immutable_tool_request_hash(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
            frozen_receipt_signing_identity,
            admitted_receipt_metadata,
        )?;
        if binding.kind() != super::AdmissionOperationKind::ToolDispatch
            || binding.request_id().as_str() != request.request_id
            || binding.capability_id().as_str() != request.capability.id
            || binding.authorization_capability_hash.as_str() != capability_hash
            || binding.action_parameter_hash().as_str() != action_hash
            || binding.immutable_request_hash() != &request_hash
        {
            return Err(invalid(
                "retained request does not match its admission binding",
            ));
        }
        Ok(())
    }

    fn matching_grants(&self) -> Result<Vec<MatchingGrant<'_>>, AdmissionOperationStoreError> {
        let indices = &self.wire.matching_grant_indices;
        if indices.is_empty() {
            return Err(invalid("retained request has no matching grants"));
        }
        let mut seen = std::collections::HashSet::with_capacity(indices.len());
        indices
            .iter()
            .map(|index| {
                if !seen.insert(*index) {
                    return Err(invalid("retained request repeats a matching grant"));
                }
                let grant = self
                    .wire
                    .request
                    .capability
                    .scope
                    .grants
                    .get(*index)
                    .ok_or_else(|| invalid("retained request grant index is out of bounds"))?;
                Ok(MatchingGrant {
                    index: *index,
                    grant,
                    specificity: (0, 0, 0),
                })
            })
            .collect()
    }
}

fn invalid(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.to_string())
}
