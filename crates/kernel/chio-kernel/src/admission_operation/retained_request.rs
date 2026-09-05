//! Original request material, not a collection or execution authorization token.

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::ToolGrant;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

use super::{AdmissionDigest, AdmissionOperationBindingV1, AdmissionOperationStoreError};
use crate::kernel::MatchingGrant;
use crate::tool_outcome::FrozenEvaluationStepV1;
use crate::ToolCallRequest;

const SCHEMA: &str = "chio.retained-tool-admission-request.v1";
const MAX_BYTES: usize = 262_144;

/// Bounded original capability and immutable request material retained by the
/// admission store. Construction and decoding check structure, not authority.
/// Only a fenced store read can establish provenance; current capability,
/// revocation, policy, submitter and request checks remain mandatory.
///
/// One-shot credentials and approval artifacts are deliberately not retained.
/// This record must not be exposed on a public receipt or collector response.
#[derive(Clone)]
pub struct RetainedToolAdmissionRequestV1 {
    wire: RetainedRequestWire,
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
    request: ToolCallRequest,
    matching_grant_indices: Vec<usize>,
    post_return_steps: Vec<FrozenEvaluationStepV1>,
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
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
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
    };
    let bytes = canonical_json_bytes(&immutable).map_err(invalid)?;
    AdmissionDigest::try_new("immutable_request_hash", sha256_hex(&bytes)).map_err(Into::into)
}

impl RetainedToolAdmissionRequestV1 {
    pub(crate) fn from_admission(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
    ) -> Result<Self, AdmissionOperationStoreError> {
        // Explicit construction makes additions to ToolCallRequest require a
        // retention decision. Do not clone credentials and then redact them.
        let request = ToolCallRequest {
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
        };
        let wire = RetainedRequestWire {
            schema: SCHEMA.to_owned(),
            request,
            matching_grant_indices: matching_grants.iter().map(|grant| grant.index).collect(),
            post_return_steps: post_return_steps.to_vec(),
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
        let wire: RetainedRequestWire = serde_json::from_slice(bytes).map_err(invalid)?;
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
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        if canonical != bytes {
            return Err(invalid(
                "retained request is not exact typed canonical JSON",
            ));
        }
        let retained = Self { wire, canonical };
        retained.matching_grants()?;
        Ok(retained)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Request data for fresh authority validation, never a dispatch permit.
    /// One-shot credentials must be supplied and verified afresh at execution.
    #[must_use]
    pub fn request_for_revalidation(&self) -> &ToolCallRequest {
        &self.wire.request
    }

    pub fn validate_binding(
        &self,
        binding: &AdmissionOperationBindingV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let request = &self.wire.request;
        let capability_hash =
            sha256_hex(&canonical_json_bytes(&request.capability).map_err(invalid)?);
        let action_hash = sha256_hex(&canonical_json_bytes(&request.arguments).map_err(invalid)?);
        let request_hash = immutable_tool_request_hash(
            request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
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
