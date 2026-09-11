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
use crate::tool_outcome::FrozenEvaluationStepV1;
use crate::ToolCallRequest;

const SCHEMA: &str = "chio.retained-tool-admission-request.v1";
const SECURITY_SCHEMA: &str = "chio.retained-tool-admission-request.v2";
const NATIVE_SECURITY_SCHEMA: &str = "chio.retained-tool-admission-request.v3";
const AUTHORITY_PROFILE_SCHEMA: &str = "chio.retained-tool-admission-request.v4";
const MAX_BYTES: usize = 262_144;

mod security_binding;
pub(crate) use security_binding::AdmissionSecurityBindingV1;

/// Bounded original capability and immutable request material retained by the
/// admission store. Construction and decoding check structure, not authority.
/// Only a fenced store read can establish provenance; current capability,
/// revocation, policy, submitter and request checks remain mandatory.
///
/// One-shot credentials and approval artifacts are deliberately not retained.
/// This record must not be exposed on a public receipt or collector response.
/// The API accepts unbound v1, identity-bound v2 and native-authority-bound v3
/// artifacts, plus explicit original authority profiles in v4. No stored
/// version establishes a current trusted host context or claim authority.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    security_binding: Option<AdmissionSecurityBindingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_profile: Option<AdmissionAuthorityProfileV1>,
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
    security_binding: Option<&AdmissionSecurityBindingV1>,
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
    let mut bytes = canonical_json_bytes(&immutable).map_err(invalid)?;
    if let Some(security_binding) = security_binding {
        security_binding.validate()?;
        #[derive(Serialize)]
        struct SecurityBoundRequest<'a> {
            schema: &'static str,
            unbound_request_hash: String,
            security_binding: &'a AdmissionSecurityBindingV1,
        }
        bytes = canonical_json_bytes(&SecurityBoundRequest {
            schema: if security_binding.native_authority().is_some() {
                "chio.tool-admission-request.v3"
            } else {
                "chio.tool-admission-request.v2"
            },
            unbound_request_hash: sha256_hex(&bytes),
            security_binding,
        })
        .map_err(invalid)?;
    }
    AdmissionDigest::try_new("immutable_request_hash", sha256_hex(&bytes)).map_err(Into::into)
}

pub(crate) fn immutable_tool_request_hash_with_profile(
    request: &ToolCallRequest,
    matching_grants: &[MatchingGrant<'_>],
    post_return_steps: &[FrozenEvaluationStepV1],
    security_binding: Option<&AdmissionSecurityBindingV1>,
    authority_profile: Option<&AdmissionAuthorityProfileV1>,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let prior_request_hash = immutable_tool_request_hash(
        request,
        matching_grants,
        post_return_steps,
        security_binding,
    )?;
    let Some(authority_profile) = authority_profile else {
        return Ok(prior_request_hash);
    };
    #[derive(Serialize)]
    struct ProfileBoundRequest<'a> {
        schema: &'static str,
        prior_request_hash: &'a AdmissionDigest,
        authority_profile: &'a AdmissionAuthorityProfileV1,
    }
    let bytes = canonical_json_bytes(&ProfileBoundRequest {
        schema: "chio.tool-admission-request.v4",
        prior_request_hash: &prior_request_hash,
        authority_profile,
    })
    .map_err(invalid)?;
    AdmissionDigest::try_new("immutable_request_hash", sha256_hex(&bytes)).map_err(Into::into)
}

impl RetainedToolAdmissionRequestV1 {
    fn request_without_transient_credentials(request: &ToolCallRequest) -> ToolCallRequest {
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
    /// Ordinary dispatch does not inherit the stored artifact's size limit.
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

    #[cfg(test)]
    pub(crate) fn from_admission(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Self::from_admission_with_profile(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            None,
        )
    }

    pub(crate) fn from_admission_with_profile(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let request = Self::request_without_transient_credentials(request);
        let wire = RetainedRequestWire {
            schema: Self::schema(security_binding, authority_profile).to_owned(),
            request,
            matching_grant_indices: matching_grants.iter().map(|grant| grant.index).collect(),
            post_return_steps: post_return_steps.to_vec(),
            security_binding: security_binding.cloned(),
            authority_profile: authority_profile.cloned(),
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
        let expected_schema = Self::schema(
            wire.security_binding.as_ref(),
            wire.authority_profile.as_ref(),
        );
        if wire.schema != expected_schema
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
        if let Some(binding) = wire.security_binding.as_ref() {
            binding.validate()?;
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

    /// Historical binding from retained bytes, not a current host context.
    pub(crate) fn security_binding(&self) -> Option<&AdmissionSecurityBindingV1> {
        self.wire.security_binding.as_ref()
    }

    fn schema(
        binding: Option<&AdmissionSecurityBindingV1>,
        profile: Option<&AdmissionAuthorityProfileV1>,
    ) -> &'static str {
        if profile.is_some() {
            return AUTHORITY_PROFILE_SCHEMA;
        }
        match binding {
            Some(binding) if binding.native_authority().is_some() => NATIVE_SECURITY_SCHEMA,
            Some(_) => SECURITY_SCHEMA,
            None => SCHEMA,
        }
    }

    /// Original configured selections only, not activation or mutable policy.
    #[must_use]
    pub fn authority_profile(&self) -> Option<&AdmissionAuthorityProfileV1> {
        self.wire.authority_profile.as_ref()
    }

    /// Historical authority selection only. It cannot authorize a new write.
    #[must_use]
    pub fn native_security_authority_binding(&self) -> Option<&NativeSecurityAuthorityBindingV1> {
        self.security_binding()
            .and_then(AdmissionSecurityBindingV1::native_authority)
    }

    /// Require exact original selection before a native mutation. Legacy
    /// records without a selection remain readable, but cannot acquire one.
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
        let candidate = Self::from_admission_with_profile(
            request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
            self.wire.security_binding.as_ref(),
            self.wire.authority_profile.as_ref(),
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
            self.wire.authority_profile.as_ref(),
        )
    }

    pub(crate) fn validate_request_binding(
        binding: &AdmissionOperationBindingV1,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let capability_hash =
            sha256_hex(&canonical_json_bytes(&request.capability).map_err(invalid)?);
        let action_hash = sha256_hex(&canonical_json_bytes(&request.arguments).map_err(invalid)?);
        let request_hash = immutable_tool_request_hash_with_profile(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
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
