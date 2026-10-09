//! Original request material, not a collection or execution authorization token.

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::ToolGrant;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

use super::{
    AdmissionAuthorityProfileV1, AdmissionDigest, AdmissionOperationBindingV1,
    AdmissionOperationStoreError, NativeOutputRetentionProfileV1, NativeSecurityAuthorityBindingV1,
};
use crate::kernel::MatchingGrant;
use crate::tool_outcome::FrozenEvaluationStepV1;
use crate::ToolCallRequest;

const SCHEMA: &str = "chio.retained-tool-admission-request.v1";
const SECURITY_SCHEMA: &str = "chio.retained-tool-admission-request.v2";
const NATIVE_SECURITY_SCHEMA: &str = "chio.retained-tool-admission-request.v3";
const AUTHORITY_PROFILE_SCHEMA: &str = "chio.retained-tool-admission-request.v4";
const OUTPUT_RETENTION_SCHEMA: &str = "chio.retained-tool-admission-request.v5";
const ORIGINAL_SEMANTIC_SCHEMA: &str = "chio.retained-tool-admission-request.v6";
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
/// artifacts, explicit original authority profiles in v4 and original output
/// retention data in v5. No stored
/// version establishes a current trusted host context or claim authority.
#[derive(Clone)]
pub struct RetainedToolAdmissionRequestV1 {
    // Historical custody verification composes several store layers. Keep the
    // decoded request heap-owned so each validating frame carries a handle,
    // not another full capability/request/authority-profile value.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_profile: Option<AdmissionAuthorityProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_output_retention: Option<NativeOutputRetentionProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_semantic_request_commitment:
        Option<chio_security_types::recovery::CanonicalPayloadDigest>,
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

/// Extends the original V4 request commitment without changing its preimage.
/// This is configuration binding DATA, not capture or financing authority.
pub(crate) fn immutable_tool_request_hash_with_output_retention(
    request: &ToolCallRequest,
    matching_grants: &[MatchingGrant<'_>],
    post_return_steps: &[FrozenEvaluationStepV1],
    security_binding: Option<&AdmissionSecurityBindingV1>,
    authority_profile: Option<&AdmissionAuthorityProfileV1>,
    native_output_retention: Option<&NativeOutputRetentionProfileV1>,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let prior_request_hash = immutable_tool_request_hash_with_profile(
        request,
        matching_grants,
        post_return_steps,
        security_binding,
        authority_profile,
    )?;
    let Some(retention) = native_output_retention else {
        return Ok(prior_request_hash);
    };
    retention
        .validate_original_plan(post_return_steps.len())
        .map_err(invalid)?;
    if authority_profile.is_none()
        || security_binding
            .and_then(AdmissionSecurityBindingV1::native_authority)
            .is_none()
    {
        return Err(invalid(
            "native output retention requires original native authority",
        ));
    }
    #[derive(Serialize)]
    struct RetentionBoundRequest<'a> {
        schema: &'static str,
        prior_request_hash: &'a AdmissionDigest,
        native_output_retention: &'a NativeOutputRetentionProfileV1,
    }
    let bytes = canonical_json_bytes(&RetentionBoundRequest {
        schema: "chio.tool-admission-request.v5",
        prior_request_hash: &prior_request_hash,
        native_output_retention: retention,
    })
    .map_err(invalid)?;
    AdmissionDigest::try_new("immutable_request_hash", sha256_hex(&bytes)).map_err(Into::into)
}

/// Fresh native originals bind the actual full semantic request before
/// transient credentials are omitted from storage. The old V5 helper remains
/// unchanged; the new outer commitment carries no credential bytes.
pub(crate) fn immutable_tool_request_hash_with_original_semantics(
    request: &ToolCallRequest,
    matching_grants: &[MatchingGrant<'_>],
    post_return_steps: &[FrozenEvaluationStepV1],
    security_binding: Option<&AdmissionSecurityBindingV1>,
    authority_profile: Option<&AdmissionAuthorityProfileV1>,
    native_output_retention: Option<&NativeOutputRetentionProfileV1>,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let prior = immutable_tool_request_hash_with_output_retention(
        request,
        matching_grants,
        post_return_steps,
        security_binding,
        authority_profile,
        native_output_retention,
    )?;
    if native_output_retention.is_none() {
        return Ok(prior);
    }
    let semantic = crate::recovery::semantic_request_semantics(request).map_err(invalid)?;
    bind_original_semantics(&prior, semantic)
}

fn bind_original_semantics(
    prior: &AdmissionDigest,
    semantic: chio_security_types::recovery::CanonicalPayloadDigest,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(&("chio.tool-admission-request.v6", prior, semantic))
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

    #[cfg(test)]
    pub(crate) fn from_admission_with_profile(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Self::from_admission_with_output_retention(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
            None,
        )
    }

    pub(crate) fn from_admission_with_output_retention(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
        native_output_retention: Option<&NativeOutputRetentionProfileV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if let Some(retention) = native_output_retention {
            retention
                .validate_original_plan(post_return_steps.len())
                .map_err(invalid)?;
        }
        let request = Self::request_without_transient_credentials(request);
        let wire = RetainedRequestWire {
            schema: if native_output_retention.is_some() {
                OUTPUT_RETENTION_SCHEMA
            } else {
                Self::schema(security_binding, authority_profile)
            }
            .to_owned(),
            request: Box::new(request),
            matching_grant_indices: matching_grants.iter().map(|grant| grant.index).collect(),
            post_return_steps: post_return_steps.to_vec(),
            security_binding: security_binding.cloned(),
            authority_profile: authority_profile.cloned(),
            native_output_retention: native_output_retention.cloned(),
            original_semantic_request_commitment: None,
        };
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        Self::from_canonical_bytes(&canonical)
    }

    /// Only the actual fresh Kernel admission constructs V6. Historical
    /// constructors keep their original version and never synthesize a digest
    /// from a sanitized request or today's configured native profile.
    pub(crate) fn from_admission_with_original_semantics(
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
        native_output_retention: Option<&NativeOutputRetentionProfileV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let original_semantic = native_output_retention
            .map(|_| crate::recovery::semantic_request_semantics(request).map_err(invalid))
            .transpose()?;
        let mut retained = Self::from_admission_with_output_retention(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
            native_output_retention,
        )?;
        if let Some(semantic) = original_semantic {
            retained.wire.schema = ORIGINAL_SEMANTIC_SCHEMA.into();
            retained.wire.original_semantic_request_commitment = Some(semantic);
            let canonical = canonical_json_bytes(&retained.wire).map_err(invalid)?;
            return Self::from_canonical_bytes(&canonical);
        }
        Ok(retained)
    }

    /// Decode untrusted stored bytes without granting provenance or authority.
    /// Exact typed canonical re-encoding also rejects ignored nested fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdmissionOperationStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid("retained request exceeds its artifact bound"));
        }
        let wire: Box<RetainedRequestWire> = serde_json::from_slice(bytes).map_err(invalid)?;
        let request = &wire.request;
        let expected_schema = if let Some(retention) = wire.native_output_retention.as_ref() {
            retention
                .validate_original_plan(wire.post_return_steps.len())
                .map_err(invalid)?;
            if wire.authority_profile.is_none()
                || wire
                    .security_binding
                    .as_ref()
                    .and_then(AdmissionSecurityBindingV1::native_authority)
                    .is_none()
            {
                return Err(invalid(
                    "native output retention lost original native authority",
                ));
            }
            if wire.original_semantic_request_commitment.is_some() {
                ORIGINAL_SEMANTIC_SCHEMA
            } else {
                OUTPUT_RETENTION_SCHEMA
            }
        } else {
            if wire.original_semantic_request_commitment.is_some() {
                return Err(invalid(
                    "original semantic commitment lacks original native profile",
                ));
            }
            Self::schema(
                wire.security_binding.as_ref(),
                wire.authority_profile.as_ref(),
            )
        };
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

    /// Complete original producer bounds from retained DATA. Actual store
    /// provenance, original operation/lease and funded liabilities are separate.
    #[must_use]
    pub fn native_output_retention(&self) -> Option<&NativeOutputRetentionProfileV1> {
        self.wire.native_output_retention.as_ref()
    }

    /// Independent original full-semantic commitment DATA. Only the actual
    /// fenced retained original/begin binding establishes its provenance.
    /// It grants neither a current classifier nor admission/financing authority.
    #[must_use]
    pub fn original_semantic_request_commitment(
        &self,
    ) -> Option<chio_security_types::recovery::CanonicalPayloadDigest> {
        self.wire.original_semantic_request_commitment
    }

    /// Equality against the actual borrowed live request. Historical callers
    /// use the retained scalar only after independently verifying the original
    /// source; they cannot regenerate it from omitted approval/DPoP material.
    pub fn validate_original_semantic_request(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), AdmissionOperationStoreError> {
        if let Some(semantic) = self.original_semantic_request_commitment() {
            if crate::recovery::semantic_request_semantics(request).map_err(invalid)? != semantic {
                return Err(invalid(
                    "request differs from its original full semantic commitment",
                ));
            }
        }
        Ok(())
    }

    /// Original frozen verifier identities as read-only DATA. The native store
    /// independently authenticates retained source, operation and funded phase
    /// purposes before using them. This view grants no execution or loan.
    #[must_use]
    pub fn post_return_steps(&self) -> &[FrozenEvaluationStepV1] {
        &self.wire.post_return_steps
    }

    /// Validate only the closed original bounded materialization DATA shape.
    /// A decoded request can satisfy this check, so it grants no admission,
    /// finishing allocation, dispatch or replacement of a historical profile.
    pub fn validate_bounded_native_materializer(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.native_security_authority_binding().is_none() {
            return Err(AdmissionOperationStoreError::Invariant(
                "bounded materializer requires original native selection".into(),
            ));
        }
        let profile = self.native_output_retention().ok_or_else(|| {
            AdmissionOperationStoreError::Invariant(
                "bounded materializer original profile is absent".into(),
            )
        })?;
        let expected = profile.materialization_identity()?;
        if self.post_return_steps() != [expected] {
            return Err(AdmissionOperationStoreError::Invariant(
                "bounded materializer differs from the original frozen step".into(),
            ));
        }
        Ok(())
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
        let mut candidate = Self::from_admission_with_output_retention(
            request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
            self.wire.security_binding.as_ref(),
            self.wire.authority_profile.as_ref(),
            self.wire.native_output_retention.as_ref(),
        )?;
        if let Some(semantic) = self.original_semantic_request_commitment() {
            candidate.wire.schema = ORIGINAL_SEMANTIC_SCHEMA.into();
            candidate.wire.original_semantic_request_commitment = Some(semantic);
            candidate.canonical = canonical_json_bytes(&candidate.wire).map_err(invalid)?;
        }
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
        if let Some(semantic) = self.original_semantic_request_commitment() {
            let prior = immutable_tool_request_hash_with_output_retention(
                &self.wire.request,
                &self.matching_grants()?,
                &self.wire.post_return_steps,
                self.wire.security_binding.as_ref(),
                self.wire.authority_profile.as_ref(),
                self.wire.native_output_retention.as_ref(),
            )?;
            let expected = bind_original_semantics(&prior, semantic)?;
            let capability =
                sha256_hex(&canonical_json_bytes(&self.wire.request.capability).map_err(invalid)?);
            let action =
                sha256_hex(&canonical_json_bytes(&self.wire.request.arguments).map_err(invalid)?);
            if binding.kind() != super::AdmissionOperationKind::ToolDispatch
                || binding.request_id().as_str() != self.wire.request.request_id
                || binding.capability_id().as_str() != self.wire.request.capability.id
                || binding.authorization_capability_hash.as_str() != capability
                || binding.action_parameter_hash().as_str() != action
                || binding.immutable_request_hash() != &expected
            {
                return Err(invalid(
                    "V6 retained original differs from its admission binding",
                ));
            }
            return Ok(());
        }
        Self::validate_request_binding_with_output_retention(
            binding,
            &self.wire.request,
            &self.matching_grants()?,
            &self.wire.post_return_steps,
            self.wire.security_binding.as_ref(),
            self.wire.authority_profile.as_ref(),
            self.wire.native_output_retention.as_ref(),
        )
    }

    /// Reconstruct an original plan commitment with its authenticated retained
    /// scalar. No current profile or stripped-request semantics is synthesized.
    pub(crate) fn immutable_hash_for_original_plan(
        &self,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        steps: &[FrozenEvaluationStepV1],
        security: Option<&AdmissionSecurityBindingV1>,
        profile: Option<&AdmissionAuthorityProfileV1>,
        retention: Option<&NativeOutputRetentionProfileV1>,
    ) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        let prior = immutable_tool_request_hash_with_output_retention(
            request,
            matching_grants,
            steps,
            security,
            profile,
            retention,
        )?;
        match self.original_semantic_request_commitment() {
            Some(semantic) => bind_original_semantics(&prior, semantic),
            None => Ok(prior),
        }
    }

    pub(crate) fn validate_request_binding(
        binding: &AdmissionOperationBindingV1,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
    ) -> Result<(), AdmissionOperationStoreError> {
        Self::validate_request_binding_with_output_retention(
            binding,
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
            None,
        )
    }

    fn validate_request_binding_with_output_retention(
        binding: &AdmissionOperationBindingV1,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        post_return_steps: &[FrozenEvaluationStepV1],
        security_binding: Option<&AdmissionSecurityBindingV1>,
        authority_profile: Option<&AdmissionAuthorityProfileV1>,
        native_output_retention: Option<&NativeOutputRetentionProfileV1>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let capability_hash =
            sha256_hex(&canonical_json_bytes(&request.capability).map_err(invalid)?);
        let action_hash = sha256_hex(&canonical_json_bytes(&request.arguments).map_err(invalid)?);
        let request_hash = immutable_tool_request_hash_with_output_retention(
            request,
            matching_grants,
            post_return_steps,
            security_binding,
            authority_profile,
            native_output_retention,
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
