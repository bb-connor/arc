//! Test composition-root verifier with a genuinely signed, request-bound artifact.
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Signature};
use chio_kernel::supplemental_quota::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Body {
    capability_id: String,
    request_id: String,
    arguments_hash: String,
    destination: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Artifact {
    body: Body,
    signature: Signature,
}

pub fn issue(request: &chio_kernel::ToolCallRequest) -> super::Result<String> {
    let body = Body {
        capability_id: request.capability.id.clone(),
        request_id: request.request_id.clone(),
        arguments_hash: sha256_hex(&canonical_json_bytes(&request.arguments)?),
        destination: String::from_utf8(canonical_json_bytes(&serde_json::json!({
            "server_id": request.server_id, "tool_name": request.tool_name,
        }))?)?,
        expires_at: request.capability.expires_at,
    };
    let (signature, _) = super::issuer().sign_canonical(&body)?;
    Ok(serde_json::to_string(&Artifact { body, signature })?)
}

pub struct Verifier;
impl SupplementalQuotaVerifier for Verifier {
    fn verify(
        &self,
        bytes: &[u8],
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaVerifierError> {
        let checked = || -> super::Result<VerifiedSupplementalQuotaClaim> {
            let artifact: Artifact = serde_json::from_slice(bytes)?;
            let body = artifact.body;
            if !super::issuer()
                .public_key()
                .verify_canonical(&body, &artifact.signature)?
                || body.capability_id != context.capability_id
                || body.request_id != context.request_id
                || body.arguments_hash != context.arguments_hash
                || body.destination != context.normalized_destination
            {
                return Err("signed supplemental binding mismatch".into());
            }
            Ok(VerifiedSupplementalQuotaClaim {
                profile: BROKER_CAPABILITY_EXECUTION_PROFILE.into(),
                broker_capability_id: "process-supplemental-budget".into(),
                issuer: super::issuer().public_key(),
                request_constraint_digest: sha256_hex(&canonical_json_bytes(&body)?),
                max_invocations: 1,
                authorization_artifact_digest: supplemental_authorization_artifact_digest(bytes),
                supplemental_revocation_ids: vec!["process-supplemental-budget".into()],
                expires_at: body.expires_at,
                request_binding_hash: supplemental_request_binding_hash(context)?,
                capability_id: context.capability_id.clone(),
                capability_digest: context.capability_digest.clone(),
                request_namespace_digest: context.request_namespace_digest.clone(),
                operation_id: context.operation_id.clone(),
                subject: context.subject.clone(),
                request_id: context.request_id.clone(),
                normalized_destination: context.normalized_destination.clone(),
                arguments_hash: context.arguments_hash.clone(),
                negotiated_features: context.negotiated_features.clone(),
            })
        };
        checked().map_err(|error| SupplementalQuotaVerifierError::new(error.to_string()))
    }
}
