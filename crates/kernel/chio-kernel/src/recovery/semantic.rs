//! Exact semantic request projection, independent of proof-bearing arguments.
use crate::{KernelError, ToolCallRequest};
use chio_core_types::recovery::semantic_content_digest;
use chio_security_types::recovery::CanonicalPayloadDigest;

/// The invocation body separately binds payload and the closed unsigned action.
/// Disclosure and execution nonce artifacts are native-owned participants: their
/// full original bytes and one-shot custody are validated at physical capture.
/// Keeping those artifacts outside this preimage avoids signature/hash cycles.
/// All other authorization and request semantics are fixed. This destructuring
/// intentionally has no rest pattern, so a new request field requires review.
pub fn semantic_request_semantics(
    request: &ToolCallRequest,
) -> Result<CanonicalPayloadDigest, KernelError> {
    let ToolCallRequest {
        request_id,
        capability,
        tool_name,
        server_id,
        agent_id,
        arguments: _,
        dpop_proof,
        execution_nonce: _,
        governed_intent,
        approval_token,
        approval_tokens,
        threshold_approval_proposal,
        supplemental_authorization,
        model_metadata,
        federated_origin_kernel_id,
        declassification_grant: _,
    } = request;
    semantic_content_digest(&(
        "chio.semantic.native-request-semantics.v1",
        request_id,
        capability,
        tool_name,
        server_id,
        agent_id,
        dpop_proof,
        governed_intent,
        approval_token,
        approval_tokens,
        threshold_approval_proposal,
        supplemental_authorization,
        model_metadata,
        federated_origin_kernel_id,
    ))
    .map_err(|_| KernelError::DurableAdmission("native semantic remedy refused".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_semantics_bind_identity_route_authorization_and_model(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
        ))?;
        let request: ToolCallRequest = serde_json::from_value(fixture["request"].clone())?;
        let original = semantic_request_semantics(&request)?;
        for mutation in 0..7 {
            let mut changed = request.clone();
            match mutation {
                0 => changed.agent_id = "other-agent".into(),
                1 => changed.server_id = "other-server".into(),
                2 => changed.tool_name = "other-tool".into(),
                3 => changed.request_id = "other-request".into(),
                4 => changed.capability.id = "other-capability".into(),
                5 => changed.federated_origin_kernel_id = Some("other-kernel".into()),
                _ => {
                    changed.model_metadata = Some(chio_core::capability::scope::ModelMetadata {
                        model_id: "other-model".into(),
                        safety_tier: None,
                        provider: None,
                        provenance_class: Default::default(),
                    })
                }
            }
            assert_ne!(semantic_request_semantics(&changed)?, original);
        }
        let mut proof_bearing = request;
        proof_bearing.arguments = serde_json::json!({"proof":"later-bound-invocation-proof"});
        assert_eq!(semantic_request_semantics(&proof_bearing)?, original);
        Ok(())
    }
}
