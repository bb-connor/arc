use chio_core::{
    canonical::UntrustedJsonText,
    capability::{attenuation::validate_delegation_chain, token::CapabilityToken},
    crypto::PublicKey,
    Error as CoreError,
};
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTimeStatus {
    Valid,
    NotYetValid,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityVerification {
    pub signature_valid: bool,
    pub delegation_chain_shape_valid: bool,
    pub time_valid: bool,
    pub time_status: CapabilityTimeStatus,
}

/// Decodes capability JSON with the signed-wire contract: a duplicate object
/// key at any depth, or a number token that would change representation,
/// fails before any field is read.
pub fn parse_capability_json(input: &str) -> Result<CapabilityToken> {
    UntrustedJsonText::from_wire(input.as_bytes(), crate::MAX_JSON_INPUT_BYTES)
        .and_then(|text| text.decode_signed())
        .map_err(|error| CoreError::UntrustedInput(error.into()).into())
}

pub fn capability_signing_body_canonical_json(capability: &CapabilityToken) -> Result<String> {
    chio_core::canonical_json_string(&capability.signing_body()).map_err(Into::into)
}

/// `root_delegator` is the subject key of the parent capability the delegation
/// chain starts from. A delegated capability without it is refused with
/// `DelegationRootUnresolved`.
pub fn verify_capability(
    capability: &CapabilityToken,
    root_delegator: Option<&PublicKey>,
    now: u64,
    max_delegation_depth: Option<u32>,
) -> Result<CapabilityVerification> {
    let delegation_chain_shape_valid = if capability.delegation_chain.is_empty() {
        true
    } else {
        let root_delegator = root_delegator
            .or(capability
                .delegation_chain
                .first()
                .map(|link| &link.delegator))
            .ok_or(CoreError::DelegationRootUnresolved)?;
        validate_delegation_chain(
            &capability.delegation_chain,
            root_delegator,
            max_delegation_depth,
        )
        .is_ok()
    };
    let time_status = match capability.validate_time(now) {
        Ok(()) => CapabilityTimeStatus::Valid,
        Err(CoreError::CapabilityNotYetValid { .. }) => CapabilityTimeStatus::NotYetValid,
        Err(CoreError::CapabilityExpired { .. }) => CapabilityTimeStatus::Expired,
        Err(error) => return Err(error.into()),
    };

    Ok(CapabilityVerification {
        signature_valid: capability.verify_integrity_embedded_key()?,
        delegation_chain_shape_valid,
        time_valid: matches!(time_status, CapabilityTimeStatus::Valid),
        time_status,
    })
}

pub fn verify_capability_json(
    input: &str,
    root_delegator_hex: Option<&str>,
    now: u64,
    max_delegation_depth: Option<u32>,
) -> Result<CapabilityVerification> {
    let capability = parse_capability_json(input)?;
    let root_delegator = root_delegator_hex.map(PublicKey::from_hex).transpose()?;
    verify_capability(
        &capability,
        root_delegator.as_ref(),
        now,
        max_delegation_depth,
    )
}

#[cfg(test)]
mod tests {
    use super::{verify_capability, CapabilityTimeStatus};
    use chio_core::{
        capability::{
            scope::{ChioScope, Constraint, Operation, ToolGrant},
            token::{CapabilityToken, CapabilityTokenBody},
        },
        Keypair,
    };

    fn sample_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                operations: vec![Operation::Invoke, Operation::ReadResult],
                constraints: vec![Constraint::PathPrefix("/workspace/".to_string())],
                max_invocations: Some(3),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        }
    }

    fn sample_capability() -> crate::Result<CapabilityToken> {
        let issuer = Keypair::from_seed(&[11u8; 32]);
        let subject = Keypair::from_seed(&[12u8; 32]);
        Ok(CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-bindings-valid".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: sample_scope(),
                issued_at: 1710000200,
                expires_at: 1710000800,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &issuer,
        )?)
    }

    #[test]
    fn verify_valid_capability() -> crate::Result<()> {
        let capability = sample_capability()?;
        let verification = verify_capability(&capability, None, 1710000400, None)?;
        assert_eq!(
            verification,
            super::CapabilityVerification {
                signature_valid: true,
                delegation_chain_shape_valid: true,
                time_valid: true,
                time_status: CapabilityTimeStatus::Valid,
            }
        );
        Ok(())
    }
}
