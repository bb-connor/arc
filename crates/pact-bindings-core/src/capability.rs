use pact_core::{validate_delegation_chain, CapabilityToken, Error as CoreError};
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
    pub delegation_chain_valid: bool,
    pub time_valid: bool,
    pub time_status: CapabilityTimeStatus,
}

pub fn parse_capability_json(input: &str) -> Result<CapabilityToken> {
    Ok(serde_json::from_str(input)?)
}

pub fn capability_body_canonical_json(capability: &CapabilityToken) -> Result<String> {
    pact_core::canonical_json_string(&capability.body()).map_err(Into::into)
}

pub fn verify_capability(
    capability: &CapabilityToken,
    now: u64,
    max_delegation_depth: Option<u32>,
) -> Result<CapabilityVerification> {
    let time_status = match capability.validate_time(now) {
        Ok(()) => CapabilityTimeStatus::Valid,
        Err(CoreError::CapabilityNotYetValid { .. }) => CapabilityTimeStatus::NotYetValid,
        Err(CoreError::CapabilityExpired { .. }) => CapabilityTimeStatus::Expired,
        Err(error) => return Err(error.into()),
    };

    Ok(CapabilityVerification {
        signature_valid: capability.verify_signature()?,
        delegation_chain_valid: validate_delegation_chain(
            &capability.delegation_chain,
            max_delegation_depth,
        )
        .is_ok(),
        time_valid: matches!(time_status, CapabilityTimeStatus::Valid),
        time_status,
    })
}

pub fn verify_capability_json(
    input: &str,
    now: u64,
    max_delegation_depth: Option<u32>,
) -> Result<CapabilityVerification> {
    let capability = parse_capability_json(input)?;
    verify_capability(&capability, now, max_delegation_depth)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{verify_capability, CapabilityTimeStatus};
    use pact_core::{
        CapabilityToken, CapabilityTokenBody, Constraint, Keypair, Operation, PactScope, ToolGrant,
    };

    fn sample_scope() -> PactScope {
        PactScope {
            grants: vec![ToolGrant {
                server_id: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                operations: vec![Operation::Invoke, Operation::ReadResult],
                constraints: vec![Constraint::PathPrefix("/workspace/".to_string())],
                max_invocations: Some(3),
                max_cost_per_invocation: None,
                max_total_cost: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        }
    }

    fn sample_capability() -> CapabilityToken {
        let issuer = Keypair::from_seed(&[11u8; 32]);
        let subject = Keypair::from_seed(&[12u8; 32]);
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-bindings-valid".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: sample_scope(),
                issued_at: 1710000200,
                expires_at: 1710000800,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .unwrap()
    }

    #[test]
    fn verify_valid_capability() {
        let capability = sample_capability();
        let verification = verify_capability(&capability, 1710000400, None).unwrap();
        assert_eq!(
            verification,
            super::CapabilityVerification {
                signature_valid: true,
                delegation_chain_valid: true,
                time_valid: true,
                time_status: CapabilityTimeStatus::Valid,
            }
        );
    }
}
