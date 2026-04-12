use arc_core::web3::{SignedWeb3IdentityBinding, Web3KeyBindingPurpose};
use serde::{Deserialize, Serialize};

use crate::{AnchorError, AnchorServiceConfig};

pub const ARC_ANCHOR_DISCOVERY_SCHEMA: &str = "arc.anchor-discovery.v1";
pub const ARC_ANCHOR_SERVICE_TYPE: &str = "ArcAnchorService";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryChain {
    pub chain_id: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryServiceEndpoint {
    pub chains: Vec<AnchorDiscoveryChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin_anchor_method: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ots_calendars: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_cluster: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: AnchorDiscoveryServiceEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPublicationOwnership {
    pub chain_id: String,
    pub root_owner_address: String,
    pub publisher_address: String,
    pub delegate_publication_allowed: bool,
    pub ownership_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDiscoveryArtifact {
    pub schema: String,
    pub arc_identity: String,
    pub operator_binding: SignedWeb3IdentityBinding,
    pub service: AnchorDiscoveryService,
    pub root_publication_ownership: Vec<RootPublicationOwnership>,
}

pub fn build_anchor_discovery_artifact(
    config: &AnchorServiceConfig,
    binding: &SignedWeb3IdentityBinding,
) -> Result<AnchorDiscoveryArtifact, AnchorError> {
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Anchor)
    {
        return Err(AnchorError::InvalidBinding(
            "binding certificate does not include anchor purpose".to_string(),
        ));
    }

    let chains: Vec<AnchorDiscoveryChain> = config
        .evm_targets
        .iter()
        .map(|target| AnchorDiscoveryChain {
            chain_id: target.chain_id.clone(),
            contract_address: target.contract_address.clone(),
            operator_address: target.operator_address.clone(),
            publisher_address: target.publisher_address.clone(),
            requires_delegate_authorization: target.publisher_address != target.operator_address,
        })
        .collect();
    let root_publication_ownership = config
        .evm_targets
        .iter()
        .map(|target| RootPublicationOwnership {
            chain_id: target.chain_id.clone(),
            root_owner_address: target.operator_address.clone(),
            publisher_address: target.publisher_address.clone(),
            delegate_publication_allowed: target.publisher_address != target.operator_address,
            ownership_rule: if target.publisher_address == target.operator_address {
                "operator-published".to_string()
            } else {
                "operator-owned-root delegate-published-via-root-registry-authorization".to_string()
            },
        })
        .collect();

    Ok(AnchorDiscoveryArtifact {
        schema: ARC_ANCHOR_DISCOVERY_SCHEMA.to_string(),
        arc_identity: binding.certificate.arc_identity.clone(),
        operator_binding: binding.clone(),
        service: AnchorDiscoveryService {
            id: format!("{}#anchor", binding.certificate.arc_identity),
            service_type: ARC_ANCHOR_SERVICE_TYPE.to_string(),
            service_endpoint: AnchorDiscoveryServiceEndpoint {
                chains,
                bitcoin_anchor_method: (!config.ots_calendars.is_empty())
                    .then(|| "opentimestamps".to_string()),
                ots_calendars: config.ots_calendars.clone(),
                solana_cluster: config.solana_cluster.clone(),
            },
        },
        root_publication_ownership,
    })
}
