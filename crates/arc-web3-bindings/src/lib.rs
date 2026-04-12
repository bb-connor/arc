//! Alloy bindings and packaged artifacts for the official ARC web3 contract family.
//!
//! This crate is the Rust-side integration target for the Solidity package in
//! `contracts/`. It exposes:
//!
//! - `alloy::sol!` bindings derived from the compiled interface artifacts
//! - bundled ABI JSON emitted from the local contract compiler
//! - bundled deployment and qualification artifacts for the local devnet harness

pub mod interfaces;

pub use interfaces::{
    ArcMerkleProof, IArcBondVault, IArcEscrow, IArcIdentityRegistry, IArcPriceResolver,
    IArcRootRegistry,
};

pub const ARC_ROOT_REGISTRY_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IArcRootRegistry.json");
pub const ARC_IDENTITY_REGISTRY_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IArcIdentityRegistry.json");
pub const ARC_ESCROW_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IArcEscrow.json");
pub const ARC_BOND_VAULT_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IArcBondVault.json");
pub const ARC_PRICE_RESOLVER_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IArcPriceResolver.json");

pub const ARC_ROOT_REGISTRY_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ArcRootRegistry.json");
pub const ARC_IDENTITY_REGISTRY_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ArcIdentityRegistry.json");
pub const ARC_ESCROW_ARTIFACT: &str = include_str!("../../../contracts/artifacts/ArcEscrow.json");
pub const ARC_BOND_VAULT_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ArcBondVault.json");
pub const ARC_PRICE_RESOLVER_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ArcPriceResolver.json");

pub const ARC_LOCAL_DEVNET_DEPLOYMENT: &str =
    include_str!("../../../contracts/deployments/local-devnet.json");
pub const ARC_LOCAL_DEVNET_QUALIFICATION_REPORT: &str =
    include_str!("../../../contracts/reports/local-devnet-qualification.json");

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        ARC_BOND_VAULT_ARTIFACT, ARC_BOND_VAULT_INTERFACE_ARTIFACT, ARC_ESCROW_ARTIFACT,
        ARC_ESCROW_INTERFACE_ARTIFACT, ARC_IDENTITY_REGISTRY_ARTIFACT,
        ARC_IDENTITY_REGISTRY_INTERFACE_ARTIFACT, ARC_LOCAL_DEVNET_DEPLOYMENT,
        ARC_LOCAL_DEVNET_QUALIFICATION_REPORT, ARC_PRICE_RESOLVER_ARTIFACT,
        ARC_PRICE_RESOLVER_INTERFACE_ARTIFACT, ARC_ROOT_REGISTRY_ARTIFACT,
        ARC_ROOT_REGISTRY_INTERFACE_ARTIFACT,
    };

    fn assert_contract_artifact(name: &str, body: &str) {
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["contractName"], name);
        assert!(parsed["abi"].is_array());
        assert!(parsed["bytecode"].as_str().is_some());
    }

    #[test]
    fn bundled_contract_artifacts_parse() {
        assert_contract_artifact("ArcRootRegistry", ARC_ROOT_REGISTRY_ARTIFACT);
        assert_contract_artifact("ArcIdentityRegistry", ARC_IDENTITY_REGISTRY_ARTIFACT);
        assert_contract_artifact("ArcEscrow", ARC_ESCROW_ARTIFACT);
        assert_contract_artifact("ArcBondVault", ARC_BOND_VAULT_ARTIFACT);
        assert_contract_artifact("ArcPriceResolver", ARC_PRICE_RESOLVER_ARTIFACT);
    }

    #[test]
    fn bundled_interface_artifacts_parse() {
        assert_contract_artifact("IArcRootRegistry", ARC_ROOT_REGISTRY_INTERFACE_ARTIFACT);
        assert_contract_artifact(
            "IArcIdentityRegistry",
            ARC_IDENTITY_REGISTRY_INTERFACE_ARTIFACT,
        );
        assert_contract_artifact("IArcEscrow", ARC_ESCROW_INTERFACE_ARTIFACT);
        assert_contract_artifact("IArcBondVault", ARC_BOND_VAULT_INTERFACE_ARTIFACT);
        assert_contract_artifact("IArcPriceResolver", ARC_PRICE_RESOLVER_INTERFACE_ARTIFACT);
    }

    #[test]
    fn bundled_devnet_artifacts_parse() {
        let deployment: Value = serde_json::from_str(ARC_LOCAL_DEVNET_DEPLOYMENT).unwrap();
        assert_eq!(
            deployment["manifest_id"],
            "arc.web3-deployment.local-devnet.v1"
        );

        let qualification: Value =
            serde_json::from_str(ARC_LOCAL_DEVNET_QUALIFICATION_REPORT).unwrap();
        assert_eq!(
            qualification["report_id"],
            "arc.web3-contract-qualification.local-devnet.v1"
        );
        assert!(qualification["checks"].is_array());
    }
}
