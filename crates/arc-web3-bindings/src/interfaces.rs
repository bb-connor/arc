//! Artifact-derived Alloy bindings for the official ARC web3 contract family.

use alloy::primitives::{B256, U256};

pub(crate) mod root_registry_bindings {
    use alloy::sol;

    sol!(
        IArcRootRegistry,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/artifacts/interfaces/IArcRootRegistry.json"
        )
    );
}

pub(crate) mod identity_registry_bindings {
    use alloy::sol;

    sol!(
        IArcIdentityRegistry,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/artifacts/interfaces/IArcIdentityRegistry.json"
        )
    );
}

pub(crate) mod escrow_bindings {
    use alloy::sol;

    sol!(
        IArcEscrow,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/artifacts/interfaces/IArcEscrow.json"
        )
    );
}

pub(crate) mod bond_vault_bindings {
    use alloy::sol;

    sol!(
        IArcBondVault,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/artifacts/interfaces/IArcBondVault.json"
        )
    );
}

pub(crate) mod price_resolver_bindings {
    use alloy::sol;

    sol!(
        IArcPriceResolver,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/artifacts/interfaces/IArcPriceResolver.json"
        )
    );
}

pub use bond_vault_bindings::IArcBondVault;
pub use escrow_bindings::IArcEscrow;
pub use identity_registry_bindings::IArcIdentityRegistry;
pub use price_resolver_bindings::IArcPriceResolver;
pub use root_registry_bindings::IArcRootRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcMerkleProof {
    pub audit_path: Vec<B256>,
    pub leaf_index: U256,
    pub tree_size: U256,
}

impl From<&ArcMerkleProof> for root_registry_bindings::ArcMerkle::Proof {
    fn from(proof: &ArcMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ArcMerkleProof> for root_registry_bindings::ArcMerkle::Proof {
    fn from(proof: ArcMerkleProof) -> Self {
        Self::from(&proof)
    }
}

impl From<&ArcMerkleProof> for escrow_bindings::ArcMerkle::Proof {
    fn from(proof: &ArcMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ArcMerkleProof> for escrow_bindings::ArcMerkle::Proof {
    fn from(proof: ArcMerkleProof) -> Self {
        Self::from(&proof)
    }
}

impl From<&ArcMerkleProof> for bond_vault_bindings::ArcMerkle::Proof {
    fn from(proof: &ArcMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ArcMerkleProof> for bond_vault_bindings::ArcMerkle::Proof {
    fn from(proof: ArcMerkleProof) -> Self {
        Self::from(&proof)
    }
}
