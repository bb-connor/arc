//! Revocation oracle primitives for Chio.

#![forbid(unsafe_code)]

pub mod api;
pub mod epoch;
pub mod finding_status_sparse;
pub mod freshness;
pub mod partner_mirror;
pub mod passport_bridge;
pub mod signer;
pub mod sparse_merkle;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey,
    RevocationOracle, RevocationOracleError, RootSignature, SubjectId,
};
pub use epoch::{
    tick_and_broadcast, EpochBroadcaster, InMemoryEpochBroadcaster, SignedEpochRoot,
    DEFAULT_EPOCH_TICK_MS,
};
pub use finding_status_sparse::{
    finding_status_empty_leaf_hash, finding_status_key_hash, verify_finding_status_inclusion,
    verify_finding_status_non_inclusion, FindingStatusSparseLeaf, FindingStatusSparseMap,
    FindingStatusSparseProof, FindingStatusSparseRoot, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
pub use freshness::{verify_fresh_epoch_root, FreshnessConfig};
pub use partner_mirror::{
    check_history, ConflictRecord, PartnerMirrorConflict, PartnerMirrorRefusal,
    MAX_RECORDED_PARTNER_CONFLICTS,
};
pub use passport_bridge::{
    apply_passport_revocation, credential_revocation_key, passport_revocation_key,
    PassportRevocationBridgeError, PassportRevocationEvent, PassportRevocationLeafKind,
    CREDENTIAL_REVOCATION_NONCE, PASSPORT_REVOCATION_NONCE,
};
#[cfg(feature = "sqlite")]
pub use passport_bridge::{PassportRevocationLeaf, PassportRevocationLeafError};
pub use signer::{
    Ed25519RootSigner, Ed25519RootVerifier, EpochRootSigner, EpochRootVerifier,
    PASSPORT_REVOCATION_ROOT_SCHEMA,
};
pub use sparse_merkle::InMemoryRevocationOracle;
#[cfg(feature = "sqlite")]
pub use sqlite::partner_mirror::{PartnerMirrorError, PartnerMirrorView, SqlitePartnerMirror};
#[cfg(feature = "sqlite")]
pub use sqlite::{
    RevocationLeaf, RevocationTransaction, SqliteRevocationOracle, SqliteRevocationOracleError,
    MAX_REVOCATION_SUBJECT_BYTES, SQLITE_REVOCATION_ORACLE_SCHEMA_VERSION,
};
