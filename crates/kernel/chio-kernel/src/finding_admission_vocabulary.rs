//! Finding admission vocabulary that kernel seams name in every build.
//!
//! Without the `finding-market` feature the verified admission types are
//! uninhabited, so such a kernel cannot hold a verified purchase, recovery
//! or status proof, and the replay-snapshot keys stay reserved so receipts
//! that carry them are rejected.

/// Receipt-metadata key carrying the durable, admission-verified purchase
/// binding used by terminal replay after authority rotation.
pub(crate) const FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY: &str =
    "finding_purchase_replay_snapshot";

/// Receipt-metadata key carrying the durable recovery binding and the exact
/// live-status floor admitted immediately before dispatch.
pub(crate) const FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY: &str =
    "finding_recovery_replay_snapshot";

#[cfg(not(feature = "finding-market"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiedFindingPurchase {}

#[cfg(not(feature = "finding-market"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiedFindingStatusProof {}

#[cfg(not(feature = "finding-market"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiedFindingRecovery {}
