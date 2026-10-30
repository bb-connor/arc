//! Per-peer `issued_at` high-water marks: a receiver refuses every peer
//! request issued at or below its peer's stored mark, across restarts.

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
use alloc::string::String;

pub const CLUSTER_PEER_NODE_ID_MAX_BYTES: usize = 2048;

pub const CLUSTER_PEER_REPLAY_MAX_PEERS: usize = 4096;

/// A cluster peer node id of 1 to [`CLUSTER_PEER_NODE_ID_MAX_BYTES`] bytes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClusterPeerNodeId(String);

impl ClusterPeerNodeId {
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        (!value.is_empty() && value.len() <= CLUSTER_PEER_NODE_ID_MAX_BYTES)
            .then(|| Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-negative peer request issue time, in Unix seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PeerIssuedAtSecs(i64);

impl PeerIssuedAtSecs {
    #[must_use]
    pub fn new(secs: i64) -> Option<Self> {
        (secs >= 0).then_some(Self(secs))
    }

    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerReplayStoreError {
    Unavailable,
    IntegrityFailure,
    CapacityExhausted,
    NotAdvanced,
}

#[cfg(feature = "std")]
pub trait PeerReplayHighWaterStore: core::fmt::Debug + Send + Sync {
    fn high_waters(
        &self,
    ) -> Result<BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs>, PeerReplayStoreError>;

    /// Raise `node_id`'s mark atomically. Refuses with `NotAdvanced` unless
    /// `issued_at` is strictly above the stored mark, and with
    /// `CapacityExhausted` when a new peer would exceed the cap.
    fn advance(
        &self,
        node_id: &ClusterPeerNodeId,
        issued_at: PeerIssuedAtSecs,
    ) -> Result<(), PeerReplayStoreError>;
}
