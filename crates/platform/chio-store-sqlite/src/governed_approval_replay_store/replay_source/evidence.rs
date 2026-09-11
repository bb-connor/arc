//! SQLite-only live seal observations. Canonical migration data and configured
//! source I/O contracts are owned by the kernel, independent of this backend.

pub use chio_kernel::admission_operation::governed_approval_replay::{
    GovernedApprovalReplaySourceBinding, GovernedApprovalReplaySourceSnapshot,
};
pub(super) use chio_kernel::admission_operation::governed_approval_replay::{
    GovernedApprovalReplaySourceInventory as Inventory,
    GovernedApprovalReplaySourceMarker as Marker,
    MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_BYTES as MAX_BYTES,
    MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS as MAX_MARKERS,
};

/// A verified observation of a source's persisted seal. This is not operation
/// ownership. Importers must reverify the live source against an independently
/// pinned expectation. No public deserializer can manufacture this observation.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedApprovalReplaySourceSeal(pub(super) GovernedApprovalReplaySourceSnapshot);

impl std::fmt::Debug for GovernedApprovalReplaySourceSeal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("GovernedApprovalReplaySourceSeal")
            .field(&self.0)
            .finish()
    }
}

impl GovernedApprovalReplaySourceSeal {
    pub fn snapshot(&self) -> &GovernedApprovalReplaySourceSnapshot {
        &self.0
    }
    pub fn binding(&self) -> &GovernedApprovalReplaySourceBinding {
        self.0.binding()
    }
}
