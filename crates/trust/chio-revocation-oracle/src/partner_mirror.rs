//! History rules for a mirror of a federation partner's revocation tree.
//!
//! A mirror accepts a partner's signed root only as a forward step from the
//! root it accepted last, and only when the leaves it replays rebuild that
//! root. A root that contradicts the accepted history is a conflict the mirror
//! records, up to [`MAX_RECORDED_PARTNER_CONFLICTS`].

use crate::{EpochRoot, SignedEpochRoot};

/// Most distinct conflicting roots one mirror records.
pub const MAX_RECORDED_PARTNER_CONFLICTS: u64 = 256;

/// Why a mirror refused a partner root or its leaves. Every refusal leaves the
/// mirror unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartnerMirrorRefusal {
    #[error("revocation mirror tree does not match its accepted root")]
    Diverged,
    #[error("revocation root epoch {offered} rolls back accepted epoch {accepted}")]
    Rollback { accepted: u64, offered: u64 },
    #[error("revocation root issued at {offered} predates the accepted root issued at {accepted}")]
    AttestationRollback { accepted: u64, offered: u64 },
    #[error("signed two different revocation roots for epoch {epoch}")]
    Equivocation { epoch: u64 },
    #[error("revocation leaf {seq} does not follow mirror leaf {have}")]
    OutOfSequence { seq: u64, have: u64 },
    #[error("revocation leaf {seq} is not a valid revocation key: {reason}")]
    InvalidLeaf { seq: u64, reason: String },
    #[error("revocation leaf {seq} repeats a revoked key")]
    DuplicateLeaf { seq: u64 },
    #[error("revocation leaves rebuild a root that differs from the signed root at epoch {epoch}")]
    RootMismatch { epoch: u64 },
}

impl PartnerMirrorRefusal {
    /// Whether the refused root contradicts the accepted history, as opposed
    /// to arriving with leaves the mirror cannot apply.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::Rollback { .. }
                | Self::AttestationRollback { .. }
                | Self::Equivocation { .. }
                | Self::RootMismatch { .. }
        )
    }
}

/// Refuses `offered` unless it moves forward from `accepted`: no older epoch,
/// no second tree for the accepted epoch, and no older attestation.
pub fn check_history(
    accepted: &EpochRoot,
    offered: &EpochRoot,
) -> Result<(), PartnerMirrorRefusal> {
    if offered.epoch < accepted.epoch {
        return Err(PartnerMirrorRefusal::Rollback {
            accepted: accepted.epoch,
            offered: offered.epoch,
        });
    }
    if offered.epoch == accepted.epoch && !offered.same_tree(accepted) {
        return Err(PartnerMirrorRefusal::Equivocation {
            epoch: offered.epoch,
        });
    }
    if offered.issued_at_unix_ms < accepted.issued_at_unix_ms {
        return Err(PartnerMirrorRefusal::AttestationRollback {
            accepted: accepted.issued_at_unix_ms,
            offered: offered.issued_at_unix_ms,
        });
    }
    Ok(())
}

/// A partner root that contradicted the mirror's accepted history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerMirrorConflict {
    pub observed_at_unix_ms: u64,
    pub reason: String,
    pub accepted_root: Option<SignedEpochRoot>,
    pub offered_root: SignedEpochRoot,
}

/// Outcome of recording a conflicting root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictRecord {
    Recorded,
    AlreadyRecorded,
    /// The mirror already holds [`MAX_RECORDED_PARTNER_CONFLICTS`] other
    /// conflicts; nothing was written.
    LogFull,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(epoch: u64, hash: u8, leaf_count: usize, issued_at_unix_ms: u64) -> EpochRoot {
        EpochRoot {
            epoch,
            root_hash: [hash; 32],
            leaf_count,
            issued_at_unix_ms,
        }
    }

    #[test]
    fn history_admits_forward_steps_and_reattestations() {
        let accepted = root(4, 1, 3, 100);
        assert_eq!(check_history(&accepted, &root(4, 1, 3, 100)), Ok(()));
        assert_eq!(check_history(&accepted, &root(4, 1, 3, 200)), Ok(()));
        assert_eq!(check_history(&accepted, &root(5, 2, 4, 100)), Ok(()));
    }

    #[test]
    fn history_refuses_rollback_equivocation_and_older_attestation() {
        let accepted = root(4, 1, 3, 100);
        assert_eq!(
            check_history(&accepted, &root(3, 1, 3, 200)),
            Err(PartnerMirrorRefusal::Rollback {
                accepted: 4,
                offered: 3
            })
        );
        for other in [root(4, 2, 3, 200), root(4, 1, 4, 200)] {
            assert_eq!(
                check_history(&accepted, &other),
                Err(PartnerMirrorRefusal::Equivocation { epoch: 4 })
            );
        }
        assert_eq!(
            check_history(&accepted, &root(5, 2, 4, 99)),
            Err(PartnerMirrorRefusal::AttestationRollback {
                accepted: 100,
                offered: 99
            })
        );
    }
}
