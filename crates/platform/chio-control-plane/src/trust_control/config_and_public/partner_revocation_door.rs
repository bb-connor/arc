//! The partner revocation door every passport admission passes through.
//!
//! A door prepares before its acceptance instant: it re-reads the partner
//! registry, matches the presented passport to partners, and syncs every
//! matched mirror that is not fresh. That is the only network phase. The
//! door then admits at one acceptance instant sampled after the last network
//! wait, rechecking every matched mirror at that instant.
use super::*;

use chio_revocation_oracle::EpochRoot;
use chio_security_types::clock::Clock;

use crate::passport_revocation_mirror::{
    PartnerMirrorCache, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::revocation_partner::RevocationPartner;

/// How a stale partner mirror catches up with its partner's feed.
pub(crate) trait PartnerMirrorSync: Send + Sync {
    fn sync(
        &self,
        mirror: Arc<PartnerRevocationMirror>,
        partner: &RevocationPartner,
        clock: Arc<dyn Clock>,
    ) -> Result<EpochRoot, PartnerRevocationError>;
}

struct StrictPartnerMirrorSync;

impl PartnerMirrorSync for StrictPartnerMirrorSync {
    fn sync(
        &self,
        mirror: Arc<PartnerRevocationMirror>,
        partner: &RevocationPartner,
        clock: Arc<dyn Clock>,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        sync_partner_revocation_mirror(mirror, partner.clone(), clock)
    }
}

/// The long-lived partner mirror handles and the transport that syncs them.
pub(crate) struct PartnerRevocationDoor {
    mirrors: PartnerMirrorCache,
    sync: Arc<dyn PartnerMirrorSync>,
}

impl PartnerRevocationDoor {
    /// A door that syncs only over the strict partner feed transport.
    pub(crate) fn strict() -> Self {
        Self::with_sync(Arc::new(StrictPartnerMirrorSync))
    }

    pub(crate) fn with_sync(sync: Arc<dyn PartnerMirrorSync>) -> Self {
        Self {
            mirrors: PartnerMirrorCache::default(),
            sync,
        }
    }
}
