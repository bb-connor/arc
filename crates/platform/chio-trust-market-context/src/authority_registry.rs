//! RR2-TM-01 market-authority registry resolver.
//!
//! The trust-market market-authority registry (RR2-TM-01) is the externally
//! pinned source of truth for the trusted-kernel-key set that signs commerce
//! receipts and claims. The same pinned set is the provenance for the Pass
//! `accepted_kernel_keys`: that allowlist is NOT ad-hoc caller configuration, it
//! is whatever this registry pins for the active rotation epoch.
//!
//! Membership rotates per epoch, so the registry is modelled as an ordered set of
//! rotation epochs, each carrying the kernel-key set trusted while that epoch is
//! the active rotation. Resolution reads only the active epoch's set, so a key
//! rotated out in a later epoch is no longer trusted. Every step is fail-closed:
//! an empty registry, an empty epoch key set, a duplicate or non-ascending epoch,
//! and an unknown active epoch are all rejected rather than defaulted.

use std::error::Error;
use std::fmt;

use chio_core_types::PublicKey;

/// Canonical identifier of the externally pinned trust-market market-authority
/// registry this resolver reads.
///
/// The Pass `accepted_kernel_keys` provenance and the commerce-proof
/// market-authority trust roots are both pinned to this registry rather than to
/// ad-hoc caller configuration.
pub const RR2_TM_01_REGISTRY_REF: &str = "RR2-TM-01";

/// One rotation epoch in the RR2-TM-01 registry: the kernel-key set trusted while
/// that epoch is the active rotation.
#[derive(Debug, Clone)]
pub struct MarketAuthorityRotationEpoch {
    epoch: u64,
    kernel_keys: Vec<PublicKey>,
}

impl MarketAuthorityRotationEpoch {
    /// Pin one rotation epoch to its kernel-key set.
    #[must_use]
    pub fn new(epoch: u64, kernel_keys: Vec<PublicKey>) -> Self {
        Self { epoch, kernel_keys }
    }

    /// The rotation epoch number (monotonic across the registry).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The kernel keys trusted while this epoch is the active rotation.
    #[must_use]
    pub fn kernel_keys(&self) -> &[PublicKey] {
        &self.kernel_keys
    }
}

/// The externally pinned RR2-TM-01 market-authority registry.
///
/// Rotation epochs are held in strictly ascending order; each epoch carries the
/// kernel-key set trusted while that epoch is the active rotation. Build the
/// registry fail-closed with [`MarketAuthorityRegistry::pin`], then resolve the
/// active epoch's set with [`MarketAuthorityRegistry::resolve_kernel_keys`].
#[derive(Debug, Clone)]
pub struct MarketAuthorityRegistry {
    epochs: Vec<MarketAuthorityRotationEpoch>,
}

impl MarketAuthorityRegistry {
    /// Pin the registry from externally loaded rotation epochs.
    ///
    /// # Errors
    ///
    /// Fails closed when the registry pins no epoch, when an epoch pins no kernel
    /// key (which would silently force every commerce proof untrusted), when an
    /// epoch repeats a kernel key, or when the epochs are not strictly ascending
    /// (which would make the rotation order ambiguous).
    pub fn pin(
        epochs: Vec<MarketAuthorityRotationEpoch>,
    ) -> Result<Self, MarketAuthorityRegistryError> {
        if epochs.is_empty() {
            return Err(MarketAuthorityRegistryError::EmptyRegistry);
        }
        let mut previous: Option<u64> = None;
        for epoch in &epochs {
            if let Some(previous_epoch) = previous {
                if epoch.epoch <= previous_epoch {
                    return Err(MarketAuthorityRegistryError::NonAscendingEpochs {
                        previous: previous_epoch,
                        found: epoch.epoch,
                    });
                }
            }
            previous = Some(epoch.epoch);
            if epoch.kernel_keys.is_empty() {
                return Err(MarketAuthorityRegistryError::EmptyEpochKeySet { epoch: epoch.epoch });
            }
            for (index, key) in epoch.kernel_keys.iter().enumerate() {
                if epoch
                    .kernel_keys
                    .iter()
                    .take(index)
                    .any(|earlier| earlier == key)
                {
                    return Err(MarketAuthorityRegistryError::DuplicateKernelKey {
                        epoch: epoch.epoch,
                    });
                }
            }
        }
        Ok(Self { epochs })
    }

    /// The pinned registry identifier (always [`RR2_TM_01_REGISTRY_REF`]).
    #[must_use]
    pub fn registry_ref(&self) -> &'static str {
        RR2_TM_01_REGISTRY_REF
    }

    /// The rotation epochs in strictly ascending order.
    #[must_use]
    pub fn epochs(&self) -> &[MarketAuthorityRotationEpoch] {
        &self.epochs
    }

    /// The newest pinned rotation epoch number.
    ///
    /// [`Self::pin`] guarantees at least one epoch, so this is the highest epoch
    /// number in the registry; the `0` fallback is unreachable for a pinned
    /// registry and only guards against an empty epoch slice.
    #[must_use]
    pub fn latest_epoch(&self) -> u64 {
        self.epochs
            .last()
            .map(MarketAuthorityRotationEpoch::epoch)
            .unwrap_or(0)
    }

    /// Resolve the pinned kernel-key set trusted at `active_epoch`.
    ///
    /// Returns a clone of the active epoch's kernel keys. This set is the sole
    /// provenance for the Pass `accepted_kernel_keys` and the commerce-proof
    /// market-authority trust roots.
    ///
    /// # Errors
    ///
    /// Fails closed when `active_epoch` is not pinned in the registry; the
    /// resolver never falls back to a neighbouring epoch.
    pub fn resolve_kernel_keys(
        &self,
        active_epoch: u64,
    ) -> Result<Vec<PublicKey>, MarketAuthorityRegistryError> {
        self.epochs
            .iter()
            .find(|epoch| epoch.epoch == active_epoch)
            .map(|epoch| epoch.kernel_keys.clone())
            .ok_or(MarketAuthorityRegistryError::UnknownActiveEpoch { active_epoch })
    }
}

/// Resolve the RR2-TM-01 pinned market-authority kernel-key set for the active
/// rotation epoch.
///
/// This is the entry point the CLI and control-plane call to source the Pass
/// `accepted_kernel_keys` provenance and the commerce-proof market-authority
/// trust roots from the externally pinned registry, with rotation honoured. The
/// caller supplies the registry it loaded fail-closed and the rotation epoch it
/// considers active; this resolver yields exactly the pinned set for that epoch.
///
/// # Errors
///
/// Propagates [`MarketAuthorityRegistry::resolve_kernel_keys`] fail-closed
/// errors.
pub fn resolve_rr2_tm_01_kernel_keys(
    registry: &MarketAuthorityRegistry,
    active_epoch: u64,
) -> Result<Vec<PublicKey>, MarketAuthorityRegistryError> {
    registry.resolve_kernel_keys(active_epoch)
}

/// Fail-closed errors raised while pinning or resolving the RR2-TM-01 registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketAuthorityRegistryError {
    /// The registry pinned no rotation epoch.
    EmptyRegistry,
    /// A rotation epoch pinned no kernel key.
    EmptyEpochKeySet {
        /// The offending epoch number.
        epoch: u64,
    },
    /// A rotation epoch repeated a kernel key.
    DuplicateKernelKey {
        /// The offending epoch number.
        epoch: u64,
    },
    /// The rotation epochs were not strictly ascending.
    NonAscendingEpochs {
        /// The previous epoch number seen.
        previous: u64,
        /// The non-ascending epoch number that followed it.
        found: u64,
    },
    /// The requested active epoch is not pinned in the registry.
    UnknownActiveEpoch {
        /// The active epoch the caller asked to resolve.
        active_epoch: u64,
    },
}

impl fmt::Display for MarketAuthorityRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRegistry => write!(
                formatter,
                "RR2-TM-01 market-authority registry pins no rotation epoch"
            ),
            Self::EmptyEpochKeySet { epoch } => write!(
                formatter,
                "RR2-TM-01 rotation epoch {epoch} pins no market-authority kernel key"
            ),
            Self::DuplicateKernelKey { epoch } => write!(
                formatter,
                "RR2-TM-01 rotation epoch {epoch} repeats a market-authority kernel key"
            ),
            Self::NonAscendingEpochs { previous, found } => write!(
                formatter,
                "RR2-TM-01 rotation epochs must strictly ascend: {found} follows {previous}"
            ),
            Self::UnknownActiveEpoch { active_epoch } => write!(
                formatter,
                "RR2-TM-01 active rotation epoch {active_epoch} is not pinned in the registry"
            ),
        }
    }
}

impl Error for MarketAuthorityRegistryError {}
