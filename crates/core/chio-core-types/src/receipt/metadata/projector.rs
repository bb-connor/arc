//! Builds and checks signed metadata projections that also carry keyed values: each raw
//! identifier becomes a `MetadataCommitment` through a `MetadataCommitter`, and each
//! low-entropy digest a keyed value under the deployment's tenant index key set.
//!
//! In project mode keyed values derive under the active generation; in verify mode under the
//! generation the projection names. The caller compares the rebuilt projection with the
//! signed one and calls `finish`.

use crate::receipt::metadata::{
    MetadataCommitment, MetadataCommitmentError, MetadataCommitter, MetadataOpenings,
};
use crate::rng::Rng;
use crate::root_authority::{SaltRef, Sha256Digest};
use crate::tenant_index::{
    IndexDomain, KeyedIndexValue, TenantBinding, TenantBindingAlg, TenantBindingError,
    TenantIndexKeySet,
};

/// The state of one projection build or check.
pub struct MetadataProjector<'a> {
    keys: &'a TenantIndexKeySet,
    key_id: Sha256Digest,
    committer: MetadataCommitter<'a>,
}

impl<'a> MetadataProjector<'a> {
    /// Builds a projection under the active generation of `keys`.
    #[must_use]
    pub fn project(keys: &'a TenantIndexKeySet, rng: &'a dyn Rng) -> Self {
        Self {
            keys,
            key_id: *keys.active_key_id(),
            committer: MetadataCommitter::project(rng),
        }
    }

    /// Rebuilds a projection signed under generation `key_id` from `openings`. An unknown
    /// `key_id` refuses.
    pub fn verify(
        keys: &'a TenantIndexKeySet,
        key_id: &Sha256Digest,
        openings: &'a MetadataOpenings,
    ) -> Result<Self, ProjectionError> {
        if !keys.key_ids().any(|loaded| loaded == key_id) {
            return Err(ProjectionError::Key(
                TenantBindingError::TenantIndexKeyUnknown { key_id: *key_id },
            ));
        }
        Ok(Self {
            keys,
            key_id: *key_id,
            committer: MetadataCommitter::verify(openings),
        })
    }

    /// The commitment of `value` under `salt_ref`; see `MetadataCommitter::commit`.
    pub fn commit<T: serde::Serialize>(
        &mut self,
        salt_ref: SaltRef,
        value: &T,
    ) -> Result<MetadataCommitment, ProjectionError> {
        Ok(self.committer.commit(salt_ref, value)?)
    }

    /// The keyed value of `domain || preimage` under the projection's generation.
    pub fn keyed(
        &self,
        domain: IndexDomain,
        preimage: &[u8],
    ) -> Result<KeyedIndexValue, ProjectionError> {
        Ok(self.keys.derive_in(&self.key_id, domain, preimage)?)
    }

    /// The tenant binding of `tenant_id` under the projection's generation.
    pub fn tenant_binding(&self, tenant_id: &str) -> Result<TenantBinding, ProjectionError> {
        let keyed = self.keyed(IndexDomain::TenantBinding, tenant_id.as_bytes())?;
        Ok(TenantBinding {
            alg: TenantBindingAlg::HkdfHmacSha256,
            key_id: keyed.key_id,
            value: keyed.value,
        })
    }

    /// Ends a verify-mode check; see `MetadataCommitter::finish`.
    pub fn finish(&self) -> Result<(), ProjectionError> {
        Ok(self.committer.finish()?)
    }

    /// The openings a project-mode build drew. A verify-mode check draws none.
    #[must_use]
    pub fn into_openings(self) -> MetadataOpenings {
        self.committer.into_openings()
    }
}

/// Why a projection cannot be built or checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Metadata(MetadataCommitmentError),
    Key(TenantBindingError),
}

impl From<MetadataCommitmentError> for ProjectionError {
    fn from(error: MetadataCommitmentError) -> Self {
        Self::Metadata(error)
    }
}

impl From<TenantBindingError> for ProjectionError {
    fn from(error: TenantBindingError) -> Self {
        Self::Key(error)
    }
}

impl core::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Metadata(error) => write!(formatter, "metadata projection refused: {error}"),
            Self::Key(error) => write!(formatter, "metadata projection key refused: {error}"),
        }
    }
}

impl core::error::Error for ProjectionError {}
