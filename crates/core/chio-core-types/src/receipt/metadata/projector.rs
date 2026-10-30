//! Builds and checks signed metadata projections that also carry keyed values: each raw
//! identifier becomes a `MetadataCommitment` through the receipt's `MetadataCommitter`, and
//! each low-entropy digest a keyed value under the deployment's tenant index key set.
//!
//! A projector borrows the caller's committer, so every block of one receipt commits through
//! one committer and the caller calls `finish` once per receipt. Keyed values derive under
//! the active generation when building and under the generation the signed projection names
//! when checking.

use crate::receipt::metadata::{MetadataCommitment, MetadataCommitmentError, MetadataCommitter};
use crate::root_authority::{SaltRef, Sha256Digest};
use crate::tenant_index::{
    IndexDomain, KeyedIndexValue, TenantBinding, TenantBindingAlg, TenantBindingError,
    TenantIndexKeySet,
};

/// One block's view of a receipt projection build or check.
pub struct MetadataProjector<'a, 'o> {
    keys: &'a TenantIndexKeySet,
    key_id: Sha256Digest,
    committer: &'a mut MetadataCommitter<'o>,
}

impl<'a, 'o> MetadataProjector<'a, 'o> {
    /// Derives keyed values under the active generation of `keys`.
    #[must_use]
    pub fn active(keys: &'a TenantIndexKeySet, committer: &'a mut MetadataCommitter<'o>) -> Self {
        Self {
            keys,
            key_id: *keys.active_key_id(),
            committer,
        }
    }

    /// Derives keyed values under generation `key_id` of `keys`. An unknown `key_id` refuses.
    pub fn generation(
        keys: &'a TenantIndexKeySet,
        key_id: &Sha256Digest,
        committer: &'a mut MetadataCommitter<'o>,
    ) -> Result<Self, ProjectionError> {
        if !keys.key_ids().any(|loaded| loaded == key_id) {
            return Err(ProjectionError::Key(
                TenantBindingError::TenantIndexKeyUnknown { key_id: *key_id },
            ));
        }
        Ok(Self {
            keys,
            key_id: *key_id,
            committer,
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

    /// The keyed value of `domain || preimage` under the projector's generation.
    pub fn keyed(
        &self,
        domain: IndexDomain,
        preimage: &[u8],
    ) -> Result<KeyedIndexValue, ProjectionError> {
        Ok(self.keys.derive_in(&self.key_id, domain, preimage)?)
    }

    /// The tenant binding of `tenant_id` under the projector's generation.
    pub fn tenant_binding(&self, tenant_id: &str) -> Result<TenantBinding, ProjectionError> {
        let keyed = self.keyed(IndexDomain::TenantBinding, tenant_id.as_bytes())?;
        Ok(TenantBinding {
            alg: TenantBindingAlg::HkdfHmacSha256,
            key_id: keyed.key_id,
            value: keyed.value,
        })
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
