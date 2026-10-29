//! Builds and checks signed metadata projections: each raw identifier becomes a
//! `MetadataCommitment` and each low-entropy digest a keyed value under the deployment's
//! tenant index key set.
//!
//! One projection function serves both directions. In project mode the projector draws a
//! salt per committed field and derives keyed values under the active generation. In verify
//! mode it rebuilds each commitment from the held opening, refusing an opening whose value
//! is not the raw field value, and derives keyed values under the generation the projection
//! names; the caller compares the rebuilt projection with the signed one.

use crate::receipt::metadata::{
    MetadataCommitment, MetadataCommitmentError, MetadataOpening, MetadataOpenings, MetadataValue,
};
use crate::rng::Rng;
use crate::root_authority::{SaltRef, Sha256Digest};
use crate::tenant_index::{
    IndexDomain, KeyedIndexValue, TenantBinding, TenantBindingAlg, TenantBindingError,
    TenantIndexKeySet,
};

enum Mode<'a> {
    Project {
        rng: &'a dyn Rng,
        openings: MetadataOpenings,
    },
    Verify {
        openings: &'a MetadataOpenings,
    },
}

/// The state of one projection build or check.
pub struct MetadataProjector<'a> {
    keys: &'a TenantIndexKeySet,
    key_id: Sha256Digest,
    mode: Mode<'a>,
}

impl<'a> MetadataProjector<'a> {
    /// Builds a projection under the active generation of `keys`.
    #[must_use]
    pub fn project(keys: &'a TenantIndexKeySet, rng: &'a dyn Rng) -> Self {
        Self {
            keys,
            key_id: *keys.active_key_id(),
            mode: Mode::Project {
                rng,
                openings: MetadataOpenings::new(),
            },
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
            mode: Mode::Verify { openings },
        })
    }

    /// The commitment of `value` under `salt_ref`. A `salt_ref` committed twice in one
    /// projection yields one commitment and refuses a second, different value.
    pub fn commit<T: serde::Serialize>(
        &mut self,
        salt_ref: SaltRef,
        value: &T,
    ) -> Result<MetadataCommitment, ProjectionError> {
        let value = MetadataValue::from_json(value)?;
        match &mut self.mode {
            Mode::Project { rng, openings } => match openings.get(&salt_ref) {
                Some(held) => commit_held(salt_ref, held, &value),
                None => {
                    let commitment = openings.commit_value(salt_ref, value, *rng)?;
                    Ok(commitment)
                }
            },
            Mode::Verify { openings } => match openings.get(&salt_ref) {
                Some(held) => commit_held(salt_ref, held, &value),
                None => Err(MetadataCommitmentError::OpeningUnavailable { salt_ref }.into()),
            },
        }
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

    /// The openings a project-mode build drew. A verify-mode check draws none.
    #[must_use]
    pub fn into_openings(self) -> MetadataOpenings {
        match self.mode {
            Mode::Project { openings, .. } => openings,
            Mode::Verify { .. } => MetadataOpenings::new(),
        }
    }
}

fn commit_held(
    salt_ref: SaltRef,
    held: &MetadataOpening,
    value: &MetadataValue,
) -> Result<MetadataCommitment, ProjectionError> {
    if held.value != *value {
        return Err(MetadataCommitmentError::MetadataCommitmentMismatch { salt_ref }.into());
    }
    Ok(MetadataCommitment::compute(salt_ref, held)?)
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
