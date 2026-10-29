//! Commits the field values of a signed metadata projection, or checks a projection against
//! held openings.
//!
//! One build function serves both directions. In project mode the committer draws a salt
//! per committed field from the `Rng` seam and keeps the openings. In verify mode it rebuilds
//! each commitment from the held opening, refusing an opening whose value is not the field
//! value; the caller compares the rebuilt projection with the signed one and calls `finish`,
//! which refuses any held opening the projection never committed.

use alloc::collections::BTreeSet;

use crate::receipt::metadata::{
    MetadataCommitment, MetadataCommitmentError, MetadataOpening, MetadataOpenings, MetadataValue,
};
use crate::rng::Rng;
use crate::root_authority::SaltRef;

enum Mode<'a> {
    Project {
        rng: &'a dyn Rng,
        openings: MetadataOpenings,
    },
    Verify {
        openings: &'a MetadataOpenings,
        used: BTreeSet<SaltRef>,
    },
}

/// The commitments of one projection build or check.
pub struct MetadataCommitter<'a> {
    mode: Mode<'a>,
}

impl<'a> MetadataCommitter<'a> {
    /// Builds commitments with salts drawn from `rng`.
    #[must_use]
    pub fn project(rng: &'a dyn Rng) -> Self {
        Self {
            mode: Mode::Project {
                rng,
                openings: MetadataOpenings::new(),
            },
        }
    }

    /// Rebuilds commitments from `openings`.
    #[must_use]
    pub fn verify(openings: &'a MetadataOpenings) -> Self {
        Self {
            mode: Mode::Verify {
                openings,
                used: BTreeSet::new(),
            },
        }
    }

    /// The commitment of `value` under `salt_ref`. A `salt_ref` committed twice yields one
    /// commitment and refuses a second, different value.
    pub fn commit<T: serde::Serialize>(
        &mut self,
        salt_ref: SaltRef,
        value: &T,
    ) -> Result<MetadataCommitment, MetadataCommitmentError> {
        let value = MetadataValue::from_json(value)?;
        match &mut self.mode {
            Mode::Project { rng, openings } => match openings.get(&salt_ref) {
                Some(held) => commit_held(salt_ref, held, &value),
                None => openings.commit_value(salt_ref, value, *rng),
            },
            Mode::Verify { openings, used } => match openings.get(&salt_ref) {
                Some(held) => {
                    used.insert(salt_ref.clone());
                    commit_held(salt_ref, held, &value)
                }
                None => Err(MetadataCommitmentError::OpeningUnavailable { salt_ref }),
            },
        }
    }

    /// Ends a verify-mode check: the set of `salt_ref`s the projection committed must equal
    /// the set of held openings, so an opening the projection never uses refuses. A
    /// project-mode build always finishes.
    pub fn finish(&self) -> Result<(), MetadataCommitmentError> {
        match &self.mode {
            Mode::Project { .. } => Ok(()),
            Mode::Verify { openings, used } => match openings
                .iter()
                .map(|(salt_ref, _)| salt_ref)
                .find(|salt_ref| !used.contains(*salt_ref))
            {
                Some(salt_ref) => Err(MetadataCommitmentError::UnusedOpening {
                    salt_ref: salt_ref.clone(),
                }),
                None => Ok(()),
            },
        }
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
) -> Result<MetadataCommitment, MetadataCommitmentError> {
    if held.value != *value {
        return Err(MetadataCommitmentError::MetadataCommitmentMismatch { salt_ref });
    }
    MetadataCommitment::compute(salt_ref, held)
}
