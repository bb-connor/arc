//! One-way retirement of an actual process-local replay cache.
//!
//! A seal covers only this cache instance's retained history. It cannot prove
//! continuity with a prior process, another writer, or an earlier authority.
//! Importers must pin the expected instance before retirement and verify the
//! live source separately from decoding its data. Losing the source requires
//! refusal or an independently authenticated authority transition, never an
//! empty replacement cache. No durable import or operation custody is granted.

use std::sync::MutexGuard;

use super::*;
use crate::admission_operation::AdmissionIdentifier;

mod snapshot;
use snapshot::{Body, Inventory};
pub use snapshot::{
    DpopReplaySourceMarker, DpopReplaySourceRetention, DpopReplaySourceSnapshot,
    MAX_DPOP_REPLAY_SOURCE_BYTES, MAX_DPOP_REPLAY_SOURCE_MARKERS,
};

/// Operator-selected namespaces, not proof of authority creation or rekeying.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopReplaySourceBinding {
    pub dpop_authority_id: AdmissionIdentifier,
    pub destination_authority_id: AdmissionIdentifier,
}

/// Live source I/O. A public implementation does not qualify a backend.
/// Callbacks must not run under a destination transaction or coordinator lock.
pub trait DpopReplaySourcePort: Send + Sync {
    fn preview_unsealed(
        &self,
        binding: &DpopReplaySourceBinding,
    ) -> Result<DpopReplaySourceSnapshot, KernelError>;
    fn seal_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError>;
    fn verify_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError>;
}

pub(super) struct SourceState {
    instance_id: uuid::Uuid,
    created_wall: SystemTime,
    monotonic_origin: Instant,
    revision: u64,
    pruned_through: Option<SystemTime>,
    sealed: Option<DpopReplaySourceSnapshot>,
}

impl SourceState {
    pub(super) fn new() -> Self {
        Self {
            instance_id: uuid::Uuid::now_v7(),
            created_wall: SystemTime::now(),
            monotonic_origin: Instant::now(),
            revision: 0,
            pruned_through: None,
            sealed: None,
        }
    }

    pub(super) fn begin_mutation(&mut self) -> Result<(), KernelError> {
        self.ensure_unsealed()?;
        // Even a failed attempt can update replay-clock state. Advancing before
        // mutation also detects an insert/rollback cycle between preview/seal.
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("source revision exhausted"))?;
        Ok(())
    }

    fn ensure_unsealed(&self) -> Result<(), KernelError> {
        if self.sealed.is_some() {
            return Err(invalid(
                "source is retired; legacy replay mutations are forbidden",
            ));
        }
        Ok(())
    }

    pub(super) fn note_pruned(&mut self, high_water: SystemTime) {
        self.pruned_through = Some(
            self.pruned_through
                .map_or(high_water, |old| old.max(high_water)),
        );
    }
}

impl DpopNonceStore {
    /// Read-only serving check. This neither reserves a nonce nor proves that
    /// it is unused. An error denies preparation before another participant
    /// can consume anything on behalf of the retired source.
    pub(crate) fn ensure_accepting_proofs(&self) -> Result<(), KernelError> {
        self.source_lock()?.source.ensure_unsealed()
    }

    fn source_lock(&self) -> Result<MutexGuard<'_, DpopNonceState>, KernelError> {
        self.inner
            .lock()
            .map_err(|_| invalid("source mutex poisoned"))
    }

    fn source_snapshot(
        &self,
        state: &DpopNonceState,
        binding: &DpopReplaySourceBinding,
    ) -> Result<DpopReplaySourceSnapshot, KernelError> {
        if state.cache.len() > MAX_DPOP_REPLAY_SOURCE_MARKERS {
            return Err(invalid("source exceeds migration marker bound"));
        }
        let mut markers = Vec::with_capacity(state.cache.len());
        let mut marker_bytes = 0_usize;
        for ((nonce, capability_id), entry) in state.cache.iter() {
            for part in [
                Some(nonce),
                Some(capability_id),
                entry.dispatch_reservation_id.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if part.len() > snapshot::MAX_KEY_BYTES {
                    return Err(invalid("marker identity exceeds migration byte bound"));
                }
            }
            let deadline = |value: Option<Instant>| {
                value
                    .map(|value| relative_ns(value, state.source.monotonic_origin))
                    .transpose()
            };
            let retention = match entry.retention {
                ReplayRetention::Local { monotonic_deadline } => DpopReplaySourceRetention::Local {
                    monotonic_deadline_offset_ns: deadline(monotonic_deadline)?,
                },
                ReplayRetention::Signed {
                    absolute_deadline,
                    monotonic_deadline,
                } => DpopReplaySourceRetention::Signed {
                    exclusive_unix_ns: absolute_deadline.map(unix_ns).transpose()?,
                    monotonic_deadline_offset_ns: deadline(monotonic_deadline)?,
                },
            };
            let marker = DpopReplaySourceMarker {
                nonce: nonce.clone(),
                capability_id: capability_id.clone(),
                dispatch_reservation_id: entry.dispatch_reservation_id.clone(),
                retention,
            };
            marker_bytes = marker_bytes
                .checked_add(
                    canonical_json_bytes(&marker)
                        .map_err(|_| invalid("marker encoding failed"))?
                        .len(),
                )
                .ok_or_else(|| invalid("inventory byte count overflow"))?;
            if marker_bytes > MAX_DPOP_REPLAY_SOURCE_BYTES {
                return Err(invalid("inventory exceeds migration byte bound"));
            }
            markers.push(marker);
        }
        markers.sort_by(|a, b| a.key().cmp(&b.key()));
        DpopReplaySourceSnapshot::new(Body {
            schema: snapshot::SCHEMA.to_owned(),
            binding: binding.clone(),
            instance_id: state.source.instance_id.to_string(),
            inventory: Inventory {
                created_unix_ns: unix_ns(state.source.created_wall)?,
                revision: state.source.revision.to_string(),
                wall_clock_high_water_unix_ns: unix_ns(state.wall_clock_high_water)?,
                monotonic_high_water_offset_ns: relative_ns(
                    state.monotonic_high_water,
                    state.source.monotonic_origin,
                )?,
                pruned_through_unix_ns: state.source.pruned_through.map(unix_ns).transpose()?,
                capacity: state.cache.cap().get().to_string(),
                per_capability_capacity: state.per_capability_capacity.to_string(),
                identity_byte_capacity: state.identity_byte_capacity.to_string(),
                charged_identity_bytes: state.identity_bytes.to_string(),
                fallback_ttl_ns: self.ttl.as_nanos().to_string(),
                markers,
            },
        })
    }
}

impl DpopReplaySourcePort for DpopNonceStore {
    fn preview_unsealed(
        &self,
        binding: &DpopReplaySourceBinding,
    ) -> Result<DpopReplaySourceSnapshot, KernelError> {
        let state = self.source_lock()?;
        state.source.ensure_unsealed()?;
        validate_clock(&state)?;
        self.source_snapshot(&state, binding)
    }

    fn seal_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError> {
        let mut state = self.source_lock()?;
        let current = self.source_snapshot(&state, expected.binding())?;
        if &current != expected {
            return Err(invalid(
                "source no longer matches the pinned instance and inventory",
            ));
        }
        if let Some(sealed) = &state.source.sealed {
            return if sealed == expected {
                Ok(())
            } else {
                Err(invalid(
                    "source is sealed for a different destination or inventory",
                ))
            };
        }
        validate_clock(&state)?;
        // The same mutex protects every legacy insertion, reservation and
        // rollback. No mutation can cross the exact comparison/seal boundary.
        state.source.sealed = Some(expected.clone());
        Ok(())
    }

    fn verify_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError> {
        let state = self.source_lock()?;
        if state.source.sealed.as_ref() != Some(expected)
            || self.source_snapshot(&state, expected.binding())? != *expected
        {
            return Err(invalid(
                "live source seal or retained inventory does not match",
            ));
        }
        Ok(())
    }
}

fn validate_clock(state: &DpopNonceState) -> Result<(), KernelError> {
    if state.pending_clock_rebaseline.is_some() {
        return Err(invalid("source replay clock is awaiting rebaseline"));
    }
    // Preview and seal are not replay-clock maintenance. Validate a copy and
    // refuse anomalies without pruning, advancing or repairing the source.
    let (mut wall, mut monotonic, mut pending) = (
        state.wall_clock_high_water,
        state.monotonic_high_water,
        None,
    );
    advance_replay_clock(
        "dpop_nonce",
        &mut wall,
        &mut monotonic,
        &mut pending,
        SystemTime::now(),
        Instant::now(),
    )?;
    Ok(())
}

fn unix_ns(value: SystemTime) -> Result<String, KernelError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos().to_string())
        .map_err(|_| invalid("source contains a pre-epoch replay deadline"))
}

fn relative_ns(value: Instant, origin: Instant) -> Result<String, KernelError> {
    let (duration, negative) = if value >= origin {
        (value.duration_since(origin), false)
    } else {
        (origin.duration_since(value), true)
    };
    let offset = i128::try_from(duration.as_nanos())
        .map_err(|_| invalid("source monotonic offset overflow"))?;
    Ok(if negative { -offset } else { offset }.to_string())
}

fn invalid(message: impl Into<String>) -> KernelError {
    KernelError::DpopVerificationFailed(format!("DPoP replay source: {}", message.into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
