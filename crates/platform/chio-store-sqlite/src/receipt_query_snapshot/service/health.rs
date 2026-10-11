//! Sampled health telemetry. Public polling neither admits a receipt read nor
//! borrows a database connection. The walker owns sampling and its work budget.
use super::*;
use std::sync::TryLockError;

#[derive(Clone)]
pub(super) struct HealthSample {
    watermark: ReceiptSnapshotWatermark,
    quota_bytes: u64,
    used_bytes: u64,
    tool_receipts: u64,
    dimensions: u64,
    dimension_bytes: u64,
}

impl Published {
    /// Sample only on the walker, under its existing bounded hold. Publish all
    /// fields together so a public health read cannot mix generations.
    pub(super) fn refresh_health_sample(&self) -> Result<(), WalkError> {
        let sample = self.hold(|owned| {
            let (dimensions, dimension_bytes) = owned.db.dim_stats()?;
            Ok(HealthSample {
                watermark: self.watermark_of(&owned.meta),
                quota_bytes: owned.db.quota_bytes(),
                used_bytes: owned.db.used_bytes()?,
                tool_receipts: owned.db.tool_row_count()?,
                dimensions,
                dimension_bytes,
            })
        })?;
        *self.health_sample.lock().map_err(|_| {
            WalkError::Integrity("receipt snapshot health sample lock poisoned".into())
        })? = Some(sample);
        Ok(())
    }
}

impl ReceiptQuerySnapshots {
    /// Return the walker's most recent resource sample without waiting for a
    /// receipt read, database hold, filesystem operation, or another sampler.
    ///
    /// The watermark dates the sample. This is telemetry, not a fresh integrity
    /// inspection: query and point-read APIs still verify their own payloads,
    /// leases and freshness. [`Self::status`] remains an inspecting operator API.
    pub fn health_status(&self) -> ReceiptQuerySnapshotStatus {
        let phase = match self.inner.phase.try_lock() {
            Ok(phase) => phase.clone(),
            Err(TryLockError::WouldBlock) => {
                Phase::Unavailable("receipt snapshot health transition in progress".into())
            }
            Err(TryLockError::Poisoned(_)) => {
                Phase::Invalid("receipt query snapshot lock poisoned".into())
            }
        };
        let mut status = ReceiptQuerySnapshotStatus {
            state: match &phase {
                Phase::Waiting => ReceiptQuerySnapshotState::WaitingForWriterSeed,
                Phase::Building { done, total } => ReceiptQuerySnapshotState::Building {
                    authenticated_entries: *done,
                    target_entries: *total,
                },
                Phase::Ready(_) => ReceiptQuerySnapshotState::Ready,
                Phase::Invalid(reason) => ReceiptQuerySnapshotState::Invalid {
                    reason: reason.clone(),
                },
                Phase::Unavailable(reason) => ReceiptQuerySnapshotState::Unavailable {
                    reason: reason.clone(),
                },
                Phase::Stopped => ReceiptQuerySnapshotState::Stopped,
            },
            watermark: None,
            quota_bytes: self.inner.requested_quota(),
            used_bytes: 0,
            tool_receipts: 0,
            dimensions: 0,
            dimension_bytes: 0,
            last_recertification_ms: match self.inner.last_recertification_ms.load(Ordering::SeqCst)
            {
                0 => None,
                value => Some(value),
            },
        };
        if let Phase::Ready(published) = phase {
            match published.health_sample.try_lock() {
                Ok(sample) => match sample.as_ref() {
                    Some(sample) => {
                        status.watermark = Some(sample.watermark.clone());
                        status.quota_bytes = sample.quota_bytes;
                        status.used_bytes = sample.used_bytes;
                        status.tool_receipts = sample.tool_receipts;
                        status.dimensions = sample.dimensions;
                        status.dimension_bytes = sample.dimension_bytes;
                    }
                    None => {
                        status.state = ReceiptQuerySnapshotState::Unavailable {
                            reason: "receipt snapshot health sample not yet available".into(),
                        }
                    }
                },
                Err(TryLockError::WouldBlock) => {
                    status.state = ReceiptQuerySnapshotState::Unavailable {
                        reason: "receipt snapshot health sample update in progress".into(),
                    };
                }
                Err(TryLockError::Poisoned(_)) => {
                    status.state = ReceiptQuerySnapshotState::Invalid {
                        reason: "receipt snapshot health sample lock poisoned".into(),
                    };
                }
            }
        }
        status
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test fixtures fail on violated setup invariants."
)]
#[path = "health_tests.rs"]
mod tests;
