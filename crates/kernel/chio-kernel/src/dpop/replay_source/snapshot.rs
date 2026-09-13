//! Canonical source data. Monotonic offsets are relative to the live source
//! instance, not restart-portable deadlines. A destination must preserve both
//! clocks or retain a conservative blocker; it cannot expire a marker from its
//! absolute deadline alone or turn a local TTL into a signed validity window.

use std::collections::HashMap;

use chio_core::{canonical::canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::{invalid, DpopReplaySourceBinding, KernelError};

pub const MAX_DPOP_REPLAY_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DPOP_REPLAY_SOURCE_MARKERS: usize = 65_536;

/// Immutable configured replay limits, not current occupancy or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpopReplaySourceLimits {
    pub markers: u64,
    pub per_capability: u64,
    pub identity_bytes: u64,
}
pub(super) const MAX_KEY_BYTES: usize = crate::dpop::MAX_DPOP_REPLAY_IDENTITY_PART_BYTES;
pub(super) const SCHEMA: &str = "chio.dpop-replay-source-seal.v1";
const DOMAIN: &[u8] = b"chio:dpop-replay-source-inventory:v1\0";

/// Historical retention data, not an imported expiry or proof of freshness.
/// `None` retains indefinitely on that clock. Signed reclamation requires both
/// deadlines; local-only history has no signed absolute expiry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DpopReplaySourceRetention {
    Local {
        monotonic_deadline_offset_ns: Option<String>,
    },
    Signed {
        exclusive_unix_ns: Option<String>,
        monotonic_deadline_offset_ns: Option<String>,
    },
}

/// Private retained replay identity. Reservation text is historical data, not
/// permission to release, commit or reconstruct an operation-owned handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopReplaySourceMarker {
    pub nonce: String,
    pub capability_id: String,
    pub dispatch_reservation_id: Option<String>,
    pub retention: DpopReplaySourceRetention,
}

impl DpopReplaySourceMarker {
    pub(super) fn key(&self) -> (&str, &str) {
        (&self.capability_id, &self.nonce)
    }

    fn validate(&self) -> Result<(), KernelError> {
        for part in [
            Some(&self.nonce),
            Some(&self.capability_id),
            self.dispatch_reservation_id.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if part.len() > MAX_KEY_BYTES {
                return Err(invalid("marker identity exceeds byte bound"));
            }
        }
        match &self.retention {
            DpopReplaySourceRetention::Local {
                monotonic_deadline_offset_ns,
            } => {
                monotonic_deadline_offset_ns
                    .as_deref()
                    .map(signed)
                    .transpose()?;
            }
            DpopReplaySourceRetention::Signed {
                exclusive_unix_ns,
                monotonic_deadline_offset_ns,
            } => {
                exclusive_unix_ns.as_deref().map(unsigned).transpose()?;
                monotonic_deadline_offset_ns
                    .as_deref()
                    .map(signed)
                    .transpose()?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    pub created_unix_ns: String,
    pub revision: String,
    pub wall_clock_high_water_unix_ns: String,
    pub monotonic_high_water_offset_ns: String,
    pub pruned_through_unix_ns: Option<String>,
    pub capacity: String,
    pub per_capability_capacity: String,
    pub identity_byte_capacity: String,
    pub charged_identity_bytes: String,
    pub fallback_ttl_ns: String,
    pub markers: Vec<DpopReplaySourceMarker>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub schema: String,
    pub binding: DpopReplaySourceBinding,
    pub instance_id: String,
    pub inventory: Inventory,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: Body,
    inventory_sha256: String,
}

/// Bounded canonical data. Decoding does not prove live sealing, continuity
/// with a previous process, destination activation or execution permission.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopReplaySourceSnapshot(Envelope);

impl std::fmt::Debug for DpopReplaySourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopReplaySourceSnapshot")
            .field("instance_id", &self.instance_id())
            .field("marker_count", &self.markers().len())
            .field("inventory_sha256", &self.inventory_sha256())
            .finish_non_exhaustive()
    }
}

impl DpopReplaySourceSnapshot {
    pub fn replay_capacity_limits(&self) -> Result<DpopReplaySourceLimits, KernelError> {
        let inventory = &self.0.body.inventory;
        let bounded = |value: &str| -> Result<u64, KernelError> {
            u64::try_from(unsigned(value)?).map_err(|_| invalid("source capacity exceeds u64"))
        };
        Ok(DpopReplaySourceLimits {
            markers: bounded(&inventory.capacity)?,
            per_capability: bounded(&inventory.per_capability_capacity)?,
            identity_bytes: bounded(&inventory.identity_byte_capacity)?,
        })
    }
    pub fn binding(&self) -> &DpopReplaySourceBinding {
        &self.0.body.binding
    }
    pub fn instance_id(&self) -> &str {
        &self.0.body.instance_id
    }
    pub fn dpop_authority_id(&self) -> &str {
        self.binding().dpop_authority_id.as_str()
    }
    pub fn destination_authority_id(&self) -> &str {
        self.binding().destination_authority_id.as_str()
    }
    pub fn inventory_sha256(&self) -> &str {
        &self.0.inventory_sha256
    }
    pub fn markers(&self) -> &[DpopReplaySourceMarker] {
        &self.0.body.inventory.markers
    }

    /// Check a trusted destination clock before retiring the legacy domain.
    /// This does not translate monotonic deadlines or expire any marker.
    pub fn validate_transition_time(&self, authority_now_unix_ms: u64) -> Result<(), KernelError> {
        let high = unsigned(&self.0.body.inventory.wall_clock_high_water_unix_ns)?;
        let rounded = high
            .checked_add(999_999)
            .ok_or_else(|| invalid("source wall clock exceeds transition range"))?
            / 1_000_000;
        if u128::from(authority_now_unix_ms) < rounded {
            return Err(invalid(
                "destination clock precedes the retained source wall clock",
            ));
        }
        Ok(())
    }

    /// Private migration data. Never expose nonce identities or historical
    /// reservation IDs through receipts, diagnostics or agent-visible reports.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let bytes =
            canonical_json_bytes(&self.0).map_err(|_| invalid("snapshot encoding failed"))?;
        if bytes.len() > MAX_DPOP_REPLAY_SOURCE_BYTES {
            return Err(invalid("snapshot exceeds byte bound"));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, KernelError> {
        if bytes.is_empty() || bytes.len() > MAX_DPOP_REPLAY_SOURCE_BYTES {
            return Err(invalid("snapshot has invalid byte length"));
        }
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(|_| invalid("snapshot decoding failed"))?;
        envelope.body.validate()?;
        if digest(&envelope.body)? != envelope.inventory_sha256 {
            return Err(invalid("snapshot digest mismatch"));
        }
        let snapshot = Self(envelope);
        if snapshot.canonical_bytes()? != bytes {
            return Err(invalid("snapshot is not canonical"));
        }
        Ok(snapshot)
    }

    pub(super) fn new(body: Body) -> Result<Self, KernelError> {
        body.validate()?;
        let inventory_sha256 = digest(&body)?;
        let snapshot = Self(Envelope {
            body,
            inventory_sha256,
        });
        snapshot.canonical_bytes()?;
        Ok(snapshot)
    }
}

impl Body {
    fn validate(&self) -> Result<(), KernelError> {
        let instance = uuid::Uuid::parse_str(&self.instance_id)
            .map_err(|_| invalid("invalid source instance"))?;
        if self.schema != SCHEMA
            || instance.to_string() != self.instance_id
            || instance.get_version_num() != 7
        {
            return Err(invalid("unsupported source schema or instance encoding"));
        }
        let inventory = &self.inventory;
        let created = unsigned(&inventory.created_unix_ns)?;
        let high_water = unsigned(&inventory.wall_clock_high_water_unix_ns)?;
        if created > high_water {
            return Err(invalid("replay high-water precedes source creation"));
        }
        if inventory
            .pruned_through_unix_ns
            .as_deref()
            .map(unsigned)
            .transpose()?
            .is_some_and(|p| p > high_water)
        {
            return Err(invalid("prune horizon exceeds replay high-water"));
        }
        signed(&inventory.monotonic_high_water_offset_ns)?;
        u64::try_from(unsigned(&inventory.revision)?).map_err(|_| invalid("revision overflow"))?;
        unsigned(&inventory.fallback_ttl_ns)?;
        let capacity = unsigned(&inventory.capacity)?;
        let quota = unsigned(&inventory.per_capability_capacity)?;
        let byte_capacity = unsigned(&inventory.identity_byte_capacity)?;
        let charged_bytes = unsigned(&inventory.charged_identity_bytes)?;
        if byte_capacity == 0 || byte_capacity > u64::MAX.into() || charged_bytes > byte_capacity {
            return Err(invalid("invalid retained identity byte budget"));
        }
        if capacity == 0
            || capacity > u64::MAX.into()
            || quota == 0
            || quota > capacity
            || inventory.markers.len() > MAX_DPOP_REPLAY_SOURCE_MARKERS
            || inventory.markers.len() as u128 > capacity
        {
            return Err(invalid("invalid source capacity or marker count"));
        }
        let mut previous = None;
        let mut counts = HashMap::new();
        let mut actual_bytes = 0_u128;
        for marker in &inventory.markers {
            marker.validate()?;
            let bytes = crate::dpop::identity::retained_bytes(
                &marker.nonce,
                &marker.capability_id,
                marker.dispatch_reservation_id.as_deref(),
            )?;
            actual_bytes = actual_bytes
                .checked_add(bytes as u128)
                .ok_or_else(|| invalid("retained identity byte count overflow"))?;
            if previous.is_some_and(|key| key >= marker.key()) {
                return Err(invalid("source markers are not unique and sorted"));
            }
            previous = Some(marker.key());
            let count = counts.entry(&marker.capability_id).or_insert(0_u128);
            *count += 1;
            if *count > quota {
                return Err(invalid("source exceeds per-capability quota"));
            }
        }
        if actual_bytes != charged_bytes {
            return Err(invalid("retained identity byte accounting mismatch"));
        }
        Ok(())
    }
}

fn digest(body: &Body) -> Result<String, KernelError> {
    let encoded = canonical_json_bytes(body).map_err(|_| invalid("inventory encoding failed"))?;
    if encoded.len() > MAX_DPOP_REPLAY_SOURCE_BYTES {
        return Err(invalid("inventory exceeds byte bound"));
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(sha256_hex(&bytes))
}

fn unsigned(text: &str) -> Result<u128, KernelError> {
    let value = text
        .parse::<u128>()
        .map_err(|_| invalid("invalid unsigned decimal"))?;
    if value.to_string() != text {
        return Err(invalid("noncanonical unsigned decimal"));
    }
    Ok(value)
}

fn signed(text: &str) -> Result<i128, KernelError> {
    let value = text
        .parse::<i128>()
        .map_err(|_| invalid("invalid signed decimal"))?;
    if value.to_string() != text {
        return Err(invalid("noncanonical signed decimal"));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
