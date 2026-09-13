//! Bounded evidence for freezing a legacy runtime replay namespace.
//!
//! These values describe a source seal. They do not authenticate operation
//! ownership, authorize a destination import, or provide rollback protection.

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_sqlite_file_identity::SqliteFileIdentity;
use serde::{Deserialize, Serialize};

use crate::ChioRuntimeError;

pub const MAX_RUNTIME_REPLAY_SOURCE_MARKERS: usize = 16_384;
pub const MAX_RUNTIME_REPLAY_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const SOURCE_SCHEMA: &str = "chio.runtime-replay-source-seal.v1";
const SOURCE_DOMAIN: &[u8] = b"chio.runtime-replay-source-seal.v1\0";

#[cfg(test)]
mod tests;

/// Operator-selected migration labels, not proof of source or destination authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeReplaySourceBinding {
    source_id: AdmissionIdentifier,
    runtime_authority_id: AdmissionIdentifier,
    destination_authority_id: AdmissionIdentifier,
}

impl RuntimeReplaySourceBinding {
    pub fn new(
        source_id: impl Into<String>,
        runtime_authority_id: impl Into<String>,
        destination_authority_id: impl Into<String>,
    ) -> Result<Self, ChioRuntimeError> {
        Ok(Self {
            source_id: identifier("replay_source_id", source_id)?,
            runtime_authority_id: identifier("runtime_authority_id", runtime_authority_id)?,
            destination_authority_id: identifier(
                "destination_authority_id",
                destination_authority_id,
            )?,
        })
    }

    pub fn source_id(&self) -> &str {
        self.source_id.as_str()
    }

    pub fn runtime_authority_id(&self) -> &str {
        self.runtime_authority_id.as_str()
    }

    pub fn destination_authority_id(&self) -> &str {
        self.destination_authority_id.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReplayMarkerKind {
    DestructiveLease,
    TreatyContinuation,
    SwarmContinuation,
}

/// A legacy blocking marker. Its admission ID is historical data, not ownership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeReplayMarker {
    kind: RuntimeReplayMarkerKind,
    resource_id: AdmissionIdentifier,
    admission_id: AdmissionIdentifier,
}

impl RuntimeReplayMarker {
    pub fn new(
        kind: RuntimeReplayMarkerKind,
        resource_id: impl Into<String>,
        admission_id: impl Into<String>,
    ) -> Result<Self, ChioRuntimeError> {
        Ok(Self {
            kind,
            resource_id: identifier("runtime_replay_resource_id", resource_id)?,
            admission_id: identifier("runtime_replay_admission_id", admission_id)?,
        })
    }

    pub fn kind(&self) -> RuntimeReplayMarkerKind {
        self.kind
    }

    pub fn resource_id(&self) -> &str {
        self.resource_id.as_str()
    }

    pub fn admission_id(&self) -> &str {
        self.admission_id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealBody {
    schema: String,
    binding: RuntimeReplaySourceBinding,
    // Decimal strings preserve exact filesystem identity beyond I-JSON integers.
    device: String,
    inode: String,
    link_count: u64,
    barrier_sha256: String,
    marker_counts: [u32; 3],
    markers: Vec<RuntimeReplayMarker>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedSeal {
    body: SealBody,
    inventory_sha256: String,
}

/// Verified source contents at observation time, not durable participant custody.
///
/// There is deliberately no public decoder. Consumers must verify the live
/// source against an independently retained expected seal before relying on it.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeReplaySourceSeal {
    body: SealBody,
    identity: SqliteFileIdentity,
    inventory_sha256: String,
}

impl std::fmt::Debug for RuntimeReplaySourceSeal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeReplaySourceSeal")
            .field("binding", &self.body.binding)
            .field("file_identity", &self.identity)
            .field("marker_count", &self.body.markers.len())
            .field("inventory_sha256", &self.inventory_sha256)
            .finish_non_exhaustive()
    }
}

impl RuntimeReplaySourceSeal {
    pub(crate) fn from_inventory(
        binding: RuntimeReplaySourceBinding,
        identity: SqliteFileIdentity,
        barrier_sha256: String,
        markers: Vec<RuntimeReplayMarker>,
    ) -> Result<Self, ChioRuntimeError> {
        let marker_counts = validate_markers(&markers)?;
        Self::from_body(SealBody {
            schema: SOURCE_SCHEMA.into(),
            binding,
            device: identity.device.to_string(),
            inode: identity.inode.to_string(),
            link_count: identity.link_count,
            barrier_sha256,
            marker_counts,
            markers,
        })
    }

    fn from_body(body: SealBody) -> Result<Self, ChioRuntimeError> {
        if body.schema != SOURCE_SCHEMA
            || body.link_count != 1
            || !is_digest(&body.barrier_sha256)
            || validate_markers(&body.markers)? != body.marker_counts
        {
            return Err(invalid("runtime replay source seal body is invalid"));
        }
        let identity = SqliteFileIdentity {
            device: identity_number(&body.device)?,
            inode: identity_number(&body.inode)?,
            link_count: body.link_count,
        };
        let encoded = encode(&body)?;
        check_size(encoded.len())?;
        let mut preimage = Vec::with_capacity(SOURCE_DOMAIN.len() + encoded.len());
        preimage.extend_from_slice(SOURCE_DOMAIN);
        preimage.extend_from_slice(&encoded);
        let seal = Self {
            body,
            identity,
            inventory_sha256: sha256_hex(&preimage),
        };
        seal.canonical_bytes()?;
        Ok(seal)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChioRuntimeError> {
        check_size(bytes.len())?;
        let persisted: PersistedSeal = serde_json::from_slice(bytes)
            .map_err(|_| invalid("runtime replay source seal encoding is invalid"))?;
        let seal = Self::from_body(persisted.body)?;
        if seal.inventory_sha256 != persisted.inventory_sha256 || seal.canonical_bytes()? != bytes {
            return Err(invalid(
                "runtime replay source seal digest or canonical bytes mismatch",
            ));
        }
        Ok(seal)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChioRuntimeError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Evidence<'a> {
            body: &'a SealBody,
            inventory_sha256: &'a str,
        }
        let encoded = encode(&Evidence {
            body: &self.body,
            inventory_sha256: &self.inventory_sha256,
        })?;
        check_size(encoded.len())?;
        Ok(encoded)
    }

    pub fn binding(&self) -> &RuntimeReplaySourceBinding {
        &self.body.binding
    }

    pub fn inventory_sha256(&self) -> &str {
        &self.inventory_sha256
    }

    pub fn markers(&self) -> &[RuntimeReplayMarker] {
        &self.body.markers
    }

    pub fn file_identity(&self) -> &SqliteFileIdentity {
        &self.identity
    }

    pub fn barrier_sha256(&self) -> &str {
        &self.body.barrier_sha256
    }
}

fn validate_markers(markers: &[RuntimeReplayMarker]) -> Result<[u32; 3], ChioRuntimeError> {
    if markers.len() > MAX_RUNTIME_REPLAY_SOURCE_MARKERS {
        return Err(limit());
    }
    let mut counts = [0_u32; 3];
    let mut previous = None;
    for marker in markers {
        let identity = (marker.kind(), marker.resource_id());
        if previous.is_some_and(|previous| previous >= identity) {
            return Err(invalid(
                "runtime replay markers must be sorted and unique by kind and ID",
            ));
        }
        previous = Some(identity);
        let index = match marker.kind() {
            RuntimeReplayMarkerKind::DestructiveLease => 0,
            RuntimeReplayMarkerKind::TreatyContinuation => 1,
            RuntimeReplayMarkerKind::SwarmContinuation => 2,
        };
        counts[index] = counts[index].checked_add(1).ok_or_else(limit)?;
    }
    Ok(counts)
}

fn identity_number(value: &str) -> Result<u64, ChioRuntimeError> {
    let number = value
        .parse::<u64>()
        .map_err(|_| invalid("invalid source file identity"))?;
    if number.to_string() != value {
        return Err(invalid(
            "source file identity must be an exact decimal integer",
        ));
    }
    Ok(number)
}

fn identifier(
    field: &'static str,
    value: impl Into<String>,
) -> Result<AdmissionIdentifier, ChioRuntimeError> {
    AdmissionIdentifier::try_new(field, value)
        .map_err(|_| invalid("runtime replay source identifier is invalid"))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, ChioRuntimeError> {
    canonical_json_bytes(value).map_err(|error| ChioRuntimeError::Canonical(error.to_string()))
}

fn check_size(size: usize) -> Result<(), ChioRuntimeError> {
    if size > MAX_RUNTIME_REPLAY_SOURCE_BYTES {
        Err(limit())
    } else {
        Ok(())
    }
}

fn invalid(detail: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_replay_source_invalid",
        detail: detail.into(),
    }
}

fn limit() -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_replay_source_inventory_limit",
        detail: "runtime replay source inventory exceeds its complete-snapshot limit".into(),
    }
}
