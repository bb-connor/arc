//! Dependency-neutral migration data, not source sealing or dispatch authority.
//! The canonical snapshot is validated at construction and decode boundaries.
//! Raw inventory fields remain untrusted until wrapped in that snapshot.

use chio_core::{canonical::canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::{AdmissionIdentifier, AdmissionOperationStoreError as Error};

pub const MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS: usize = 16_384;
const SCHEMA: &str = "chio.governed-approval-replay-source-seal.v1";
const DOMAIN: &[u8] = b"chio:governed-approval-replay-source-inventory:v1\0";

/// Historical wildcard marker. New subject-scoped credentials must not use it.
pub const LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT: &str = "__chio_legacy_unscoped_subject__";

/// Untrusted identity data. Only a configured source backend can establish that
/// it describes its actual open database, rather than a copied artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedApprovalReplaySourceFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub link_count: u64,
}

/// Operator-selected namespace labels, not authenticated authority credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalReplaySourceBinding {
    pub source_id: AdmissionIdentifier,
    pub approval_authority_id: AdmissionIdentifier,
    pub destination_authority_id: AdmissionIdentifier,
}

/// Raw migration data, not a reservation or operation owner. Numeric text is
/// validated when constructing or decoding the enclosing canonical snapshot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalReplaySourceMarker {
    pub subject_id: AdmissionIdentifier,
    pub request_id: AdmissionIdentifier,
    pub intent_hash: AdmissionIdentifier,
    // Decimal strings preserve the entire SQLite integer range in RFC 8785.
    pub expires_at: String,
    pub dispatch_reservation_id: Option<AdmissionIdentifier>,
}

impl GovernedApprovalReplaySourceMarker {
    /// This marker blocks the same request/intent for every subject. Importers
    /// must preserve that wildcard rather than treat the sentinel as a subject.
    pub fn is_legacy_unscoped(&self) -> bool {
        self.subject_id.as_str() == LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT
    }

    fn key(&self) -> (&str, &str, &str) {
        (
            self.subject_id.as_str(),
            self.request_id.as_str(),
            self.intent_hash.as_str(),
        )
    }
}

/// Raw retained inventory. It confers no authority and must pass the bounded
/// snapshot constructor before a destination can pin it as migration data.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalReplaySourceInventory {
    pub wall_clock_high_water: String,
    pub pruned_through: String,
    pub capacity: String,
    pub markers: Vec<GovernedApprovalReplaySourceMarker>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: String,
    binding: GovernedApprovalReplaySourceBinding,
    device: String,
    inode: String,
    link_count: String,
    barrier_sha256: String,
    inventory: GovernedApprovalReplaySourceInventory,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: Body,
    inventory_sha256: String,
}

/// Bounded canonical migration data. A preview or decoded artifact proves
/// neither source sealing nor permission to import or execute anything.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedApprovalReplaySourceSnapshot(Envelope);

impl std::fmt::Debug for GovernedApprovalReplaySourceSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernedApprovalReplaySourceSnapshot")
            .field("binding", self.binding())
            .field("marker_count", &self.marker_count())
            .field("inventory_sha256", &self.0.inventory_sha256)
            .finish_non_exhaustive()
    }
}

impl GovernedApprovalReplaySourceSnapshot {
    pub fn binding(&self) -> &GovernedApprovalReplaySourceBinding {
        &self.0.body.binding
    }

    pub fn marker_count(&self) -> usize {
        self.0.body.inventory.markers.len()
    }

    pub fn source_id(&self) -> &str {
        self.binding().source_id.as_str()
    }

    pub fn approval_authority_id(&self) -> &str {
        self.binding().approval_authority_id.as_str()
    }

    pub fn destination_authority_id(&self) -> &str {
        self.binding().destination_authority_id.as_str()
    }

    pub fn inventory_sha256(&self) -> &str {
        &self.0.inventory_sha256
    }

    /// Validated identity data, not proof of a live file descriptor.
    pub fn file_identity(&self) -> Result<GovernedApprovalReplaySourceFileIdentity, Error> {
        Ok(GovernedApprovalReplaySourceFileIdentity {
            device: unsigned(&self.0.body.device)?,
            inode: unsigned(&self.0.body.inode)?,
            link_count: unsigned(&self.0.body.link_count)?,
        })
    }

    pub fn inventory(&self) -> &GovernedApprovalReplaySourceInventory {
        &self.0.body.inventory
    }

    pub fn markers(&self) -> &[GovernedApprovalReplaySourceMarker] {
        &self.0.body.inventory.markers
    }

    /// Private migration data, including historical reservation identifiers.
    /// Never expose it as an agent-visible report or dispatch authorization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes = canonical_json_bytes(&self.0)
            .map_err(|error| invalid(format!("inventory encoding failed: {error}")))?;
        if bytes.len() > MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_BYTES {
            return Err(invalid("inventory exceeds its byte bound"));
        }
        Ok(bytes)
    }

    /// Decode data only. Live source verification is a separate store operation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_BYTES {
            return Err(invalid("inventory has invalid byte length"));
        }
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(|_| invalid("inventory decoding failed"))?;
        envelope.body.validate()?;
        if digest(&envelope.body)? != envelope.inventory_sha256 {
            return Err(invalid("inventory digest mismatch"));
        }
        let snapshot = Self(envelope);
        if snapshot.canonical_bytes()? != bytes {
            return Err(invalid("inventory is not canonical"));
        }
        Ok(snapshot)
    }

    /// Validate raw inventory into canonical data, never a live seal claim.
    pub fn from_inventory(
        binding: GovernedApprovalReplaySourceBinding,
        identity: GovernedApprovalReplaySourceFileIdentity,
        barrier_sha256: String,
        inventory: GovernedApprovalReplaySourceInventory,
    ) -> Result<Self, Error> {
        let body = Body {
            schema: SCHEMA.to_owned(),
            binding,
            device: identity.device.to_string(),
            inode: identity.inode.to_string(),
            link_count: identity.link_count.to_string(),
            barrier_sha256,
            inventory,
        };
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

/// Operator-configured migration I/O, never selected by an agent request.
/// Public implementation of this trait does not qualify a source profile.
///
/// Preview must reject already sealed sources. Exact sealing must compare the
/// entire pinned snapshot before mutation, and verify an existing seal on retry.
/// Verification must inspect live barriers, data and physical identity, never
/// echo the caller's bytes. No callback may run under the destination DB lock.
pub trait GovernedApprovalReplaySourcePort: Send + Sync {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, Error>;

    fn seal_exact(&self, expected: &GovernedApprovalReplaySourceSnapshot) -> Result<(), Error>;

    fn verify_exact(&self, expected: &GovernedApprovalReplaySourceSnapshot) -> Result<(), Error>;
}

impl Body {
    fn validate(&self) -> Result<(), Error> {
        if self.schema != SCHEMA || self.link_count != "1" {
            return Err(invalid("unsupported inventory schema or link count"));
        }
        unsigned(&self.device)?;
        unsigned(&self.inode)?;
        if self.barrier_sha256.len() != 64
            || !self
                .barrier_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("invalid barrier digest"));
        }
        self.inventory.validate()
    }
}

impl GovernedApprovalReplaySourceInventory {
    /// Validate retained data without claiming source identity or live sealing.
    pub fn validate(&self) -> Result<(), Error> {
        let high_water = signed(&self.wall_clock_high_water)?;
        let pruned = signed(&self.pruned_through)?;
        let capacity = signed(&self.capacity)?;
        if high_water < 0
            || pruned > high_water
            || (pruned < 0 && pruned != i64::MIN)
            || capacity <= 0
            || self.markers.len() > MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS
            || u64::try_from(self.markers.len()).map_err(|_| invalid("invalid marker count"))?
                > u64::try_from(capacity).map_err(|_| invalid("invalid capacity"))?
        {
            return Err(invalid("invalid clock, capacity, or marker count"));
        }
        for marker in &self.markers {
            if signed(&marker.expires_at)? < 0 {
                return Err(invalid("negative marker expiry"));
            }
        }
        if self
            .markers
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(invalid("markers are unordered or duplicate"));
        }
        Ok(())
    }
}

fn signed(value: &str) -> Result<i64, Error> {
    let parsed: i64 = value
        .parse()
        .map_err(|_| invalid("invalid signed decimal"))?;
    if parsed.to_string() != value {
        return Err(invalid("noncanonical signed decimal"));
    }
    Ok(parsed)
}

fn unsigned(value: &str) -> Result<u64, Error> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| invalid("invalid unsigned decimal"))?;
    if parsed.to_string() != value {
        return Err(invalid("noncanonical unsigned decimal"));
    }
    Ok(parsed)
}

fn digest(body: &Body) -> Result<String, Error> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(
        canonical_json_bytes(body).map_err(|_| invalid("inventory digest encoding failed"))?,
    );
    Ok(sha256_hex(&bytes))
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invariant(format!(
        "governed approval replay source: {}",
        message.into()
    ))
}
