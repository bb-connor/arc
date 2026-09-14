//! Dependency-neutral, untrusted data for retiring legacy runtime replay state.
//!
//! Decoding a snapshot does not establish sealing, source authority, operation
//! ownership or activation. The configured source port and qualified destination
//! must independently verify it against a durably pinned expectation.

use super::{AdmissionDigest, AdmissionIdentifier, AdmissionOperationStoreError};
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

pub const MAX_RUNTIME_REPLAY_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RUNTIME_REPLAY_SOURCE_MARKERS: usize = 16_384;
const SOURCE_SCHEMA: &str = "chio.runtime-replay-source-seal.v1";
const SOURCE_DOMAIN: &[u8] = b"chio.runtime-replay-source-seal.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReplayParticipantKind {
    DestructiveLease,
    TreatyContinuation,
    SwarmContinuation,
}

impl RuntimeReplayParticipantKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestructiveLease => "destructive_lease",
            Self::TreatyContinuation => "treaty_continuation",
            Self::SwarmContinuation => "swarm_continuation",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeReplaySourceMarkerV1 {
    kind: RuntimeReplayParticipantKind,
    resource_id: AdmissionIdentifier,
    admission_id: AdmissionIdentifier,
}

impl RuntimeReplaySourceMarkerV1 {
    pub fn kind(&self) -> RuntimeReplayParticipantKind {
        self.kind
    }

    pub fn resource_id(&self) -> &str {
        self.resource_id.as_str()
    }

    /// Historical provenance only. This is never an operation owner.
    pub fn historical_admission_id(&self) -> &str {
        self.admission_id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceBinding {
    source_id: AdmissionIdentifier,
    runtime_authority_id: AdmissionIdentifier,
    destination_authority_id: AdmissionIdentifier,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceBody {
    schema: String,
    binding: SourceBinding,
    device: String,
    inode: String,
    link_count: u64,
    barrier_sha256: AdmissionDigest,
    marker_counts: [u32; 3],
    markers: Vec<RuntimeReplaySourceMarkerV1>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceEvidence {
    body: SourceBody,
    inventory_sha256: AdmissionDigest,
}

/// Bounded canonical source data, deliberately not a verified authority token.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeReplaySourceSnapshotV1 {
    evidence: SourceEvidence,
    canonical: Vec<u8>,
    device: u64,
    inode: u64,
}

impl std::fmt::Debug for RuntimeReplaySourceSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeReplaySourceSnapshotV1")
            .field("binding", &self.evidence.body.binding)
            .field("inventory_sha256", &self.inventory_sha256())
            .field("marker_count", &self.markers().len())
            .finish_non_exhaustive()
    }
}

impl RuntimeReplaySourceSnapshotV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdmissionOperationStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_REPLAY_SOURCE_BYTES {
            return Err(invalid("source snapshot byte limit exceeded"));
        }
        let evidence: SourceEvidence = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid source snapshot encoding"))?;
        let body = &evidence.body;
        if body.schema != SOURCE_SCHEMA || body.link_count != 1 {
            return Err(invalid("invalid source snapshot schema or link count"));
        }
        let device = identity_number(&body.device)?;
        let inode = identity_number(&body.inode)?;
        if body.markers.len() > MAX_RUNTIME_REPLAY_SOURCE_MARKERS {
            return Err(invalid("source snapshot marker limit exceeded"));
        }
        let mut counts = [0_u32; 3];
        let mut previous = None;
        for marker in &body.markers {
            let identity = (marker.kind(), marker.resource_id());
            if previous.is_some_and(|previous| previous >= identity) {
                return Err(invalid("source markers are not sorted and unique"));
            }
            previous = Some(identity);
            let index = match marker.kind() {
                RuntimeReplayParticipantKind::DestructiveLease => 0,
                RuntimeReplayParticipantKind::TreatyContinuation => 1,
                RuntimeReplayParticipantKind::SwarmContinuation => 2,
            };
            counts[index] = counts[index]
                .checked_add(1)
                .ok_or_else(|| invalid("source marker count overflow"))?;
        }
        if counts != body.marker_counts {
            return Err(invalid("source marker counts disagree"));
        }
        let encoded_body = encode(body)?;
        let mut preimage = Vec::with_capacity(SOURCE_DOMAIN.len() + encoded_body.len());
        preimage.extend_from_slice(SOURCE_DOMAIN);
        preimage.extend_from_slice(&encoded_body);
        if sha256_hex(&preimage) != evidence.inventory_sha256.as_str() {
            return Err(invalid("source snapshot inventory digest mismatch"));
        }
        if encode(&evidence)? != bytes {
            return Err(invalid("source snapshot is not exact canonical JSON"));
        }
        Ok(Self {
            evidence,
            canonical: bytes.to_vec(),
            device,
            inode,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn source_id(&self) -> &str {
        self.evidence.body.binding.source_id.as_str()
    }

    pub fn runtime_authority_id(&self) -> &str {
        self.evidence.body.binding.runtime_authority_id.as_str()
    }

    pub fn destination_authority_id(&self) -> &str {
        self.evidence.body.binding.destination_authority_id.as_str()
    }

    pub fn inventory_sha256(&self) -> &str {
        self.evidence.inventory_sha256.as_str()
    }

    pub fn barrier_sha256(&self) -> &str {
        self.evidence.body.barrier_sha256.as_str()
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn link_count(&self) -> u64 {
        self.evidence.body.link_count
    }

    pub fn markers(&self) -> &[RuntimeReplaySourceMarkerV1] {
        &self.evidence.body.markers
    }
}

/// Trusted migration I/O, configured by the operator, never by an agent request.
///
/// Implementations must bind the actual source identity and entire inventory.
/// Preview must reject already sealed sources; exact sealing must compare the
/// pinned snapshot before any mutation and verify existing seals on retry.
/// Verification must inspect live storage, not just echo caller-supplied bytes.
/// A public implementation of this trait alone is not a qualified source profile.
pub trait RuntimeReplaySourcePort: Send + Sync {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError>;

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError>;

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError>;
}

fn identity_number(value: &str) -> Result<u64, AdmissionOperationStoreError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid("invalid source file identity"))?;
    if parsed.to_string() != value {
        return Err(invalid("source file identity is not canonical decimal"));
    }
    Ok(parsed)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(value).map_err(|error| invalid(&error.to_string()))
}

fn invalid(detail: &str) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(format!("runtime replay source: {detail}"))
}
