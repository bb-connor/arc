use chio_core_types::{crypto::PublicKey, receipt::lineage::SignedExportEnvelope};
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use serde::{Deserialize, Serialize};

mod update;

pub use update::{
    sign_treaty_epoch_record, treaty_epoch_from_wire, verify_treaty_epoch_update,
    VerifiedTreatyEpochUpdate,
};

pub const CHIO_TREATY_EPOCH_SCHEMA: &str = "chio.treaty-epoch.v1";
pub const MAX_TREATY_EPOCH_BYTES: usize = 1024 * 1024;
pub const MAX_TREATY_EPOCH_PARTICIPANTS: usize = 64;
pub const MAX_TREATY_EPOCH_AUTHORITIES: usize = 128;
pub const MAX_TREATY_EPOCH_RECORDS: usize = 4096;
pub const MAX_TREATY_EPOCH_AUTHORIZATIONS: usize = 65536;
pub const MAX_TREATY_EPOCH_INTEGER: u64 = (1_u64 << 53) - 1;

pub type SignedTreatyEpochV1 = SignedExportEnvelope<TreatyEpochRecordV1>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreatyEpochStatusV1 {
    Active,
    Revoked,
    Withdrawn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreatyEpochParticipantV1 {
    pub kernel_id: AdmissionIdentifier,
    pub public_key: PublicKey,
    pub ladder_manifest_sha256: AdmissionDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreatyEpochRecordV1 {
    pub schema: String,
    pub verifier_id: AdmissionIdentifier,
    pub treaty_id: AdmissionIdentifier,
    pub sequence: u64,
    pub previous_record_sha256: Option<AdmissionDigest>,
    pub status: TreatyEpochStatusV1,
    pub participants: Vec<TreatyEpochParticipantV1>,
    pub trust_bundle_sha256: AdmissionDigest,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TreatyEpochError {
    #[error("treaty epoch exceeds its byte bound")]
    TooLarge,
    #[error("treaty epoch wire encoding is invalid")]
    InvalidEncoding,
    #[error("treaty epoch schema is invalid")]
    InvalidSchema,
    #[error("treaty epoch sequence or predecessor is invalid")]
    InvalidSequence,
    #[error("treaty epoch participant binding is invalid")]
    InvalidParticipants,
    #[error("treaty epoch validity interval is invalid")]
    InvalidInterval,
    #[error("treaty epoch signer differs from configured authority")]
    AuthorityMismatch,
    #[error("treaty epoch signature is invalid")]
    InvalidSignature,
    #[error("treaty epoch signing backend failed")]
    SigningFailed,
    #[error("treaty epoch is not fresh")]
    Stale,
    #[error("treaty is revoked")]
    Revoked,
    #[error("treaty is withdrawn")]
    Withdrawn,
}
