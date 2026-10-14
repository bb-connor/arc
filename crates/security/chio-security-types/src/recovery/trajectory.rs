//! Qualification assertions preserve the meaning of every digest.
//!
//! ```compile_fail
//! use chio_security_types::recovery::RecoveryTrajectoryV1;
//! fn substitute(trajectory: &mut RecoveryTrajectoryV1) {
//!     trajectory.profile_digest = trajectory.contract_digest;
//! }
//! ```
//!
//! ```compile_fail
//! use chio_security_types::recovery::{BasisDigest, RecoveryAssertionsV1};
//! fn substitute(assertions: &mut RecoveryAssertionsV1, basis: BasisDigest) {
//!     assertions.knowledge_digest = basis;
//! }
//! ```
use super::{
    ContractDigest, KnowledgeDigest, NativeAdmissionDigest, NonEmptyBoundedList, PolicyDigest,
    ProcessRequestDigest, ProfileDigest, RecoveryObservationV1, SafeInteger, SourceDigest,
    VersionV1,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryTrajectorySchema {
    #[serde(rename = "chio.recovery.trajectory.v1")]
    V1,
}

/// Required assertions prevent a decision-only fixture from qualifying safety.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAssertionsV1 {
    pub effect_count: SafeInteger,
    pub consumed_authority: SafeInteger,
    pub remaining_budget: SafeInteger,
    pub knowledge_digest: KnowledgeDigest,
    pub native_admission_digest: NativeAdmissionDigest,
    pub process_request_digest: ProcessRequestDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTrajectoryFrameV1 {
    pub observation: RecoveryObservationV1,
    pub expected: RecoveryAssertionsV1,
}

/// foundation establishes the closed fixture contract. Native cutpoint execution and
/// provider truth are separate native recovery harness obligations, never wire assertions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTrajectoryV1 {
    pub schema: RecoveryTrajectorySchema,
    pub version: VersionV1,
    pub source_digest: SourceDigest,
    pub contract_digest: ContractDigest,
    pub policy_digest: PolicyDigest,
    pub profile_digest: ProfileDigest,
    pub deterministic_time: SafeInteger,
    pub frames: NonEmptyBoundedList<RecoveryTrajectoryFrameV1, 32>,
}
