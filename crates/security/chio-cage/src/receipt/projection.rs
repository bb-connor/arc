//! Signed metadata block `cage_receipt`: the projection of a `CageReceiptBody`.
//!
//! Every argument-derived digest is committed under `metadata.cage_receipt.<field>`, in every
//! location: the plan and descriptor-table digests hash the target argv, environment and
//! descriptor paths. The profile digest is committed once and the receipt's top-level
//! `policy_hash` carries that commitment's value, so the verifier's equality between the two
//! still holds and neither confirms a guess. Operator-installed binary and manifest digests,
//! file identities, closed enforcement codes, versions and timestamps stay in the projection.
//! One commitment, `metadata.cage_receipt.raw`, binds the projection to the canonical raw
//! body: a verifier that opens it recomputes every field commitment from the opened body.

use chio_core::receipt::metadata::{metadata_salt_ref, MetadataCommitment, MetadataCommitter};
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    validate_digest, CageReceiptBody, CageReceiptError, CageReceiptStage,
    CAGE_RECEIPT_METADATA_SCHEMA,
};
use crate::{
    CageEnforcementFailure, CageEnforcementState, FileIdentity, ObservedRulesetStatus,
    SandboxArchitecture, SeccompEnforcementStatus,
};

/// `CageReceiptBindings` with the plan and descriptor-table digests committed. The profile
/// digest is the projection's top-level `profile_digest`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageBindingsProjection {
    pub manifest_digest: String,
    pub plan_digest: MetadataCommitment,
    pub fd_table_digest: MetadataCommitment,
    pub helper_binding_digest: String,
    pub target_binding_digest: String,
    pub target_identity: FileIdentity,
}

/// `FullyEnforcedEvidence` without the members the bindings already carry. The exec
/// transition repeats the prepared process id, trace session and target binding, which the
/// body's validation requires to be equal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageEnforcementProjection {
    pub process_id: MetadataCommitment,
    pub applied_execution_identity: MetadataCommitment,
    pub nono_version: String,
    pub nono_patch_version: String,
    pub landlock_abi: u32,
    pub landlock_filesystem_status: ObservedRulesetStatus,
    pub landlock_network_status: ObservedRulesetStatus,
    pub seccompiler_version: String,
    pub seccomp_status: SeccompEnforcementStatus,
    pub seccomp_architecture: SandboxArchitecture,
    pub seccomp_filter_digest: MetadataCommitment,
    pub trace_session_digest: MetadataCommitment,
    pub prepared_at_unix_ms: u64,
    pub exec_observed_at_unix_ms: u64,
    pub status_eof_observed: bool,
}

/// `ProcessExitEvidence` with the process id committed. The exit code and signal stay: the
/// verifier derives the signed decision from them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageExitProjection {
    pub process_id: MetadataCommitment,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub exited_at_unix_ms: u64,
}

/// Signed metadata block `cage_receipt`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageReceiptProjection {
    /// Always `CAGE_RECEIPT_METADATA_SCHEMA`; any other value refuses on decode.
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: String,
    pub attempt_id: MetadataCommitment,
    pub stage: CageReceiptStage,
    pub state: CageEnforcementState,
    pub started_at_unix_ms: u64,
    pub recorded_at_unix_ms: u64,
    /// The profile digest the receipt's signing context names; its value is the receipt's
    /// top-level `policy_hash`.
    pub profile_digest: MetadataCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bindings: Option<CageBindingsProjection>,
    /// The profile digest's commitment when the admitted policy digest equals it, else its
    /// own commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_policy_digest: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<CageEnforcementProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<CageEnforcementFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<CageExitProjection>,
    /// Commitment over the canonical raw `CageReceiptBody`.
    pub raw: MetadataCommitment,
}

impl CageReceiptProjection {
    /// True when this projection is the projection of `body` and `policy_hash` under
    /// `committer`. The receipt's other blocks share `committer`, and the caller calls
    /// `finish` once per receipt.
    #[must_use]
    pub fn matches_with(
        &self,
        body: &CageReceiptBody,
        policy_hash: &str,
        committer: &mut MetadataCommitter<'_>,
    ) -> bool {
        Self::project_with(body, policy_hash, committer).is_ok_and(|rebuilt| rebuilt == *self)
    }

    /// The receipt's top-level `policy_hash`: the bare hex value of the profile digest
    /// commitment.
    #[must_use]
    pub fn policy_hash(&self) -> String {
        self.profile_digest.value().to_bare_hex()
    }

    /// Opens the raw body commitment through `committer` and checks that the projection is
    /// the projection of the opened body; returns the verified raw body. The caller calls
    /// `finish` once per receipt.
    pub fn open_raw(
        &self,
        policy_hash: &str,
        committer: &mut MetadataCommitter<'_>,
    ) -> Result<CageReceiptBody, CageReceiptError> {
        let body: CageReceiptBody =
            serde_json::from_slice(committer.open(&self.raw)?.value.as_bytes())?;
        if !self.matches_with(&body, policy_hash, committer) {
            return Err(CageReceiptError::ContentMismatch);
        }
        Ok(body)
    }

    /// The projection of `body` signed under the profile digest `policy_hash`, committing
    /// every committed field through `committer`, which the receipt's other blocks share. A
    /// body that does not validate, or whose bindings name another profile digest, refuses.
    pub fn project_with(
        body: &CageReceiptBody,
        policy_hash: &str,
        committer: &mut MetadataCommitter<'_>,
    ) -> Result<Self, CageReceiptError> {
        body.validate()?;
        validate_digest(policy_hash)?;
        if body
            .bindings
            .as_ref()
            .is_some_and(|bindings| bindings.profile_digest != policy_hash)
        {
            return Err(CageReceiptError::BindingMismatch);
        }
        let profile_digest = commit(committer, "profile_digest", &policy_hash)?;
        let admitted_policy_digest = match &body.admitted_policy_digest {
            Some(digest) if digest == policy_hash => Some(profile_digest.clone()),
            Some(digest) => Some(commit(committer, "admitted_policy_digest", digest)?),
            None => None,
        };
        let attempt_id = commit(committer, "attempt_id", &body.attempt_id)?;
        let bindings = match &body.bindings {
            Some(bindings) => Some(CageBindingsProjection {
                manifest_digest: bindings.manifest_digest.clone(),
                plan_digest: commit(committer, "plan_digest", &bindings.plan_digest)?,
                fd_table_digest: commit(committer, "fd_table_digest", &bindings.fd_table_digest)?,
                helper_binding_digest: bindings.helper_binding_digest.clone(),
                target_binding_digest: bindings.target_binding_digest.clone(),
                target_identity: bindings.target_identity,
            }),
            None => None,
        };
        let record = &body.enforcement_record;
        let enforcement = match &record.fully_enforced {
            Some(evidence) => {
                let prepared = &evidence.prepared;
                Some(CageEnforcementProjection {
                    process_id: commit(committer, "process_id", &prepared.process_id)?,
                    applied_execution_identity: commit(
                        committer,
                        "applied_execution_identity",
                        &prepared.applied_execution_identity,
                    )?,
                    nono_version: prepared.nono_version.clone(),
                    nono_patch_version: prepared.nono_patch_version.clone(),
                    landlock_abi: prepared.landlock_abi,
                    landlock_filesystem_status: prepared.landlock_filesystem_status,
                    landlock_network_status: prepared.landlock_network_status,
                    seccompiler_version: prepared.seccompiler_version.clone(),
                    seccomp_status: prepared.seccomp_status,
                    seccomp_architecture: prepared.seccomp_architecture,
                    seccomp_filter_digest: commit(
                        committer,
                        "seccomp_filter_digest",
                        &prepared.seccomp_filter_digest,
                    )?,
                    trace_session_digest: commit(
                        committer,
                        "trace_session_digest",
                        &prepared.trace_session_digest,
                    )?,
                    prepared_at_unix_ms: prepared.prepared_at_unix_ms,
                    exec_observed_at_unix_ms: evidence.exec_transition.observed_at_unix_ms,
                    status_eof_observed: evidence.status_eof_observed,
                })
            }
            None => None,
        };
        let exit = match &record.exit {
            Some(exit) => Some(CageExitProjection {
                process_id: commit(committer, "process_id", &exit.process_id)?,
                exit_code: exit.exit_code,
                signal: exit.signal,
                exited_at_unix_ms: exit.exited_at_unix_ms,
            }),
            None => None,
        };
        let raw = commit(committer, "raw", body)?;
        Ok(Self {
            schema: CAGE_RECEIPT_METADATA_SCHEMA.to_string(),
            attempt_id,
            stage: body.stage,
            state: record.state,
            started_at_unix_ms: body.started_at_unix_ms,
            recorded_at_unix_ms: body.recorded_at_unix_ms,
            profile_digest,
            bindings,
            admitted_policy_digest,
            enforcement,
            failure: record.failure.clone(),
            exit,
            raw,
        })
    }
}

fn commit<T: Serialize>(
    committer: &mut MetadataCommitter<'_>,
    field: &str,
    value: &T,
) -> Result<MetadataCommitment, CageReceiptError> {
    Ok(committer.commit(metadata_salt_ref("cage_receipt", field)?, value)?)
}

fn deserialize_schema<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let schema = String::deserialize(deserializer)?;
    if schema != CAGE_RECEIPT_METADATA_SCHEMA {
        return Err(serde::de::Error::custom(
            "cage receipt projection schema is not chio.cage.receipt-metadata.v1",
        ));
    }
    Ok(schema)
}
