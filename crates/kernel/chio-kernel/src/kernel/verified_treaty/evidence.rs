//! Private verifier inputs. Deserializing these bytes never verifies a treaty.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreatyVerificationEvidence {
    envelope: DsseEnvelope,
    admission: AdmissionBinding,
}

impl std::fmt::Debug for TreatyVerificationEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TreatyVerificationEvidence")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionBinding {
    accepted: bool,
    admission_report_sha256: String,
    treaty_id: String,
    treaty_scope_sha256: String,
    ladder_intersection_sha256: String,
    action_class_id: String,
    consistency_model: String,
    co_sign: String,
}

impl TreatyVerificationEvidence {
    pub(super) fn retain(input: &FederationTreatyVerification<'_>) -> Self {
        let admission = &input.admission;
        Self {
            envelope: input.envelope.clone(),
            admission: AdmissionBinding {
                accepted: admission.accepted,
                admission_report_sha256: admission.admission_report_sha256.into(),
                treaty_id: admission.treaty_id.into(),
                treaty_scope_sha256: admission.treaty_scope_sha256.into(),
                ladder_intersection_sha256: admission.ladder_intersection_sha256.into(),
                action_class_id: admission.action_class_id.into(),
                consistency_model: admission.consistency_model.into(),
                co_sign: admission.co_sign.into(),
            },
        }
    }

    /// The caller must first establish this evidence's durable provenance and
    /// the original admission time and participant pins. These inputs are not
    /// trusted merely because they occur in a canonical or signed DTO.
    pub(crate) fn reverify(
        &self,
        request: &ToolCallRequest,
        participant_kernel_ids: [&str; 2],
        participant_public_keys: [&PublicKey; 2],
        admitted_at_unix_ms: u64,
    ) -> Result<VerifiedFederationTreatyMaterial, KernelError> {
        VerifiedFederationTreatyMaterial::verify(FederationTreatyVerification {
            envelope: &self.envelope,
            participant_kernel_ids,
            participant_public_keys,
            request,
            local_kernel_id: participant_kernel_ids[1],
            admission: FederationTreatyAdmissionBinding {
                accepted: self.admission.accepted,
                admission_report_sha256: &self.admission.admission_report_sha256,
                treaty_id: &self.admission.treaty_id,
                treaty_scope_sha256: &self.admission.treaty_scope_sha256,
                ladder_intersection_sha256: &self.admission.ladder_intersection_sha256,
                action_class_id: &self.admission.action_class_id,
                consistency_model: &self.admission.consistency_model,
                co_sign: &self.admission.co_sign,
            },
            now_unix_ms: admitted_at_unix_ms,
        })
    }
}
