//! Advisory signature domains cannot be substituted for recovery grant domains.
use super::authority::{invalid, signed_authority};
use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, Keypair, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};
use alloc::vec::Vec;
use chio_security_types::recovery::{RecoveryExplanationReportV1, RecoveryExplanationViewV1};
use serde::{Deserialize, Serialize};

pub const RECOVERY_EXPLANATION_REPORT_SIGNATURE_DOMAIN: &str =
    "chio:recovery-explanation-report:v1";
pub const RECOVERY_EXPLANATION_VIEW_SIGNATURE_DOMAIN: &str = "chio:recovery-explanation-view:v1";

signed_authority!(
    SignedRecoveryExplanationReportV1,
    RecoveryExplanationReportV1,
    RECOVERY_EXPLANATION_REPORT_SIGNATURE_DOMAIN,
    |body: &RecoveryExplanationReportV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoveryExplanationViewV1,
    RecoveryExplanationViewV1,
    RECOVERY_EXPLANATION_VIEW_SIGNATURE_DOMAIN,
    |body: &RecoveryExplanationViewV1| body.validate().map_err(|_| invalid())
);
