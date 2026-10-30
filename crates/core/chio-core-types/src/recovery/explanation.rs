//! Advisory signature domains cannot be substituted for recovery grant domains.
use super::authority::{invalid, signed_authority};
use crate::{Keypair, PublicKey, Result, Signature, SigningBackend};
use chio_security_types::recovery::{RecoveryExplanationReportV1, RecoveryExplanationViewV1};
use serde::{Deserialize, Serialize};

/// Signing-wrapper schema id of a recovery explanation report.
pub const CHIO_RECOVERY_EXPLANATION_REPORT_SCHEMA: &str =
    "chio.recovery.signed-explanation-report.v1";
/// Signing-wrapper schema id of a recovery explanation view.
pub const CHIO_RECOVERY_EXPLANATION_VIEW_SCHEMA: &str = "chio.recovery.signed-explanation-view.v1";

signed_authority!(
    SignedRecoveryExplanationReportV1,
    RecoveryExplanationReportV1,
    CHIO_RECOVERY_EXPLANATION_REPORT_SCHEMA,
    |body: &RecoveryExplanationReportV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoveryExplanationViewV1,
    RecoveryExplanationViewV1,
    CHIO_RECOVERY_EXPLANATION_VIEW_SCHEMA,
    |body: &RecoveryExplanationViewV1| body.validate().map_err(|_| invalid())
);
