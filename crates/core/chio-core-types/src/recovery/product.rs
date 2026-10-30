//! Domain-separated product evidence uses the common canonical authority frame.
use super::authority::{invalid, signed_authority};
use crate::{Keypair, PublicKey, Result, Signature, SigningBackend};
use chio_security_types::recovery::{
    PolicyDeploymentChangeV1, RecoverySetupProbeV1, RecoverySetupReportV1,
};
use serde::{Deserialize, Serialize};

/// Signing-wrapper schema id of a policy deployment change.
pub const CHIO_RECOVERY_POLICY_DEPLOYMENT_CHANGE_SCHEMA: &str =
    "chio.recovery.signed-policy-deployment-change.v1";
/// Signing-wrapper schema id of a recovery setup probe.
pub const CHIO_RECOVERY_SETUP_PROBE_SCHEMA: &str = "chio.recovery-setup-probe.v1";
/// Signing-wrapper schema id of a recovery setup report.
pub const CHIO_RECOVERY_SETUP_REPORT_SCHEMA: &str = "chio.recovery-setup-report.v1";

signed_authority!(
    SignedPolicyDeploymentChangeV1,
    PolicyDeploymentChangeV1,
    CHIO_RECOVERY_POLICY_DEPLOYMENT_CHANGE_SCHEMA,
    |body: &PolicyDeploymentChangeV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoverySetupProbeV1,
    RecoverySetupProbeV1,
    CHIO_RECOVERY_SETUP_PROBE_SCHEMA,
    |body: &RecoverySetupProbeV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoverySetupReportV1,
    RecoverySetupReportV1,
    CHIO_RECOVERY_SETUP_REPORT_SCHEMA,
    |body: &RecoverySetupReportV1| body.validate().map_err(|_| invalid())
);
