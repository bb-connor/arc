//! Domain-separated product evidence uses the common canonical authority frame.
use super::authority::{invalid, signed_authority};
use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, Keypair, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};
use alloc::vec::Vec;
use chio_security_types::recovery::{
    PolicyDeploymentChangeV1, RecoverySetupProbeV1, RecoverySetupReportV1,
};
use serde::{Deserialize, Serialize};

pub const RECOVERY_POLICY_DEPLOYMENT_CHANGE_SIGNATURE_DOMAIN: &str =
    "chio:recovery-policy-deployment-change:v1";
pub const RECOVERY_SETUP_PROBE_SIGNATURE_DOMAIN: &str = "chio:recovery-setup-probe:v1";
pub const RECOVERY_SETUP_REPORT_SIGNATURE_DOMAIN: &str = "chio:recovery-setup-report:v1";

signed_authority!(
    SignedPolicyDeploymentChangeV1,
    PolicyDeploymentChangeV1,
    RECOVERY_POLICY_DEPLOYMENT_CHANGE_SIGNATURE_DOMAIN,
    |body: &PolicyDeploymentChangeV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoverySetupProbeV1,
    RecoverySetupProbeV1,
    RECOVERY_SETUP_PROBE_SIGNATURE_DOMAIN,
    |body: &RecoverySetupProbeV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedRecoverySetupReportV1,
    RecoverySetupReportV1,
    RECOVERY_SETUP_REPORT_SIGNATURE_DOMAIN,
    |body: &RecoverySetupReportV1| body.validate().map_err(|_| invalid())
);
