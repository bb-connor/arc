//! Explicit deployment configuration for execution-bound approvals.

use std::io::Read;
use std::path::Path;

use chio_core_types::crypto::PublicKey;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use chio_kernel::caller_delivery::CallerExecutorIdentityV1;
use serde::{Deserialize, Serialize};

use crate::ProtectError;

/// Pins an already installed approval authority and its authenticated executor.
/// Loading this configuration never installs an approval authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectApprovalConfig {
    pub tenant_id: String,
    pub approvers: Vec<PublicKey>,
    pub binding: GovernedApprovalAuthorityBindingV1,
    pub caller_executor: CallerExecutorIdentityV1,
}

impl ProtectApprovalConfig {
    /// Read bounded operator configuration. HTTP clients cannot set this policy.
    pub fn load(path: &Path) -> Result<Self, ProtectError> {
        const LIMIT: usize = 64 * 1024;
        let file = std::fs::File::open(path).map_err(config_error)?;
        let mut bytes = Vec::new();
        file.take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(config_error)?;
        chio_core_types::canonical::UntrustedJsonText::from_wire(&bytes, LIMIT)
            .and_then(|input| input.decode_signed())
            .map_err(config_error)
    }
}

pub(super) fn configure(
    kernel: &mut chio_kernel::ChioKernel,
    config: &ProtectApprovalConfig,
) -> Result<(), ProtectError> {
    if !kernel.has_durable_admission_store() {
        return Err(config_error("approvals require durable admission"));
    }
    if config.approvers.is_empty() {
        return Err(config_error("approval roster must not be empty"));
    }
    kernel
        .set_governed_approval_policy(config.tenant_id.clone(), config.approvers.clone())
        .map_err(config_error)?;
    kernel
        .set_operation_owned_governed_approval_authority(config.binding.clone())
        .map_err(config_error)?;
    kernel
        .set_caller_executor(config.caller_executor.clone())
        .map_err(config_error)?;
    Ok(())
}

fn config_error(error: impl std::fmt::Display) -> ProtectError {
    ProtectError::Config(format!("approval authority: {error}"))
}
