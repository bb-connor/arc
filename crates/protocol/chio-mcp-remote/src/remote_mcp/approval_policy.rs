//! Explicit operator approval principals and a previously installed approval authority.

use std::io::Read;
use std::path::Path;

use chio_core::PublicKey;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use serde::{Deserialize, Serialize};

use crate::CliError;

/// Public pins only. Signing stays with the external operator, and loading this
/// document never installs an approval authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalConfig {
    pub tenant_id: String,
    pub approvers: Vec<PublicKey>,
    pub binding: GovernedApprovalAuthorityBindingV1,
}

impl RemoteApprovalConfig {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        const LIMIT: usize = 64 * 1024;
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, LIMIT)
            .and_then(|input| input.decode_signed())
            .map_err(config_error)
    }
}

pub(super) fn configure(
    kernel: &mut chio_kernel::ChioKernel,
    config: &RemoteApprovalConfig,
) -> Result<(), CliError> {
    if !kernel.has_durable_admission_store() || config.approvers.is_empty() {
        return Err(config_error(
            "requires durable admission and a nonempty approver roster",
        ));
    }
    kernel
        .set_governed_approval_policy(config.tenant_id.clone(), config.approvers.clone())
        .map_err(config_error)?;
    kernel
        .set_operation_owned_governed_approval_authority(config.binding.clone())
        .map_err(config_error)
}

fn config_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!("remote MCP approval authority: {error}"))
}
