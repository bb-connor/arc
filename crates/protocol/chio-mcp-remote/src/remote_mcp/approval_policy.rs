//! Explicit operator approval principals and previously activated replay custody.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core::PublicKey;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use serde::{Deserialize, Serialize};

use crate::CliError;

/// Public pins only. Signing stays with the external operator, and loading this
/// document never imports or activates a replay authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalConfig {
    pub tenant_id: String,
    pub approvers: Vec<PublicKey>,
    pub replay_source_path: PathBuf,
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
    let source = chio_store_sqlite::SqliteGovernedApprovalReplaySource::open_with_clock(
        &config.replay_source_path,
        kernel.authority_clock(),
    )
    .map_err(config_error)?;
    kernel
        .set_operation_owned_governed_approval_source(config.binding.clone(), Arc::new(source))
        .map_err(config_error)
}

fn config_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!("remote MCP approval authority: {error}"))
}
