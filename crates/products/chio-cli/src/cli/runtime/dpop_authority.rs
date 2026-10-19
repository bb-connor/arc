use super::{ChioKernel, CliError, DurableAdmissionRuntime, Path};

pub(crate) fn configured_dpop_replay_authority(
) -> Result<Option<chio_kernel::dpop::authority::DpopReplayAuthority>, CliError> {
    let path = std::env::var_os(chio_control_plane::DPOP_REPLAY_AUTHORITY_FILE_ENV);
    configured_dpop_replay_authority_from_path(path.as_deref().map(Path::new))
}

/// Load the configured descriptor and refuse startup when the policy requires
/// DPoP without one.
pub(crate) fn policy_dpop_replay_authority(
    policy: &chio_control_plane::policy::LoadedPolicy,
) -> Result<Option<chio_kernel::dpop::authority::DpopReplayAuthority>, CliError> {
    let authority = configured_dpop_replay_authority()?;
    chio_control_plane::require_configured_dpop_replay_authority(policy, authority.as_ref())?;
    Ok(authority)
}

fn configured_dpop_replay_authority_from_path(
    path: Option<&Path>,
) -> Result<Option<chio_kernel::dpop::authority::DpopReplayAuthority>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = crate::input::read_regular(path, 4096)?;
    Ok(Some(crate::input::decode(&bytes, 4096)?))
}

pub(super) fn attach_durable_admission_runtime(
    kernel: &mut ChioKernel,
    runtime: Option<&DurableAdmissionRuntime>,
    dpop_authority: Option<&chio_kernel::dpop::authority::DpopReplayAuthority>,
) -> Result<(), CliError> {
    if kernel.durable_admission_mode()
        == chio_kernel::admission_operation::DurableAdmissionMode::Off
    {
        if dpop_authority.is_some() {
            return Err(CliError::cli_other_error(
                "configured DPoP replay authority requires durable admission",
            ));
        }
        return Ok(());
    }
    runtime
        .ok_or_else(|| {
            CliError::cli_other_error(
                "durable admission runtime is unavailable for an enabled policy".to_string(),
            )
        })?
        .attach(kernel, dpop_authority)
}

#[cfg(test)]
#[path = "dpop_authority/tests.rs"]
mod tests;
