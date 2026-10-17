use super::{ChioKernel, CliError, DurableAdmissionRuntime};

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
