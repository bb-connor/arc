use super::{BootstrapFault, CString, CageEnforcementFailureCode, CageInitPlan};

pub(super) struct ExecVectors {
    pub(super) _argv_storage: Vec<CString>,
    pub(super) argv: Vec<*const libc::c_char>,
    pub(super) _environment_storage: Vec<CString>,
    pub(super) environment: Vec<*const libc::c_char>,
}

pub(super) fn build_exec_vectors(plan: &CageInitPlan) -> Result<ExecVectors, BootstrapFault> {
    crate::validate_target_argv(&plan.target_argv)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "argv"))?;
    let argv_storage = plan
        .target_argv
        .iter()
        .map(|argument| {
            CString::new(argument.as_str())
                .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "argv"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = argv_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let mut environment_storage = Vec::with_capacity(plan.environment.len());
    let mut total = 0_usize;
    for (name, value) in &plan.environment {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_'
                    || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
            })
            || crate::is_credential_or_injection_name(name)
            || value.len() > 16 * 1024
            || value.chars().any(char::is_control)
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "environment",
            ));
        }
        total = total
            .checked_add(name.len() + value.len() + 2)
            .ok_or_else(|| {
                BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "environment")
            })?;
        if total > 64 * 1024 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "environment",
            ));
        }
        environment_storage.push(CString::new(format!("{name}={value}")).map_err(|_| {
            BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "environment")
        })?);
    }
    let mut environment = environment_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment.push(std::ptr::null());
    Ok(ExecVectors {
        _argv_storage: argv_storage,
        argv,
        _environment_storage: environment_storage,
        environment,
    })
}

#[cfg(test)]
mod tests;
