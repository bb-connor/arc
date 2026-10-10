use super::{
    checked_slot_fd, BootstrapFault, BorrowedFd, CageEnforcementFailureCode, CageInitPlan,
    FilesystemGrantAccess, ObservedRulesetStatus, MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION,
    PINNED_NONO_VERSION,
};

pub(super) fn reset_signal_state() -> Result<(), BootstrapFault> {
    // SAFETY: sigset_t is an all-integer C structure valid when zeroed before
    // sigemptyset initializes it.
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: set is a live output object and the old mask is not requested.
    if unsafe { libc::sigemptyset(&mut set) } != 0
        // SAFETY: set was initialized above and remains borrowed for this call.
        || unsafe { libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "signal_mask",
        ));
    }
    Ok(())
}

pub(super) fn apply_resource_limits(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    if plan.resource_limits.nofile_soft > u64::from(plan.target_fd_slot)
        || plan.resource_limits.nofile_hard < plan.resource_limits.nofile_soft
        || plan.resource_limits.nofile_hard > u64::from(plan.target_fd_slot)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "nofile_limit",
        ));
    }
    let limit = libc::rlimit {
        rlim_cur: plan.resource_limits.nofile_soft,
        rlim_max: plan.resource_limits.nofile_hard,
    };
    // SAFETY: limit is fully initialized and RLIMIT_NOFILE accepts this shape.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "nofile_apply",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LandlockEnforcement {
    pub(super) abi: u32,
    pub(super) filesystem: ObservedRulesetStatus,
    pub(super) network: ObservedRulesetStatus,
}

pub(super) fn apply_landlock(plan: &CageInitPlan) -> Result<LandlockEnforcement, BootstrapFault> {
    if nono_chio::UPSTREAM_NONO_VERSION != PINNED_NONO_VERSION
        || nono_chio::CHIO_PATCH_VERSION != NONO_PATCH_VERSION
        || nono_chio::MINIMUM_LANDLOCK_ABI != MINIMUM_LANDLOCK_ABI
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::LandlockUnavailable,
            "landlock_dependency_version",
        ));
    }

    let mut capabilities = nono_chio::CapabilitySet::new();
    for grant in &plan.landlock.grants {
        let entry = plan
            .fd_table
            .iter()
            .find(|entry| entry.slot == grant.fd_slot)
            .ok_or_else(|| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::DescriptorIdentityMismatch,
                    "landlock_grant",
                )
            })?;
        if entry.identity != grant.identity {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "landlock_grant_identity",
            ));
        }
        let access = match grant.access {
            FilesystemGrantAccess::Read => nono_chio::PathAccess::Read,
            FilesystemGrantAccess::ReadDirectory => nono_chio::PathAccess::ReadDirectory,
            FilesystemGrantAccess::WriteExactFile => nono_chio::PathAccess::WriteExactFile,
            FilesystemGrantAccess::ExecuteRead => nono_chio::PathAccess::ExecuteRead,
        };
        let is_directory = entry.identity.kind() == crate::ResourceKind::Directory;
        // SAFETY: each slot is populated from the authenticated descriptor
        // table and remains open until target exec. BorrowedFd cannot outlive
        // this capability set or the child bootstrap frame.
        let descriptor = unsafe { BorrowedFd::borrow_raw(checked_slot_fd(grant.fd_slot)?) };
        capabilities.add_path_fd(descriptor, access, is_directory);
    }

    let status = capabilities.enforce().map_err(|error| match error {
        nono_chio::Error::AbiProbe(_) | nono_chio::Error::UnsupportedAbi { .. } => {
            BootstrapFault::new(
                CageEnforcementFailureCode::LandlockUnavailable,
                "landlock_abi",
            )
        }
        _ => BootstrapFault::new(
            CageEnforcementFailureCode::LandlockPartial,
            "landlock_enforcement",
        ),
    })?;
    Ok(LandlockEnforcement {
        abi: status.abi,
        filesystem: map_ruleset_status(status.filesystem),
        network: map_ruleset_status(status.network),
    })
}

const fn map_ruleset_status(status: nono_chio::RulesetStatus) -> ObservedRulesetStatus {
    match status {
        nono_chio::RulesetStatus::FullyEnforced => ObservedRulesetStatus::FullyEnforced,
        nono_chio::RulesetStatus::PartiallyEnforced => ObservedRulesetStatus::PartiallyEnforced,
        nono_chio::RulesetStatus::NotEnforced => ObservedRulesetStatus::NotEnforced,
    }
}

pub(super) fn install_seccomp(filter: &seccompiler::BpfProgram) -> Result<(), BootstrapFault> {
    seccompiler::apply_filter(filter).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_install",
        )
    })
}
