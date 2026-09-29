use super::{
    BootstrapFault, CageEnforcementFailureCode, ExecutionIdentity, MAX_SUPPLEMENTARY_GIDS,
};

fn observe_execution_identity() -> Result<ExecutionIdentity, BootstrapFault> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    // SAFETY: all pointers name live uid_t or gid_t outputs.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        // SAFETY: all three gid_t output pointers refer to distinct live locals.
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_observe",
        ));
    }
    if real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_saved_ids",
        ));
    }

    // SAFETY: a zero count queries the required group count without writing.
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let group_count = usize::try_from(group_count).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        )
    })?;
    if group_count > MAX_SUPPLEMENTARY_GIDS {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        ));
    }
    let group_count_i32 = i32::try_from(group_count).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        )
    })?;
    let mut supplementary_gids = vec![0; group_count];
    if group_count > 0 {
        // SAFETY: the vector contains group_count writable gid_t elements.
        let observed = unsafe { libc::getgroups(group_count_i32, supplementary_gids.as_mut_ptr()) };
        if observed != group_count_i32 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_groups",
            ));
        }
    }
    ExecutionIdentity::from_observed_credentials(real_uid, real_gid, supplementary_gids).map_err(
        |_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityMismatch,
                "execution_identity_observed",
            )
        },
    )
}

pub(super) fn apply_execution_identity(
    expected: &ExecutionIdentity,
) -> Result<ExecutionIdentity, BootstrapFault> {
    expected.validate().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityInvalid,
            "execution_identity",
        )
    })?;

    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    // SAFETY: all pointers name live uid_t outputs.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_observe",
        ));
    }
    if effective_uid != 0 {
        let observed = observe_execution_identity()?;
        if observed != *expected {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityMismatch,
                "execution_identity_unprivileged",
            ));
        }
    }

    // SAFETY: both prctl operations only clear privilege-retention state.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0
        // SAFETY: this prctl clears ambient capabilities and receives no pointer arguments.
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_capabilities",
        ));
    }

    if effective_uid == 0 {
        let groups = expected.supplementary_gids();
        let groups_pointer = if groups.is_empty() {
            std::ptr::null()
        } else {
            groups.as_ptr()
        };
        // SAFETY: the pointer is null for an empty slice or names the complete
        // immutable gid_t slice bound by the validated execution identity.
        if unsafe { libc::setgroups(groups.len(), groups_pointer) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setgroups",
            ));
        }
        // SAFETY: validated gid values are written to every process gid slot.
        if unsafe { libc::setresgid(expected.gid(), expected.gid(), expected.gid()) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setresgid",
            ));
        }
        // SAFETY: validated uid values are written to every process uid slot.
        if unsafe { libc::setresuid(expected.uid(), expected.uid(), expected.uid()) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setresuid",
            ));
        }
    }

    let observed = observe_execution_identity()?;
    if observed != *expected {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_verify",
        ));
    }
    Ok(observed)
}

pub(super) fn arm_parent_death(expected_parent: u32) -> Result<(), BootstrapFault> {
    // Credential changes clear this setting, so install it after the final
    // execution identity. The admitted target cannot carry set-ID bits or
    // file capabilities, and its seccomp profile cannot clear the setting.
    // Linux binds it to the creating thread: that thread must remain alive
    // for the target's lifetime. Host loss must not leave an effect-capable
    // orphan after the launch trace has detached.
    // SAFETY: PR_SET_PDEATHSIG consumes a signal number and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "parent_death_signal",
        ));
    }
    // Arm before checking to close the parent-exited-before-prctl race.
    // SAFETY: getppid takes no pointers and reports the current parent.
    if u32::try_from(unsafe { libc::getppid() }).ok() != Some(expected_parent) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "parent_lost_before_enforcement",
        ));
    }
    Ok(())
}
