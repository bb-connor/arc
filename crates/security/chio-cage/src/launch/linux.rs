include!("linux_parts/part_01.rs");
include!("linux_parts/part_02.rs");

fn helper_identity_and_binding_match(
    expected_identity: FileIdentity,
    live_identity: FileIdentity,
    expected_binding_digest: &str,
    live_binding_digest: &str,
) -> bool {
    expected_identity == live_identity && expected_binding_digest == live_binding_digest
}

fn close_unnamed_descriptors(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    let mut retained = vec![0_u32, 1, 2, plan.plan_fd_slot, plan.status_fd_slot];
    retained.extend(plan.fd_table.iter().map(|entry| entry.slot));
    retained.sort_unstable();
    retained.dedup();
    let mut first = 0_u32;
    for slot in retained {
        if first < slot {
            close_range(first, slot - 1)?;
        }
        first = slot.saturating_add(1);
    }
    close_range(first, u32::MAX)
}

fn seccomp_profile_is_fail_closed(plan: &crate::SeccompProfilePlan) -> bool {
    plan.default_action == SeccompDefaultAction::KillProcess
        && !plan.allowed_syscalls.iter().any(|name| name == "socket")
}
