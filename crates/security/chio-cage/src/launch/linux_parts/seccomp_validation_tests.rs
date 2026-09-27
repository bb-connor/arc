use super::*;
use chio_test_support::prelude::*;

#[cfg_attr(
    not(target_arch = "x86_64"),
    ignore = "requires the native x86_64 compiler boundary"
)]
#[test]
fn launch_revalidates_unlisted_constraint_keys() {
    let mut plan = crate::build_seccomp_plan(
        SandboxArchitecture::X86_64,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    )
    .test_unwrap();
    plan.argument_constraints.insert(
        crate::Syscall::Getcwd,
        vec![SyscallArgumentConstraint {
            argument_index: 0,
            comparison: SeccompArgumentComparison::Equal,
            value: 0,
        }],
    );
    assert_eq!(
        plan.validate(),
        Err(crate::SeccompPlanError::UnlistedConstraint(
            crate::Syscall::Getcwd
        ))
    );
    let error = compile_seccomp_filter(&plan).test_unwrap_err();
    assert_eq!(
        error.record().failure.as_ref().map(|failure| failure.code),
        Some(CageEnforcementFailureCode::SeccompInstallFailed)
    );
}
