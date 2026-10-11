use super::*;
use chio_cage_plan::{
    FdPurpose, FileIdentity, NetworkMode, SandboxArchitecture, SeccompDefaultAction,
    CAGE_COMPILER_VERSION, CAGE_INIT_PLAN_SCHEMA, PLAN_FD, STATUS_FD, TARGET_FD,
};
use chio_test_support::prelude::*;

fn identity(kind: &str, inode: u64) -> FileIdentity {
    serde_json::from_value(serde_json::json!({
        "device": 1,
        "inode": inode,
        "mount_id": 1,
        "mode": if kind == "directory" { 0o040700 } else { 0o100700 },
        "uid": 1000,
        "gid": 1000,
        "kind": kind
    }))
    .test_expect("valid identity")
}

fn entry(slot: u32, purpose: FdPurpose, kind: &str, inode: u64) -> chio_cage_plan::FdTableEntry {
    let stdio = matches!(
        purpose,
        FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr
    );
    chio_cage_plan::FdTableEntry {
        slot,
        purpose,
        identity: identity(kind, inode),
        path: (!stdio).then(|| format!("/test/{slot}")),
        binding_digest: None,
        broker_peer_identity: None,
        close_on_exec: true,
    }
}

fn plan() -> CageInitPlan {
    CageInitPlan {
        schema: CAGE_INIT_PLAN_SCHEMA.to_string(),
        compiler_version: CAGE_COMPILER_VERSION.to_string(),
        manifest_digest: "1".repeat(64),
        profile_digest: "2".repeat(64),
        plan_fd_slot: PLAN_FD as u32,
        status_fd_slot: STATUS_FD as u32,
        helper_fd_slot: chio_cage_plan::HELPER_FD_SLOT,
        target_fd_slot: TARGET_FD as u32,
        working_directory_fd_slot: chio_cage_plan::WORKING_DIRECTORY_FD_SLOT,
        target_argv: vec!["/test/target".to_string(), "--stdio".to_string()],
        fd_table: vec![
            entry(
                chio_cage_plan::HELPER_FD_SLOT,
                FdPurpose::CageInitHelper,
                "regular_file",
                1,
            ),
            entry(
                chio_cage_plan::WORKING_DIRECTORY_FD_SLOT,
                FdPurpose::WorkingDirectory,
                "directory",
                2,
            ),
            entry(
                chio_cage_plan::TARGET_STDIN_FD_SLOT,
                FdPurpose::TargetStdin,
                "unix_socket",
                3,
            ),
            entry(
                chio_cage_plan::TARGET_STDOUT_FD_SLOT,
                FdPurpose::TargetStdout,
                "unix_socket",
                4,
            ),
            entry(
                chio_cage_plan::TARGET_STDERR_FD_SLOT,
                FdPurpose::TargetStderr,
                "unix_socket",
                5,
            ),
            entry(
                TARGET_FD as u32,
                FdPurpose::TargetExecutable,
                "regular_file",
                6,
            ),
        ],
        landlock: chio_cage_plan::LandlockPolicyPlan {
            default_filesystem_deny: true,
            network_mode: NetworkMode::Blocked,
            forbidden_resources: Vec::new(),
            grants: Vec::new(),
        },
        seccomp: chio_cage_plan::SeccompProfilePlan::test_unchecked(
            SandboxArchitecture::X86_64,
            chio_cage_plan::NativeSyscallProfile::NativeMinimalV1,
            SeccompDefaultAction::KillProcess,
            vec![
                chio_cage_plan::Syscall::Read,
                chio_cage_plan::Syscall::Write,
                chio_cage_plan::Syscall::Exit,
            ],
            std::collections::BTreeMap::new(),
        ),
        resource_limits: chio_cage_plan::ResourceLimitPlan {
            nofile_soft: chio_cage_plan::CHILD_NOFILE_LIMIT,
            nofile_hard: chio_cage_plan::CHILD_NOFILE_LIMIT,
        },
        execution_identity: chio_cage_plan::ExecutionIdentity::new(10001, 10001, Vec::new())
            .test_unwrap(),
        environment: std::collections::BTreeMap::new(),
        broker_authentication_digest: None,
    }
}

#[test]
fn exact_target_argv_is_used_and_mutation_is_rejected() {
    let mut plan = plan();
    let vectors = build_exec_vectors(&plan).test_expect("valid argv");
    assert_eq!(
        vectors
            ._argv_storage
            .iter()
            .map(|argument| argument.to_str().test_expect("utf8"))
            .collect::<Vec<_>>(),
        vec!["/test/target", "--stdio"]
    );

    plan.target_argv[1].push('\0');
    assert!(build_exec_vectors(&plan).is_err());
}
