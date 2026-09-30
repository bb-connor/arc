use super::{
    seccomp_profile_is_fail_closed, BTreeMap, BTreeSet, BootstrapFault, CageEnforcementFailureCode,
    SandboxArchitecture, SeccompArgumentComparison, Serialize, SyscallArgumentConstraint,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct FilterInstruction {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

impl FilterInstruction {
    const fn from_seccompiler(instruction: &seccompiler::sock_filter) -> Self {
        Self {
            code: instruction.code,
            jump_true: instruction.jt,
            jump_false: instruction.jf,
            value: instruction.k,
        }
    }
}

pub fn compile_seccomp_filter(
    plan: &crate::SeccompProfilePlan,
) -> Result<seccompiler::BpfProgram, BootstrapFault> {
    let current = SandboxArchitecture::current().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompArchitectureMismatch,
            "seccomp_architecture",
        )
    })?;
    if current != plan.architecture() {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::SeccompArchitectureMismatch,
            "seccomp_architecture",
        ));
    }
    if !seccomp_profile_is_fail_closed(plan) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_fail_closed",
        ));
    }
    let target_arch = match current {
        SandboxArchitecture::X86_64 => seccompiler::TargetArch::x86_64,
        SandboxArchitecture::Aarch64 => seccompiler::TargetArch::aarch64,
    };
    let mut rules = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for name in plan.allowed_syscalls() {
        if !seen.insert(name.as_str()) {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_duplicate",
            ));
        }
        let number = i64::from(syscall_number(current, name.as_str()).ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::SeccompArchitectureMismatch,
                "seccomp_syscall",
            )
        })?);
        let rule_chain = plan
            .argument_constraints()
            .get(name)
            .map(|alternatives| {
                alternatives
                    .iter()
                    .map(|constraints| compile_seccomp_rule(constraints))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        if rules.insert(number, rule_chain).is_some() {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_duplicate_number",
            ));
        }
    }
    if plan
        .argument_constraints()
        .keys()
        .any(|name| !seen.contains(name.as_str()))
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_constraint",
        ));
    }
    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::KillProcess,
        seccompiler::SeccompAction::Allow,
        target_arch,
    )
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_filter",
        )
    })?;
    filter.try_into().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_compile",
        )
    })
}

fn compile_seccomp_rule(
    constraints: &[SyscallArgumentConstraint],
) -> Result<seccompiler::SeccompRule, BootstrapFault> {
    let mut conditions = Vec::with_capacity(constraints.len());
    let mut seen = BTreeSet::new();
    for constraint in constraints {
        if constraint.argument_index > 5
            || constraint.comparison != SeccompArgumentComparison::Equal
            || !seen.insert(constraint.argument_index)
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_argument",
            ));
        }
        conditions.push(
            seccompiler::SeccompCondition::new(
                constraint.argument_index,
                seccompiler::SeccompCmpArgLen::Qword,
                seccompiler::SeccompCmpOp::Eq,
                constraint.value,
            )
            .map_err(|_| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::SeccompInstallFailed,
                    "seccomp_condition",
                )
            })?,
        );
    }
    let rule = seccompiler::SeccompRule::new(conditions).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_rule",
        )
    })?;
    Ok(rule)
}

pub fn filter_digest(filter: &seccompiler::BpfProgram) -> Result<String, BootstrapFault> {
    let instructions = filter
        .iter()
        .map(FilterInstruction::from_seccompiler)
        .collect::<Vec<_>>();
    let bytes = chio_cage_plan::canonical_json_bytes(&instructions).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_filter_digest",
        )
    })?;
    Ok(chio_cage_plan::sha256_hex(&bytes))
}

pub fn syscall_number(architecture: SandboxArchitecture, name: &str) -> Option<u32> {
    match architecture {
        SandboxArchitecture::X86_64 => Some(match name {
            "read" => 0,
            "write" => 1,
            "open" => 2,
            "close" => 3,
            "stat" => 4,
            "fstat" => 5,
            "fsync" => 74,
            "lstat" => 6,
            "poll" => 7,
            "lseek" => 8,
            "mmap" => 9,
            "mprotect" => 10,
            "munmap" => 11,
            "brk" => 12,
            "rt_sigaction" => 13,
            "rt_sigprocmask" => 14,
            "rt_sigreturn" => 15,
            "ioctl" => 16,
            "pread64" => 17,
            "access" => 21,
            "readv" => 19,
            "writev" => 20,
            "sched_yield" => 24,
            "mremap" => 25,
            "madvise" => 28,
            "nanosleep" => 35,
            "setitimer" => 38,
            "getpid" => 39,
            "sendto" => 44,
            "recvfrom" => 45,
            "sendmsg" => 46,
            "recvmsg" => 47,
            "exit" => 60,
            "uname" => 63,
            "fcntl" => 72,
            "fdatasync" => 75,
            "pwrite64" => 18,
            "getdents64" => 217,
            "geteuid" => 107,
            "getcwd" => 79,
            "readlink" => 89,
            "sigaltstack" => 131,
            "arch_prctl" => 158,
            "gettid" => 186,
            "futex" => 202,
            "sched_getaffinity" => 204,
            "set_tid_address" => 218,
            "restart_syscall" => 219,
            "clock_gettime" => 228,
            "exit_group" => 231,
            "epoll_ctl" => 233,
            "tgkill" => 234,
            "openat" => 257,
            "newfstatat" => 262,
            "readlinkat" => 267,
            "ppoll" => 271,
            "set_robust_list" => 273,
            "epoll_pwait" => 281,
            "eventfd2" => 290,
            "epoll_create1" => 291,
            "pipe2" => 293,
            "prlimit64" => 302,
            "execveat" => 322,
            "getrandom" => 318,
            "statx" => 332,
            "rseq" => 334,
            "openat2" => 437,
            "faccessat2" => 439,
            _ => return None,
        }),
        SandboxArchitecture::Aarch64 => Some(match name {
            "getcwd" => 17,
            "eventfd2" => 19,
            "epoll_create1" => 20,
            "epoll_ctl" => 21,
            "epoll_pwait" => 22,
            "fcntl" => 25,
            "ioctl" => 29,
            "openat" => 56,
            "close" => 57,
            "pipe2" => 59,
            "getdents64" => 61,
            "geteuid" => 175,
            "lseek" => 62,
            "read" => 63,
            "write" => 64,
            "readv" => 65,
            "writev" => 66,
            "pread64" => 67,
            "pwrite64" => 68,
            "ppoll" => 73,
            "readlinkat" => 78,
            "newfstatat" => 79,
            "fstat" => 80,
            "fsync" => 82,
            "fdatasync" => 83,
            "exit" => 93,
            "exit_group" => 94,
            "set_tid_address" => 96,
            "futex" => 98,
            "set_robust_list" => 99,
            "nanosleep" => 101,
            "setitimer" => 103,
            "clock_gettime" => 113,
            "sched_getaffinity" => 123,
            "sched_yield" => 124,
            "restart_syscall" => 128,
            "tgkill" => 131,
            "sigaltstack" => 132,
            "rt_sigaction" => 134,
            "rt_sigprocmask" => 135,
            "rt_sigreturn" => 139,
            "uname" => 160,
            "getpid" => 172,
            "gettid" => 178,
            "sendto" => 206,
            "recvfrom" => 207,
            "sendmsg" => 211,
            "recvmsg" => 212,
            "brk" => 214,
            "munmap" => 215,
            "mremap" => 216,
            "mmap" => 222,
            "mprotect" => 226,
            "madvise" => 233,
            "prlimit64" => 261,
            "getrandom" => 278,
            "execveat" => 281,
            "statx" => 291,
            "rseq" => 293,
            "openat2" => 437,
            "faccessat2" => 439,
            _ => return None,
        }),
    }
}
