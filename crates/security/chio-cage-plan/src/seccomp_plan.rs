//! Closed syscall vocabulary and validating seccomp plan construction.
use crate::{
    NativeSyscallProfile, SandboxArchitecture, SeccompDefaultAction, SyscallArgumentConstraint,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A syscall understood by the cage compiler. Wire names are Linux syscall names.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Syscall {
    Accept,
    Access,
    ArchPrctl,
    Bind,
    Brk,
    ClockGettime,
    Close,
    Connect,
    EpollCreate1,
    EpollCtl,
    EpollPwait,
    Eventfd2,
    Execveat,
    Exit,
    ExitGroup,
    Faccessat2,
    Fcntl,
    Fdatasync,
    Fstat,
    Fsync,
    Futex,
    Getcwd,
    Getdents64,
    Geteuid,
    Getpid,
    Getrandom,
    Gettid,
    Ioctl,
    Kill,
    Listen,
    Lseek,
    Lstat,
    Madvise,
    Mmap,
    Mprotect,
    Mremap,
    Munmap,
    Nanosleep,
    Newfstatat,
    Open,
    Openat,
    Openat2,
    PidfdSendSignal,
    Pipe2,
    Poll,
    Ppoll,
    Pread64,
    Pwrite64,
    Prlimit64,
    Read,
    Readlink,
    Readlinkat,
    Readv,
    Recvfrom,
    Recvmsg,
    RestartSyscall,
    Rseq,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    SchedGetaffinity,
    SchedYield,
    Sendmsg,
    Sendto,
    SetRobustList,
    SetTidAddress,
    Setitimer,
    Sigaltstack,
    Socket,
    Socketpair,
    Stat,
    Statx,
    Tgkill,
    Tkill,
    Uname,
    Write,
    Writev,
}

impl Syscall {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Access => "access",
            Self::ArchPrctl => "arch_prctl",
            Self::Bind => "bind",
            Self::Brk => "brk",
            Self::ClockGettime => "clock_gettime",
            Self::Close => "close",
            Self::Connect => "connect",
            Self::EpollCreate1 => "epoll_create1",
            Self::EpollCtl => "epoll_ctl",
            Self::EpollPwait => "epoll_pwait",
            Self::Eventfd2 => "eventfd2",
            Self::Execveat => "execveat",
            Self::Exit => "exit",
            Self::ExitGroup => "exit_group",
            Self::Faccessat2 => "faccessat2",
            Self::Fcntl => "fcntl",
            Self::Fdatasync => "fdatasync",
            Self::Fstat => "fstat",
            Self::Fsync => "fsync",
            Self::Futex => "futex",
            Self::Getcwd => "getcwd",
            Self::Getdents64 => "getdents64",
            Self::Geteuid => "geteuid",
            Self::Getpid => "getpid",
            Self::Getrandom => "getrandom",
            Self::Gettid => "gettid",
            Self::Ioctl => "ioctl",
            Self::Kill => "kill",
            Self::Listen => "listen",
            Self::Lseek => "lseek",
            Self::Lstat => "lstat",
            Self::Madvise => "madvise",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Mremap => "mremap",
            Self::Munmap => "munmap",
            Self::Nanosleep => "nanosleep",
            Self::Newfstatat => "newfstatat",
            Self::Open => "open",
            Self::Openat => "openat",
            Self::Openat2 => "openat2",
            Self::PidfdSendSignal => "pidfd_send_signal",
            Self::Pipe2 => "pipe2",
            Self::Poll => "poll",
            Self::Ppoll => "ppoll",
            Self::Pread64 => "pread64",
            Self::Pwrite64 => "pwrite64",
            Self::Prlimit64 => "prlimit64",
            Self::Read => "read",
            Self::Readlink => "readlink",
            Self::Readlinkat => "readlinkat",
            Self::Readv => "readv",
            Self::Recvfrom => "recvfrom",
            Self::Recvmsg => "recvmsg",
            Self::RestartSyscall => "restart_syscall",
            Self::Rseq => "rseq",
            Self::RtSigaction => "rt_sigaction",
            Self::RtSigprocmask => "rt_sigprocmask",
            Self::RtSigreturn => "rt_sigreturn",
            Self::SchedGetaffinity => "sched_getaffinity",
            Self::SchedYield => "sched_yield",
            Self::Sendmsg => "sendmsg",
            Self::Sendto => "sendto",
            Self::SetRobustList => "set_robust_list",
            Self::SetTidAddress => "set_tid_address",
            Self::Setitimer => "setitimer",
            Self::Sigaltstack => "sigaltstack",
            Self::Socket => "socket",
            Self::Socketpair => "socketpair",
            Self::Stat => "stat",
            Self::Statx => "statx",
            Self::Tgkill => "tgkill",
            Self::Tkill => "tkill",
            Self::Uname => "uname",
            Self::Write => "write",
            Self::Writev => "writev",
        }
    }
}

/// Validated plan. Mutation is confined to the compiler and launch boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "SeccompPlanWire")]
pub struct SeccompProfilePlan {
    pub(crate) architecture: SandboxArchitecture,
    pub(crate) profile: NativeSyscallProfile,
    pub(crate) default_action: SeccompDefaultAction,
    pub(crate) allowed_syscalls: Vec<Syscall>,
    pub(crate) argument_constraints: BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeccompPlanWire {
    architecture: SandboxArchitecture,
    profile: NativeSyscallProfile,
    default_action: SeccompDefaultAction,
    allowed_syscalls: Vec<Syscall>,
    argument_constraints: BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SeccompPlanError {
    #[error("syscall {0:?} is listed more than once")]
    DuplicateSyscall(Syscall),
    #[error("syscall {0:?} grants forbidden process or network authority")]
    ForbiddenSyscall(Syscall),
    #[error("constraint names unlisted syscall {0:?}")]
    UnlistedConstraint(Syscall),
    #[error("syscall {0:?} has an empty constraint list")]
    EmptyConstraint(Syscall),
    #[error("syscall {0:?} requires between one and eight argument alternatives")]
    InvalidAlternatives(Syscall),
    #[error("invalid or duplicate argument {argument} for syscall {syscall:?}")]
    InvalidArgument { syscall: Syscall, argument: u8 },
    #[error("prlimit64 must constrain pid to the calling process")]
    UnconfinedResourceLimits,
}

impl SeccompProfilePlan {
    #[must_use]
    pub const fn profile(&self) -> NativeSyscallProfile {
        self.profile
    }

    #[cfg(feature = "enforcement-mutants")]
    #[doc(hidden)]
    pub fn test_allowed_syscalls_mut(&mut self) -> &mut Vec<Syscall> {
        &mut self.allowed_syscalls
    }

    #[cfg(feature = "enforcement-mutants")]
    #[doc(hidden)]
    pub fn test_argument_constraints_mut(
        &mut self,
    ) -> &mut BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>> {
        &mut self.argument_constraints
    }

    #[cfg(feature = "enforcement-mutants")]
    #[doc(hidden)]
    pub fn test_unchecked(
        architecture: SandboxArchitecture,
        profile: NativeSyscallProfile,
        default_action: SeccompDefaultAction,
        allowed_syscalls: Vec<Syscall>,
        argument_constraints: BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>>,
    ) -> Self {
        Self {
            architecture,
            profile,
            default_action,
            allowed_syscalls,
            argument_constraints,
        }
    }

    pub fn new(
        architecture: SandboxArchitecture,
        profile: NativeSyscallProfile,
        allowed_syscalls: Vec<Syscall>,
        argument_constraints: BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>>,
    ) -> Result<Self, SeccompPlanError> {
        let plan = Self {
            architecture,
            profile,
            default_action: SeccompDefaultAction::KillProcess,
            allowed_syscalls,
            argument_constraints,
        };
        plan.validate()?;
        Ok(plan)
    }

    #[must_use]
    pub const fn architecture(&self) -> SandboxArchitecture {
        self.architecture
    }
    #[must_use]
    pub const fn default_action(&self) -> SeccompDefaultAction {
        self.default_action
    }
    #[must_use]
    pub fn allowed_syscalls(&self) -> &[Syscall] {
        &self.allowed_syscalls
    }
    /// Each syscall maps to OR alternatives of ANDed argument constraints.
    /// Absence means unconstrained; an empty alternative is never admissible.
    #[must_use]
    pub fn argument_constraints(&self) -> &BTreeMap<Syscall, Vec<Vec<SyscallArgumentConstraint>>> {
        &self.argument_constraints
    }

    pub fn validate(&self) -> Result<(), SeccompPlanError> {
        let mut allowed = BTreeSet::new();
        for &syscall in &self.allowed_syscalls {
            if !allowed.insert(syscall) {
                return Err(SeccompPlanError::DuplicateSyscall(syscall));
            }
            if matches!(
                syscall,
                Syscall::Socket
                    | Syscall::Socketpair
                    | Syscall::Connect
                    | Syscall::Bind
                    | Syscall::Listen
                    | Syscall::Accept
                    | Syscall::Kill
                    | Syscall::Tkill
                    | Syscall::Tgkill
                    | Syscall::PidfdSendSignal
            ) {
                return Err(SeccompPlanError::ForbiddenSyscall(syscall));
            }
        }
        for (&syscall, alternatives) in &self.argument_constraints {
            if !allowed.contains(&syscall) {
                return Err(SeccompPlanError::UnlistedConstraint(syscall));
            }
            if alternatives.is_empty() || alternatives.len() > 8 {
                return Err(SeccompPlanError::InvalidAlternatives(syscall));
            }
            let mut seen = Vec::new();
            for constraints in alternatives {
                if seen.contains(&constraints) {
                    return Err(SeccompPlanError::InvalidAlternatives(syscall));
                }
                seen.push(constraints);
                if constraints.is_empty() {
                    return Err(SeccompPlanError::EmptyConstraint(syscall));
                }
                let mut arguments = BTreeSet::new();
                for constraint in constraints {
                    if constraint.argument_index > 5 || !arguments.insert(constraint.argument_index)
                    {
                        return Err(SeccompPlanError::InvalidArgument {
                            syscall,
                            argument: constraint.argument_index,
                        });
                    }
                }
            }
        }
        if allowed.contains(&Syscall::Prlimit64)
            && !self
                .argument_constraints
                .get(&Syscall::Prlimit64)
                .is_some_and(|constraints| {
                    constraints.iter().all(|alternative| {
                        alternative.iter().any(|constraint| {
                            constraint.argument_index == 0 && constraint.value == 0
                        })
                    })
                })
        {
            return Err(SeccompPlanError::UnconfinedResourceLimits);
        }
        Ok(())
    }
}

impl TryFrom<SeccompPlanWire> for SeccompProfilePlan {
    type Error = SeccompPlanError;
    fn try_from(wire: SeccompPlanWire) -> Result<Self, Self::Error> {
        let SeccompDefaultAction::KillProcess = wire.default_action;
        Self::new(
            wire.architecture,
            wire.profile,
            wire.allowed_syscalls,
            wire.argument_constraints,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeccompArgumentComparison;

    fn argument(index: u8, value: u64) -> SyscallArgumentConstraint {
        SyscallArgumentConstraint {
            argument_index: index,
            comparison: SeccompArgumentComparison::Equal,
            value,
        }
    }

    #[test]
    fn construction_rejects_constraints_for_unlisted_syscalls() {
        let result = SeccompProfilePlan::new(
            SandboxArchitecture::X86_64,
            NativeSyscallProfile::NativeMinimalV1,
            vec![Syscall::Read],
            BTreeMap::from([(Syscall::Write, vec![vec![argument(0, 1)]])]),
        );
        assert_eq!(
            result,
            Err(SeccompPlanError::UnlistedConstraint(Syscall::Write))
        );
    }

    #[test]
    fn construction_rejects_unconfined_limits_and_invalid_arguments() {
        for constraints in [
            BTreeMap::new(),
            BTreeMap::from([(Syscall::Prlimit64, vec![vec![argument(0, 1)]])]),
            BTreeMap::from([(
                Syscall::Prlimit64,
                vec![vec![argument(0, 0)], vec![argument(0, 1)]],
            )]),
        ] {
            assert_eq!(
                SeccompProfilePlan::new(
                    SandboxArchitecture::X86_64,
                    NativeSyscallProfile::NativeMinimalV1,
                    vec![Syscall::Prlimit64],
                    constraints
                ),
                Err(SeccompPlanError::UnconfinedResourceLimits)
            );
        }
        for arguments in [vec![argument(6, 0)], vec![argument(0, 0), argument(0, 1)]] {
            let expected = arguments
                .last()
                .map(|argument| argument.argument_index)
                .unwrap_or(0);
            assert_eq!(
                SeccompProfilePlan::new(
                    SandboxArchitecture::X86_64,
                    NativeSyscallProfile::NativeMinimalV1,
                    vec![Syscall::Read],
                    BTreeMap::from([(Syscall::Read, vec![arguments])])
                ),
                Err(SeccompPlanError::InvalidArgument {
                    syscall: Syscall::Read,
                    argument: expected
                })
            );
        }
    }

    #[test]
    fn empty_alternatives_cannot_introduce_unconditional_syscall_authority() {
        for alternatives in [vec![], vec![vec![]], vec![vec![argument(1, 1)]; 9]] {
            let result = SeccompProfilePlan::new(
                SandboxArchitecture::X86_64,
                NativeSyscallProfile::NativeMinimalV1,
                vec![Syscall::Fcntl],
                BTreeMap::from([(Syscall::Fcntl, alternatives)]),
            );
            assert!(matches!(
                result,
                Err(SeccompPlanError::EmptyConstraint(Syscall::Fcntl)
                    | SeccompPlanError::InvalidAlternatives(Syscall::Fcntl))
            ));
        }
    }

    #[test]
    fn wire_decode_uses_the_same_plan_validator_and_closed_syscall_keys(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plan = SeccompProfilePlan::new(
            SandboxArchitecture::X86_64,
            NativeSyscallProfile::NativeMinimalV1,
            vec![Syscall::Read],
            BTreeMap::new(),
        )?;
        let mut wire = serde_json::to_value(&plan)?;
        assert_eq!(
            serde_json::from_value::<SeccompProfilePlan>(wire.clone())?,
            plan
        );
        wire["argument_constraints"] =
            serde_json::json!({"write": [[{"argument_index":0,"comparison":"equal","value":1}]]});
        let error = serde_json::from_value::<SeccompProfilePlan>(wire.clone())
            .err()
            .ok_or("unlisted constraint decoded")?;
        assert!(
            error
                .to_string()
                .contains("constraint names unlisted syscall Write"),
            "{error}"
        );
        wire["argument_constraints"] = serde_json::json!({"prlimt64": []});
        let error = serde_json::from_value::<SeccompProfilePlan>(wire)
            .err()
            .ok_or("misspelled constraint decoded")?;
        assert!(
            error.to_string().contains("unknown variant `prlimt64`"),
            "{error}"
        );
        Ok(())
    }
}
