//! Closed native syscall profiles and descriptor-specific restrictions.
use super::{
    CageError, NativeSyscallProfile, SandboxArchitecture, SeccompArgumentComparison,
    SeccompProfilePlan, Syscall, SyscallArgumentConstraint, AT_EMPTY_PATH, BROKER_IPC_FD_SLOT,
    TARGET_FD_SLOT,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn build_seccomp_plan(
    architecture: SandboxArchitecture,
    profile: NativeSyscallProfile,
) -> Result<SeccompProfilePlan, CageError> {
    const BASE: &[Syscall] = &[
        Syscall::Brk,
        Syscall::ClockGettime,
        Syscall::Close,
        Syscall::Execveat,
        Syscall::Exit,
        Syscall::ExitGroup,
        Syscall::Faccessat2,
        Syscall::Fcntl,
        Syscall::Fstat,
        // Persist writes through already admitted descriptors. This syscall
        // does not open a path or expand the cage's filesystem authority.
        Syscall::Fsync,
        Syscall::Futex,
        Syscall::Getpid,
        Syscall::Getrandom,
        Syscall::Gettid,
        Syscall::Ioctl,
        Syscall::Lseek,
        Syscall::Madvise,
        Syscall::Mmap,
        Syscall::Mprotect,
        Syscall::Munmap,
        Syscall::Newfstatat,
        Syscall::Openat,
        Syscall::Openat2,
        Syscall::Ppoll,
        Syscall::Pread64,
        Syscall::Prlimit64,
        Syscall::Read,
        Syscall::Readlinkat,
        Syscall::Rseq,
        Syscall::RtSigaction,
        Syscall::RtSigprocmask,
        Syscall::RtSigreturn,
        Syscall::SchedGetaffinity,
        Syscall::SchedYield,
        Syscall::SetRobustList,
        Syscall::SetTidAddress,
        Syscall::Sigaltstack,
        Syscall::Statx,
        Syscall::Write,
        Syscall::Writev,
    ];
    const STANDARD: &[Syscall] = &[
        Syscall::EpollCreate1,
        Syscall::EpollCtl,
        Syscall::EpollPwait,
        Syscall::Eventfd2,
        Syscall::Getcwd,
        Syscall::Getdents64,
        Syscall::Mremap,
        Syscall::Nanosleep,
        Syscall::Pipe2,
        Syscall::Readv,
        Syscall::RestartSyscall,
        Syscall::Setitimer,
    ];
    const BROKERED: &[Syscall] = &[
        Syscall::Recvfrom,
        Syscall::Recvmsg,
        Syscall::Sendmsg,
        Syscall::Sendto,
    ];

    let mut allowed = BASE.iter().copied().collect::<BTreeSet<_>>();
    if architecture == SandboxArchitecture::X86_64 {
        // glibc's ELF loader probes /etc/ld.so.preload with access(2). The
        // subsequent open remains independently confined by Landlock.
        // Rust/glibc path canonicalization uses readlink rather than readlinkat
        // on x86_64. Both inspect link metadata; file opens remain confined.
        // musl also uses the legacy open/stat/lstat entrypoints. They have
        // the same path authority as the allowed *at variants; Landlock
        // continues to enforce every file open against the retained grants.
        allowed.extend([
            Syscall::Access,
            Syscall::ArchPrctl,
            Syscall::Lstat,
            Syscall::Open,
            Syscall::Poll,
            Syscall::Readlink,
            Syscall::Stat,
        ]);
    }
    match profile {
        NativeSyscallProfile::NativeMinimalV1 => {}
        NativeSyscallProfile::NativeStandardV1 => {
            allowed.extend(STANDARD.iter().copied());
            // CPython's uuid/platform imports inspect kernel identification.
            // This reads bounded metadata without opening resources. Keep it
            // specific to the operator-selected standard interpreter profile.
            allowed.insert(Syscall::Uname);
        }
        NativeSyscallProfile::BrokeredNativeV1 => {
            allowed.extend(STANDARD.iter().copied());
            allowed.extend(BROKERED.iter().copied());
        }
    }
    let mut argument_constraints = BTreeMap::from([(
        Syscall::Execveat,
        vec![
            SyscallArgumentConstraint {
                argument_index: 0,
                comparison: SeccompArgumentComparison::Equal,
                value: u64::from(TARGET_FD_SLOT),
            },
            SyscallArgumentConstraint {
                argument_index: 4,
                comparison: SeccompArgumentComparison::Equal,
                value: AT_EMPTY_PATH,
            },
        ],
    )]);
    // PID zero selects the calling process. A same-UID peer must never be
    // able to change the kernel's limits through this otherwise useful call.
    argument_constraints.insert(
        Syscall::Prlimit64,
        vec![SyscallArgumentConstraint {
            argument_index: 0,
            comparison: SeccompArgumentComparison::Equal,
            value: 0,
        }],
    );
    if profile != NativeSyscallProfile::BrokeredNativeV1 {
        // Rust's musl file wrapper marks newly opened descriptors close-on-exec.
        // Permit that one tightening operation, without duplication or clearing
        // flags. The broker profile retains its separate F_GETFD-only contract.
        argument_constraints.insert(
            Syscall::Fcntl,
            vec![
                SyscallArgumentConstraint {
                    argument_index: 1,
                    comparison: SeccompArgumentComparison::Equal,
                    value: 2, // Linux F_SETFD.
                },
                SyscallArgumentConstraint {
                    argument_index: 2,
                    comparison: SeccompArgumentComparison::Equal,
                    value: 1, // Linux FD_CLOEXEC.
                },
            ],
        );
    }
    if profile == NativeSyscallProfile::BrokeredNativeV1 {
        for syscall in BROKERED {
            argument_constraints.insert(
                *syscall,
                vec![SyscallArgumentConstraint {
                    argument_index: 0,
                    comparison: SeccompArgumentComparison::Equal,
                    value: u64::from(BROKER_IPC_FD_SLOT),
                }],
            );
        }
        // Rust checks descriptor validity before closing an owned socket.
        // Permit only F_GETFD on the retained broker slot. Duplication, flag
        // mutation, and inspection of every other descriptor remain denied.
        argument_constraints.insert(
            Syscall::Fcntl,
            vec![
                SyscallArgumentConstraint {
                    argument_index: 0,
                    comparison: SeccompArgumentComparison::Equal,
                    value: u64::from(BROKER_IPC_FD_SLOT),
                },
                SyscallArgumentConstraint {
                    argument_index: 1,
                    comparison: SeccompArgumentComparison::Equal,
                    value: 1, // Linux F_GETFD on both supported architectures.
                },
            ],
        );
    }
    let mut argument_constraints = argument_constraints
        .into_iter()
        .map(|(syscall, constraints)| (syscall, vec![constraints]))
        .collect::<BTreeMap<_, _>>();
    if profile != NativeSyscallProfile::BrokeredNativeV1 {
        // Inspect an existing descriptor without duplicating it or changing flags.
        // Rust's I/O safety checks use F_GETFD when closing owned files.
        argument_constraints
            .entry(Syscall::Fcntl)
            .or_default()
            .push(vec![SyscallArgumentConstraint {
                argument_index: 1,
                comparison: SeccompArgumentComparison::Equal,
                value: 1, // Linux F_GETFD.
            }]);
    }
    Ok(SeccompProfilePlan::new(
        architecture,
        profile,
        allowed.into_iter().collect(),
        argument_constraints,
    )?)
}
