//! Platform facts the confined reference runtime depends on.
//!
//! The cage needs a Linux x86_64 host with kernel 6.7 or newer, Landlock at
//! ABI 4 or newer for filesystem and TCP mediation, seccomp, the no-new-privileges
//! flag, pid file descriptors, `close_range`, `execveat` with an empty path,
//! sealed memory files, `openat2` resolve flags, mount identifiers from `statx`
//! and enough file descriptors. This probe measures each of them once through
//! a fact source, so the verdict logic is tested with fixed facts and the host
//! source only carries the system calls.

use std::fmt;

use super::super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

pub const MINIMUM_KERNEL: (u32, u32) = (6, 7);
pub const MINIMUM_NOFILE: u64 = 1024;
pub const ENFORCEMENT_ARCH: &str = "x86_64";

/// What the host offers, measured once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFacts {
    pub os: String,
    pub arch: String,
    pub kernel_release: String,
    pub landlock_abi: Option<u32>,
    pub seccomp: bool,
    pub no_new_privs: bool,
    pub pidfd_open: bool,
    pub close_range: bool,
    pub execveat_empty_path: bool,
    pub sealed_memfd: bool,
    pub openat2: bool,
    pub statx_mount_id: bool,
    pub nofile_soft: u64,
}

impl PlatformFacts {
    /// The kernel's major and minor version when the release string starts with them.
    pub fn kernel_version(&self) -> Option<(u32, u32)> {
        let mut parts = self.kernel_release.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some((major, minor))
    }
}

/// Where the facts come from: the host, or fixed values in tests.
pub trait PlatformFactSource {
    fn facts(&self) -> PlatformFacts;
}

/// One prerequisite the confined runtime cannot do without.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prerequisite {
    LinuxX86_64,
    Kernel,
    Landlock,
    Seccomp,
    NoNewPrivs,
    PidfdOpen,
    CloseRange,
    ExecveatEmptyPath,
    SealedMemfd,
    Openat2,
    StatxMountId,
    FileDescriptors,
}

impl fmt::Display for Prerequisite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LinuxX86_64 => "linux x86_64",
            Self::Kernel => "kernel 6.7 or newer",
            Self::Landlock => "landlock abi 4 or newer",
            Self::Seccomp => "seccomp",
            Self::NoNewPrivs => "no_new_privs",
            Self::PidfdOpen => "pidfd_open",
            Self::CloseRange => "close_range",
            Self::ExecveatEmptyPath => "execveat with an empty path",
            Self::SealedMemfd => "sealed memfd",
            Self::Openat2 => "openat2 resolve flags",
            Self::StatxMountId => "statx mount id",
            Self::FileDescriptors => "1024 file descriptors",
        })
    }
}

/// The prerequisites a set of facts does not satisfy, in a stable order.
pub fn missing_prerequisites(facts: &PlatformFacts) -> Vec<Prerequisite> {
    let mut missing = Vec::new();
    if facts.os != "linux" || facts.arch != ENFORCEMENT_ARCH {
        missing.push(Prerequisite::LinuxX86_64);
    }
    if facts.kernel_version().is_none_or(|version| version < MINIMUM_KERNEL) {
        missing.push(Prerequisite::Kernel);
    }
    if facts
        .landlock_abi
        .is_none_or(|abi| abi < chio_cage::MINIMUM_LANDLOCK_ABI)
    {
        missing.push(Prerequisite::Landlock);
    }
    for (present, prerequisite) in [
        (facts.seccomp, Prerequisite::Seccomp),
        (facts.no_new_privs, Prerequisite::NoNewPrivs),
        (facts.pidfd_open, Prerequisite::PidfdOpen),
        (facts.close_range, Prerequisite::CloseRange),
        (facts.execveat_empty_path, Prerequisite::ExecveatEmptyPath),
        (facts.sealed_memfd, Prerequisite::SealedMemfd),
        (facts.openat2, Prerequisite::Openat2),
        (facts.statx_mount_id, Prerequisite::StatxMountId),
        (facts.nofile_soft >= MINIMUM_NOFILE, Prerequisite::FileDescriptors),
    ] {
        if !present {
            missing.push(prerequisite);
        }
    }
    missing
}

/// Reports whether this host can run the confined reference runtime.
pub struct PlatformProbe {
    source: Box<dyn PlatformFactSource>,
    require_enforcement: bool,
}

impl PlatformProbe {
    /// A probe over the host. With `require_enforcement`, a missing
    /// prerequisite is an error; otherwise it is a warning, because a
    /// developer host that only provisions and serves at migration stage
    /// Disabled does not need the cage.
    pub fn host(require_enforcement: bool) -> Self {
        Self::with_source(Box::new(HostPlatform), require_enforcement)
    }

    pub fn with_source(source: Box<dyn PlatformFactSource>, require_enforcement: bool) -> Self {
        Self {
            source,
            require_enforcement,
        }
    }
}

impl Probe for PlatformProbe {
    fn name(&self) -> &'static str {
        "security.platform"
    }

    fn run(&self, _config: &ProbeConfig) -> ProbeReport {
        let facts = self.source.facts();
        let missing = missing_prerequisites(&facts);
        let report = if missing.is_empty() {
            ProbeReport::ok(
                self.name(),
                "the host satisfies every cage enforcement prerequisite",
            )
        } else {
            let listed = missing
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let severity = if self.require_enforcement {
                ProbeSeverity::Error
            } else {
                ProbeSeverity::Warning
            };
            ProbeReport::fail(
                self.name(),
                severity,
                "urn:chio:error:cli:other",
                format!("the host lacks cage enforcement prerequisites: {listed}"),
            )
            .with_help(
                "cage enforcement evidence is produced on Linux x86_64 with kernel 6.7 or newer; \
                 a host without these still provisions and serves at migration stage Disabled",
            )
        };
        let mut report = report
            .with_context("os", facts.os.clone())
            .with_context("arch", facts.arch.clone())
            .with_context("kernel_release", facts.kernel_release.clone())
            .with_context(
                "landlock_abi",
                facts
                    .landlock_abi
                    .map_or_else(|| "unsupported".to_string(), |abi| abi.to_string()),
            )
            .with_context("nofile_soft", facts.nofile_soft.to_string());
        for (key, present) in [
            ("seccomp", facts.seccomp),
            ("no_new_privs", facts.no_new_privs),
            ("pidfd_open", facts.pidfd_open),
            ("close_range", facts.close_range),
            ("execveat_empty_path", facts.execveat_empty_path),
            ("sealed_memfd", facts.sealed_memfd),
            ("openat2", facts.openat2),
            ("statx_mount_id", facts.statx_mount_id),
        ] {
            report = report.with_context(key, if present { "yes" } else { "no" });
        }
        report
    }
}

/// The facts of the running host.
pub struct HostPlatform;

impl PlatformFactSource for HostPlatform {
    fn facts(&self) -> PlatformFacts {
        host::facts()
    }
}

#[cfg(target_os = "linux")]
mod host {
    use std::ffi::CStr;

    use super::PlatformFacts;

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    pub(super) fn facts() -> PlatformFacts {
        PlatformFacts {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            kernel_release: kernel_release(),
            landlock_abi: landlock_abi(),
            seccomp: seccomp(),
            no_new_privs: no_new_privs(),
            pidfd_open: pidfd_open(),
            close_range: close_range(),
            execveat_empty_path: execveat_empty_path(),
            sealed_memfd: sealed_memfd(),
            openat2: openat2(),
            statx_mount_id: statx_mount_id(),
            nofile_soft: nofile_soft(),
        }
    }

    fn kernel_release() -> String {
        // SAFETY: utsname is plain data the kernel fills in; a zeroed value is
        // a valid instance and uname only writes into it.
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is to a live, writable utsname.
        if unsafe { libc::uname(&mut name) } != 0 {
            return String::new();
        }
        // SAFETY: the kernel NUL-terminates every utsname field.
        unsafe { CStr::from_ptr(name.release.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    fn landlock_abi() -> Option<u32> {
        // SAFETY: querying the ABI version passes no ruleset attribute; the
        // kernel reads nothing through the null pointer for this flag.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        u32::try_from(result).ok().filter(|abi| *abi > 0)
    }

    fn seccomp() -> bool {
        // SAFETY: PR_GET_SECCOMP takes no pointers.
        (unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }) >= 0
    }

    fn no_new_privs() -> bool {
        // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointers.
        (unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }) >= 0
    }

    fn pidfd_open() -> bool {
        // SAFETY: opening a pid file descriptor for our own process has no
        // side effect beyond the descriptor, which is closed at once.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
        if descriptor < 0 {
            return false;
        }
        // SAFETY: the descriptor was just returned by the kernel and is ours.
        unsafe { libc::close(descriptor as libc::c_int) };
        true
    }

    fn close_range() -> bool {
        // SAFETY: the range names one descriptor number no process holds,
        // so a supporting kernel closes nothing and returns zero.
        unsafe { libc::syscall(libc::SYS_close_range, u32::MAX, u32::MAX, 0u32) == 0 }
    }

    fn execveat_empty_path() -> bool {
        let empty = c"";
        let argv: [*const libc::c_char; 1] = [std::ptr::null()];
        // SAFETY: an invalid descriptor with an empty path makes the kernel
        // answer EBADF before it touches argv or envp, so nothing executes.
        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                -1 as libc::c_int,
                empty.as_ptr(),
                argv.as_ptr(),
                argv.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    fn sealed_memfd() -> bool {
        let name = c"chio-preflight";
        // SAFETY: memfd_create takes a NUL-terminated name and flags.
        let descriptor =
            unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if descriptor < 0 {
            return false;
        }
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: fcntl on a descriptor we own with integer arguments.
        let sealed = unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } == 0;
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(descriptor) };
        sealed
    }

    fn openat2() -> bool {
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY) as u64,
            mode: 0,
            resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        let root = c"/";
        // SAFETY: openat2 reads the open_how structure of the given size and
        // the NUL-terminated path; the descriptor it returns is closed here.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                root.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            return false;
        }
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(descriptor as libc::c_int) };
        true
    }

    fn statx_mount_id() -> bool {
        const STATX_MNT_ID: u32 = 0x1000;
        let root = c"/";
        // SAFETY: statx fills a plain data structure; a zeroed value is valid.
        let mut buffer: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: the path is NUL-terminated and the buffer is live and writable.
        let result = unsafe {
            libc::statx(libc::AT_FDCWD, root.as_ptr(), 0, STATX_MNT_ID, &mut buffer)
        };
        result == 0 && buffer.stx_mask & STATX_MNT_ID != 0
    }

    // `rlim_t` is 64 bits wide on every Linux libc target but is declared
    // through the libc crate, so the conversion is spelled out.
    #[allow(clippy::useless_conversion)]
    fn nofile_soft() -> u64 {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a live rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return 0;
        }
        u64::from(limit.rlim_cur)
    }
}

#[cfg(not(target_os = "linux"))]
mod host {
    use super::PlatformFacts;

    pub(super) fn facts() -> PlatformFacts {
        PlatformFacts {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            kernel_release: String::new(),
            landlock_abi: None,
            seccomp: false,
            no_new_privs: false,
            pidfd_open: false,
            close_range: false,
            execveat_empty_path: false,
            sealed_memfd: false,
            openat2: false,
            statx_mount_id: false,
            nofile_soft: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(PlatformFacts);

    impl PlatformFactSource for Fixed {
        fn facts(&self) -> PlatformFacts {
            self.0.clone()
        }
    }

    fn capable() -> PlatformFacts {
        PlatformFacts {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            kernel_release: "6.8.0-45-generic".to_string(),
            landlock_abi: Some(5),
            seccomp: true,
            no_new_privs: true,
            pidfd_open: true,
            close_range: true,
            execveat_empty_path: true,
            sealed_memfd: true,
            openat2: true,
            statx_mount_id: true,
            nofile_soft: 65536,
        }
    }

    #[test]
    fn a_capable_host_satisfies_every_prerequisite() {
        assert!(missing_prerequisites(&capable()).is_empty());
        let report = PlatformProbe::with_source(Box::new(Fixed(capable())), true)
            .run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Ok);
        assert!(report
            .context
            .iter()
            .any(|entry| entry.key == "landlock_abi" && entry.value == "5"));
    }

    #[test]
    fn every_missing_prerequisite_is_named() {
        let mut facts = capable();
        facts.arch = "aarch64".to_string();
        facts.kernel_release = "6.6.12".to_string();
        facts.landlock_abi = Some(3);
        facts.sealed_memfd = false;
        facts.nofile_soft = 256;
        assert_eq!(
            missing_prerequisites(&facts),
            vec![
                Prerequisite::LinuxX86_64,
                Prerequisite::Kernel,
                Prerequisite::Landlock,
                Prerequisite::SealedMemfd,
                Prerequisite::FileDescriptors,
            ]
        );
        let mut facts = capable();
        facts.kernel_release = "unknown".to_string();
        facts.landlock_abi = None;
        assert_eq!(
            missing_prerequisites(&facts),
            vec![Prerequisite::Kernel, Prerequisite::Landlock]
        );
    }

    #[test]
    fn enforcement_turns_a_missing_prerequisite_into_an_error() {
        let mut facts = capable();
        facts.arch = "aarch64".to_string();
        let advisory = PlatformProbe::with_source(Box::new(Fixed(facts.clone())), false)
            .run(&ProbeConfig::default());
        assert_eq!(advisory.severity, ProbeSeverity::Warning);
        assert!(advisory.message.contains("linux x86_64"));
        let enforced = PlatformProbe::with_source(Box::new(Fixed(facts)), true)
            .run(&ProbeConfig::default());
        assert_eq!(enforced.severity, ProbeSeverity::Error);
        assert!(enforced.help.is_some());
    }

    #[test]
    fn the_host_reports_its_own_facts() {
        let facts = HostPlatform.facts();
        assert_eq!(facts.os, std::env::consts::OS);
        assert_eq!(facts.arch, std::env::consts::ARCH);
        if cfg!(target_os = "linux") {
            assert!(facts.kernel_version().is_some(), "{}", facts.kernel_release);
            assert!(facts.nofile_soft > 0);
        }
    }
}
