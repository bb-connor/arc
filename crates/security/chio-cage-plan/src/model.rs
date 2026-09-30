#[cfg(target_os = "linux")]
use super::linux;
use super::{BTreeMap, CageError, Deserialize, ExecutionIdentity, SeccompProfilePlan, Serialize};

/// Cage-init plan schema emitted by this crate.
pub const CAGE_INIT_PLAN_SCHEMA: &str = "chio.cage.init-plan.v2";
/// Version of the deterministic compiler semantics.
pub const CAGE_COMPILER_VERSION: &str = "chio-cage-compiler.v2";

pub const PLAN_FD_SLOT: u32 = 3;
pub const STATUS_FD_SLOT: u32 = 4;
pub const HELPER_FD_SLOT: u32 = 5;
pub const WORKING_DIRECTORY_FD_SLOT: u32 = 6;
#[cfg(target_os = "linux")]
pub const TARGET_STDIN_FD_SLOT: u32 = 7;
pub const BROKER_IPC_FD_SLOT: u32 = 8;
#[cfg(target_os = "linux")]
pub const TARGET_STDOUT_FD_SLOT: u32 = 9;
#[cfg(target_os = "linux")]
pub const TARGET_STDERR_FD_SLOT: u32 = 10;
pub const RUNTIME_FD_SLOT_START: u32 = 16;
pub const READ_GRANT_FD_SLOT_START: u32 = 64;
pub const WRITE_GRANT_FD_SLOT_START: u32 = 128;
// The target remains inherited above this ceiling so its execveat exception
// cannot be recreated after the close-on-exec transition.
pub const CHILD_NOFILE_LIMIT: u64 = 192;
pub const TARGET_FD_SLOT: u32 = 255;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const MAX_TARGET_ARG_COUNT: usize = 256;
pub const MAX_TARGET_ARG_BYTES: usize = 16 * 1024;
pub const MAX_TARGET_ARGV_BYTES: usize = 128 * 1024;

/// Kernel object kind accepted by cage admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    RegularFile,
    Directory,
    UnixSocket,
}

/// Stable identity captured from a retained descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mount_id: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) kind: ResourceKind,
}

impl FileIdentity {
    /// Construct descriptor metadata for a plan. Admission compares it with a fresh kernel observation.
    #[must_use]
    pub const fn new(
        device: u64,
        inode: u64,
        mount_id: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        kind: ResourceKind,
    ) -> Self {
        Self {
            device,
            inode,
            mount_id,
            mode,
            uid,
            gid,
            kind,
        }
    }

    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }

    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    #[must_use]
    pub const fn kind(self) -> ResourceKind {
        self.kind
    }

    #[cfg(target_os = "linux")]
    pub fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.kind == other.kind
    }
}

/// Supported seccomp architecture binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxArchitecture {
    X86_64,
    Aarch64,
}

impl SandboxArchitecture {
    pub fn current() -> Result<Self, CageError> {
        Self::for_native_architecture(std::env::consts::ARCH)
    }

    pub fn for_native_architecture(architecture: &str) -> Result<Self, CageError> {
        match architecture {
            "x86_64" => Ok(Self::X86_64),
            architecture => Err(CageError::UnsupportedArchitecture(architecture.to_string())),
        }
    }
}

/// Filesystem action in the deny-all Landlock plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemGrantAccess {
    Read,
    ReadDirectory,
    WriteExactFile,
    ExecuteRead,
}

/// Explicit network policy. V1 never grants direct network creation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Blocked,
}

/// Function of a fixed cage-init descriptor slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FdPurpose {
    CageInitHelper,
    TargetExecutable,
    WorkingDirectory,
    TargetStdin,
    TargetStdout,
    TargetStderr,
    RuntimeFile { index: u32 },
    ReadGrant { index: u32 },
    WriteGrant { index: u32 },
    BrokerIpc,
}

impl<'de> Deserialize<'de> for FdPurpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Internally tagged unit variants ignore sibling fields in Serde. Use
        // empty struct variants for the wire decoder so every purpose object
        // remains closed without changing the public enum or JSON shape.
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
        enum ClosedFdPurpose {
            CageInitHelper {},
            TargetExecutable {},
            WorkingDirectory {},
            TargetStdin {},
            TargetStdout {},
            TargetStderr {},
            RuntimeFile { index: u32 },
            ReadGrant { index: u32 },
            WriteGrant { index: u32 },
            BrokerIpc {},
        }

        Ok(match ClosedFdPurpose::deserialize(deserializer)? {
            ClosedFdPurpose::CageInitHelper {} => Self::CageInitHelper,
            ClosedFdPurpose::TargetExecutable {} => Self::TargetExecutable,
            ClosedFdPurpose::WorkingDirectory {} => Self::WorkingDirectory,
            ClosedFdPurpose::TargetStdin {} => Self::TargetStdin,
            ClosedFdPurpose::TargetStdout {} => Self::TargetStdout,
            ClosedFdPurpose::TargetStderr {} => Self::TargetStderr,
            ClosedFdPurpose::RuntimeFile { index } => Self::RuntimeFile { index },
            ClosedFdPurpose::ReadGrant { index } => Self::ReadGrant { index },
            ClosedFdPurpose::WriteGrant { index } => Self::WriteGrant { index },
            ClosedFdPurpose::BrokerIpc {} => Self::BrokerIpc,
        })
    }
}

/// Identity expected at a fixed descriptor slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FdTableEntry {
    pub slot: u32,
    pub purpose: FdPurpose,
    pub identity: FileIdentity,
    pub path: Option<String>,
    pub binding_digest: Option<String>,
    pub broker_peer_identity: Option<BrokerPeerIdentity>,
    pub close_on_exec: bool,
}

/// Kernel-observed credentials for the connected broker peer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl BrokerPeerIdentity {
    #[must_use]
    pub const fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self { pid, uid, gid }
    }

    pub fn current_process() -> Result<Self, CageError> {
        #[cfg(target_os = "linux")]
        {
            Ok(linux::current_process_identity())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageError::UnsupportedPlatform)
        }
    }
}

/// A forbidden object resolved before any allowed rule is emitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenResourceBinding {
    pub path: String,
    pub identity: FileIdentity,
}

/// A descriptor-based filesystem grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemGrant {
    pub fd_slot: u32,
    pub access: FilesystemGrantAccess,
    pub identity: FileIdentity,
}

/// Desired Landlock policy. This is configuration, not enforcement evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockPolicyPlan {
    pub default_filesystem_deny: bool,
    pub network_mode: NetworkMode,
    pub forbidden_resources: Vec<ForbiddenResourceBinding>,
    pub grants: Vec<FilesystemGrant>,
}

/// Default action for the independent seccomp filter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompDefaultAction {
    KillProcess,
}

/// Comparison applied to a seccomp syscall argument.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompArgumentComparison {
    Equal,
}

/// Required argument value for a reviewed syscall rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallArgumentConstraint {
    pub argument_index: u8,
    pub comparison: SeccompArgumentComparison,
    pub value: u64,
}

/// Resource limits applied by cage-init before target exec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimitPlan {
    pub nofile_soft: u64,
    pub nofile_hard: u64,
}

/// Enforcement mechanisms required by the compiled profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequiredEnforcement {
    pub landlock_full: bool,
    pub seccomp_default_deny: bool,
    pub ptrace_exec_observation: bool,
}

/// Canonical plan later sealed and consumed by cage-init.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageInitPlan {
    pub schema: String,
    pub compiler_version: String,
    pub manifest_digest: String,
    pub profile_digest: String,
    pub plan_fd_slot: u32,
    pub status_fd_slot: u32,
    pub helper_fd_slot: u32,
    pub target_fd_slot: u32,
    pub working_directory_fd_slot: u32,
    pub target_argv: Vec<String>,
    pub fd_table: Vec<FdTableEntry>,
    pub landlock: LandlockPolicyPlan,
    pub seccomp: SeccompProfilePlan,
    pub resource_limits: ResourceLimitPlan,
    pub execution_identity: ExecutionIdentity,
    pub environment: BTreeMap<String, String>,
    pub broker_authentication_digest: Option<String>,
}

/// Validate the target executable entry against identity and content observed
/// from the retained or received target descriptor.
pub fn validate_cage_target_fd_binding(
    plan: &CageInitPlan,
    observed_binding_digest: &str,
    observed_identity: FileIdentity,
) -> Result<(), CageError> {
    if plan.schema != CAGE_INIT_PLAN_SCHEMA
        || plan.compiler_version != CAGE_COMPILER_VERSION
        || plan.target_fd_slot != TARGET_FD_SLOT
    {
        return Err(CageError::InvalidTargetFdBinding("plan_version"));
    }
    validate_sha256_hex(observed_binding_digest, "target binding digest")?;
    let mut targets = plan
        .fd_table
        .iter()
        .filter(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable));
    let target = targets
        .next()
        .ok_or(CageError::InvalidTargetFdBinding("target_entry"))?;
    if targets.next().is_some() {
        return Err(CageError::InvalidTargetFdBinding("target_entry_count"));
    }
    if target.slot != plan.target_fd_slot
        || !target.close_on_exec
        || target.binding_digest.as_deref() != Some(observed_binding_digest)
        || target.identity != observed_identity
    {
        return Err(CageError::InvalidTargetFdBinding("target_descriptor"));
    }
    let alternatives = plan
        .seccomp
        .argument_constraints
        .get(&crate::Syscall::Execveat)
        .filter(|alternatives| !alternatives.is_empty())
        .ok_or(CageError::InvalidTargetFdBinding("execveat_target"))?;
    for constraints in alternatives {
        let mut targets = constraints
            .iter()
            .filter(|constraint| constraint.argument_index == 0);
        let target = targets
            .next()
            .ok_or(CageError::InvalidTargetFdBinding("execveat_target"))?;
        if targets.next().is_some()
            || target.comparison != SeccompArgumentComparison::Equal
            || target.value != u64::from(plan.target_fd_slot)
        {
            return Err(CageError::InvalidTargetFdBinding("execveat_target"));
        }
    }
    Ok(())
}

pub fn validate_target_argv(target_argv: &[String]) -> Result<(), CageError> {
    if target_argv.is_empty()
        || target_argv.first().is_some_and(String::is_empty)
        || target_argv.len() > MAX_TARGET_ARG_COUNT
    {
        return Err(CageError::InvalidTargetArgv);
    }
    let mut total = 0_usize;
    for argument in target_argv {
        if argument.as_bytes().contains(&0) || argument.len() > MAX_TARGET_ARG_BYTES {
            return Err(CageError::InvalidTargetArgv);
        }
        total = total
            .checked_add(argument.len().saturating_add(1))
            .ok_or(CageError::InvalidTargetArgv)?;
        if total > MAX_TARGET_ARGV_BYTES {
            return Err(CageError::InvalidTargetArgv);
        }
    }
    Ok(())
}

pub fn validate_sha256_hex(value: &str, field: &'static str) -> Result<(), CageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CageError::InvalidDigest(field));
    }
    Ok(())
}

/// Reviewed native syscall profiles accepted by cage admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSyscallProfile {
    NativeMinimalV1,
    NativeStandardV1,
    BrokeredNativeV1,
}
