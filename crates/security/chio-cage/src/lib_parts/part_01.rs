use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chio_manifest::{
    EnvironmentVariableName, NativeSyscallProfile, NetworkDestination, VerifiedCageManifest,
};
use serde::{Deserialize, Serialize};

pub use enforcement::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord,
    CageEnforcementState, EnforcementEvidenceError, EnforcementPrepared, ExecTransitionObserved,
    FullyEnforcedEvidence, ObservedRulesetStatus, ProcessExitEvidence, SeccompEnforcementStatus,
    CAGE_ENFORCEMENT_RECORD_SCHEMA, ENFORCEMENT_PREPARED_SCHEMA, EXEC_TRANSITION_OBSERVED_SCHEMA,
    MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION, PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION,
};
#[cfg(feature = "enforcement-mutants")]
#[doc(hidden)]
pub use launch::EnforcementMutation;
pub use launch::{
    launch, launch_prepared, prepare_launch, prepare_launch_with_options, run_cage_init,
    validate_cage_target_fd_binding_production_paths, CageLaunchError, CageLaunchOptions,
    CageLaunchPreparationEvidence, CageTargetFdBindingMutation,
    CageTargetFdBindingProductionValidation, EnforcedChild, EnforcedStdio, PreparedCageLaunch,
    TerminationSignal,
};
pub use receipt::{
    persist_signed_cage_receipt, persist_signed_cage_receipt_with_trusted_key,
    prepare_cage_receipt, sign_cage_receipt, verify_signed_cage_receipt,
    verify_signed_cage_receipt_with_trusted_key, CageReceiptBindings, CageReceiptBody,
    CageReceiptError, CageReceiptPersistenceError, CageReceiptSigningContext, CageReceiptStage,
    PreparedCageReceipt, CAGE_RECEIPT_BODY_SCHEMA, CAGE_RECEIPT_METADATA_SCHEMA,
};

/// Cage compiler schema emitted by this crate.
pub const COMPILED_SANDBOX_PROFILE_SCHEMA: &str = "chio.cage.compiled-sandbox-profile.v2";
/// Cage-init plan schema emitted by this crate.
pub const CAGE_INIT_PLAN_SCHEMA: &str = "chio.cage.init-plan.v2";
/// Version of the deterministic compiler semantics.
pub const CAGE_COMPILER_VERSION: &str = "chio-cage-compiler.v2";

const PLAN_FD_SLOT: u32 = 3;
const STATUS_FD_SLOT: u32 = 4;
const HELPER_FD_SLOT: u32 = 5;
const WORKING_DIRECTORY_FD_SLOT: u32 = 6;
#[cfg(target_os = "linux")]
const TARGET_STDIN_FD_SLOT: u32 = 7;
const BROKER_IPC_FD_SLOT: u32 = 8;
#[cfg(target_os = "linux")]
const TARGET_STDOUT_FD_SLOT: u32 = 9;
#[cfg(target_os = "linux")]
const TARGET_STDERR_FD_SLOT: u32 = 10;
const RUNTIME_FD_SLOT_START: u32 = 16;
const READ_GRANT_FD_SLOT_START: u32 = 64;
const WRITE_GRANT_FD_SLOT_START: u32 = 128;
// The target remains inherited above this ceiling so its execveat exception
// cannot be recreated after the close-on-exec transition.
const CHILD_NOFILE_LIMIT: u64 = 192;
const TARGET_FD_SLOT: u32 = 255;
const AT_EMPTY_PATH: u64 = 0x1000;
const MAX_RUNTIME_RESOURCES: usize = 48;
const MAX_READ_GRANTS: usize = 64;
const MAX_WRITE_GRANTS: usize = 64;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 16 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_TARGET_ARG_COUNT: usize = 256;
const MAX_TARGET_ARG_BYTES: usize = 16 * 1024;
const MAX_TARGET_ARGV_BYTES: usize = 128 * 1024;
/// Operator maxima applied after publisher authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorCeilings {
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    network_destinations: BTreeSet<NetworkDestination>,
    environment_variables: BTreeSet<EnvironmentVariableName>,
    native_syscall_profiles: BTreeSet<NativeSyscallProfile>,
    forbidden_paths: Option<BTreeSet<PathBuf>>,
}

impl OperatorCeilings {
    #[must_use]
    pub fn new(
        read_paths: BTreeSet<PathBuf>,
        write_paths: BTreeSet<PathBuf>,
        network_destinations: BTreeSet<NetworkDestination>,
        environment_variables: BTreeSet<EnvironmentVariableName>,
        native_syscall_profiles: BTreeSet<NativeSyscallProfile>,
    ) -> Self {
        Self {
            read_paths,
            write_paths,
            network_destinations,
            environment_variables,
            native_syscall_profiles,
            forbidden_paths: None,
        }
    }

    /// Add the complete operator-forbidden filesystem set.
    #[must_use]
    pub fn with_forbidden_paths(mut self, forbidden_paths: BTreeSet<PathBuf>) -> Self {
        self.forbidden_paths = Some(forbidden_paths);
        self
    }

    fn validate(&self) -> Result<(), CageError> {
        let forbidden_paths = self
            .forbidden_paths
            .as_ref()
            .ok_or(CageError::MissingForbiddenPathPolicy)?;
        for path in self
            .read_paths
            .iter()
            .chain(&self.write_paths)
            .chain(forbidden_paths)
        {
            validate_absolute_path(path)?;
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, CageError> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            read_paths: Vec<&'a str>,
            write_paths: Vec<&'a str>,
            network_destinations: &'a BTreeSet<NetworkDestination>,
            environment_variables: &'a BTreeSet<EnvironmentVariableName>,
            native_syscall_profiles: &'a BTreeSet<NativeSyscallProfile>,
            forbidden_paths: Vec<&'a str>,
        }

        let read_paths = path_texts(&self.read_paths)?;
        let write_paths = path_texts(&self.write_paths)?;
        let forbidden_paths = path_texts(
            self.forbidden_paths
                .as_ref()
                .ok_or(CageError::MissingForbiddenPathPolicy)?,
        )?;
        digest(&Binding {
            schema: "chio.cage.operator-ceilings.v1",
            read_paths,
            write_paths,
            network_destinations: &self.network_destinations,
            environment_variables: &self.environment_variables,
            native_syscall_profiles: &self.native_syscall_profiles,
            forbidden_paths,
        })
    }
}

/// Access expected for a retained filesystem grant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedAccess {
    Read,
    WriteExactFile,
}

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
    device: u64,
    inode: u64,
    mount_id: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    kind: ResourceKind,
}

impl FileIdentity {
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
    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.kind == other.kind
    }
}

/// File revision bound to a content digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRevision {
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileRevision {
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }
}

/// A validated resource that stays bound to its original kernel object.
#[derive(Debug)]
pub struct RetainedResource {
    path: PathBuf,
    identity: FileIdentity,
    expected_access: ExpectedAccess,
    creation_parent: Option<Box<RetainedResource>>,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
}

impl RetainedResource {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[must_use]
    pub const fn expected_access(&self) -> ExpectedAccess {
        self.expected_access
    }

    #[must_use]
    pub fn creation_parent(&self) -> Option<&RetainedResource> {
        self.creation_parent.as_deref()
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }
}

/// Verified manifest digest and descriptor-owned filesystem grants.
#[derive(Debug)]
pub struct AdmittedManifest {
    manifest_digest: String,
    signed_manifest_digest: String,
    registry_digest: String,
    cage_authorization_digest: String,
    operator_ceiling_digest: String,
    read_resources: Vec<RetainedResource>,
    write_resources: Vec<RetainedResource>,
    forbidden_resources: Vec<RetainedResource>,
    network_destinations: BTreeSet<NetworkDestination>,
    environment_variables: BTreeSet<EnvironmentVariableName>,
    native_syscall_profile: NativeSyscallProfile,
}

impl AdmittedManifest {
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    #[must_use]
    pub fn signed_manifest_digest(&self) -> &str {
        &self.signed_manifest_digest
    }

    #[must_use]
    pub fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    #[must_use]
    pub fn cage_authorization_digest(&self) -> &str {
        &self.cage_authorization_digest
    }

    #[must_use]
    pub fn operator_ceiling_digest(&self) -> &str {
        &self.operator_ceiling_digest
    }

    #[must_use]
    pub fn read_resources(&self) -> &[RetainedResource] {
        &self.read_resources
    }

    #[must_use]
    pub fn write_resources(&self) -> &[RetainedResource] {
        &self.write_resources
    }

    #[must_use]
    pub fn forbidden_resources(&self) -> &[RetainedResource] {
        &self.forbidden_resources
    }

    #[must_use]
    pub fn network_destinations(&self) -> &BTreeSet<NetworkDestination> {
        &self.network_destinations
    }

    #[must_use]
    pub fn environment_variables(&self) -> &BTreeSet<EnvironmentVariableName> {
        &self.environment_variables
    }

    #[must_use]
    pub const fn native_syscall_profile(&self) -> NativeSyscallProfile {
        self.native_syscall_profile
    }
}

/// Trusted helper, target, working-directory, and runtime paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeResourcePaths {
    helper: PathBuf,
    target: PathBuf,
    working_directory: PathBuf,
    runtime_files: BTreeSet<PathBuf>,
    max_artifact_bytes: u64,
    target_argv: Option<Vec<String>>,
    execution_identity: ExecutionIdentity,
}

impl RuntimeResourcePaths {
    #[must_use]
    pub fn new(
        helper: PathBuf,
        target: PathBuf,
        working_directory: PathBuf,
        runtime_files: BTreeSet<PathBuf>,
        execution_identity: ExecutionIdentity,
    ) -> Self {
        Self {
            helper,
            target,
            working_directory,
            runtime_files,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            target_argv: None,
            execution_identity,
        }
    }

    /// Lower the maximum accepted size for each hashed artifact.
    #[must_use]
    pub fn with_max_artifact_bytes(mut self, max_artifact_bytes: u64) -> Self {
        self.max_artifact_bytes = max_artifact_bytes;
        self
    }

    /// Bind the exact target argument vector into the sealed launch plan.
    #[must_use]
    pub fn with_target_argv(mut self, target_argv: Vec<String>) -> Self {
        self.target_argv = Some(target_argv);
        self
    }
}

/// Role of a retained trusted runtime artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactRole {
    CageInitHelper,
    TargetExecutable,
    WorkingDirectory,
    RuntimeFile,
}

/// A retained runtime artifact and its content or identity digest.
#[derive(Debug)]
pub struct RetainedRuntimeArtifact {
    role: RuntimeArtifactRole,
    resource: RetainedResource,
    binding_digest: String,
    revision: Option<FileRevision>,
}

impl RetainedRuntimeArtifact {
    #[must_use]
    pub const fn role(&self) -> RuntimeArtifactRole {
        self.role
    }

    #[must_use]
    pub fn resource(&self) -> &RetainedResource {
        &self.resource
    }

    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Option<FileRevision> {
        self.revision
    }
}

/// Descriptor-owned trusted runtime inputs.
#[derive(Debug)]
pub struct RetainedRuntimeResources {
    helper: RetainedRuntimeArtifact,
    target: RetainedRuntimeArtifact,
    working_directory: RetainedRuntimeArtifact,
    runtime_files: Vec<RetainedRuntimeArtifact>,
    target_argv: Vec<String>,
    execution_identity: ExecutionIdentity,
}

impl RetainedRuntimeResources {
    #[must_use]
    pub fn helper(&self) -> &RetainedRuntimeArtifact {
        &self.helper
    }

    #[must_use]
    pub fn target(&self) -> &RetainedRuntimeArtifact {
        &self.target
    }

    #[must_use]
    pub fn working_directory(&self) -> &RetainedRuntimeArtifact {
        &self.working_directory
    }

    #[must_use]
    pub fn runtime_files(&self) -> &[RetainedRuntimeArtifact] {
        &self.runtime_files
    }

    #[must_use]
    pub fn target_argv(&self) -> &[String] {
        &self.target_argv
    }

    #[must_use]
    pub const fn execution_identity(&self) -> &ExecutionIdentity {
        &self.execution_identity
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
        match std::env::consts::ARCH {
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

/// Reviewed architecture-specific syscall plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompProfilePlan {
    pub architecture: SandboxArchitecture,
    pub profile: NativeSyscallProfile,
    pub default_action: SeccompDefaultAction,
    pub allowed_syscalls: Vec<String>,
    pub argument_constraints: BTreeMap<String, Vec<SyscallArgumentConstraint>>,
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

/// Deterministic profile binding every semantic compiler input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompiledSandboxProfile {
    pub schema: &'static str,
    pub compiler_version: &'static str,
    pub manifest_digest: String,
    pub cage_authorization_digest: String,
    pub operator_ceiling_digest: String,
    pub fd_table_digest: String,
    pub landlock_plan_digest: String,
    pub seccomp_profile_digest: String,
    pub resource_limits_digest: String,
    pub execution_identity_digest: String,
    pub environment_names: BTreeSet<String>,
    pub environment_digest: String,
    pub declared_network_destinations_digest: String,
    pub helper_binding_digest: String,
    pub target_binding_digest: String,
    pub native_syscall_profile: NativeSyscallProfile,
    pub network_mode: NetworkMode,
    pub required_enforcement: RequiredEnforcement,
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
    let mut execveat_target_constraints = plan
        .seccomp
        .argument_constraints
        .get("execveat")
        .into_iter()
        .flatten()
        .filter(|constraint| constraint.argument_index == 0);
    let target_constraint = execveat_target_constraints
        .next()
        .ok_or(CageError::InvalidTargetFdBinding("execveat_target"))?;
    if execveat_target_constraints.next().is_some()
        || target_constraint.comparison != SeccompArgumentComparison::Equal
        || target_constraint.value != u64::from(plan.target_fd_slot)
    {
        return Err(CageError::InvalidTargetFdBinding("execveat_target"));
    }
    Ok(())
}

/// Descriptor and proof for an already-connected authenticated broker channel.
#[derive(Debug)]
pub struct BrokerIpc {
    authentication_digest: String,
    identity: FileIdentity,
    peer_identity: BrokerPeerIdentity,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
}

impl BrokerIpc {
    #[must_use]
    pub fn authentication_digest(&self) -> &str {
        &self.authentication_digest
    }

    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[must_use]
    pub const fn peer_identity(&self) -> BrokerPeerIdentity {
        self.peer_identity
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }
}

/// Compiled configuration plus every descriptor it binds.
#[derive(Debug)]
pub struct CompiledCage {
    profile: CompiledSandboxProfile,
    profile_digest: String,
    plan: CageInitPlan,
    plan_digest: String,
    admitted: AdmittedManifest,
    runtime: RetainedRuntimeResources,
    broker_ipc: Option<BrokerIpc>,
    #[cfg(target_os = "linux")]
    target_stdio: Option<CompiledTargetStdio>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct CompiledTargetStdio {
    parent_stdin: Option<std::fs::File>,
    parent_stdout: Option<std::fs::File>,
    parent_stderr: Option<std::fs::File>,
    child_stdin: std::fs::File,
    child_stdout: std::fs::File,
    child_stderr: std::fs::File,
}

#[cfg(target_os = "linux")]
impl CompiledTargetStdio {
    pub(crate) fn create() -> Result<Self, CageError> {
        fn pair() -> Result<(std::fs::File, std::fs::File), CageError> {
            use std::os::fd::OwnedFd;
            use std::os::unix::net::UnixStream;

            let (parent, child) = UnixStream::pair().map_err(CageError::TargetStdio)?;
            Ok((
                std::fs::File::from(OwnedFd::from(parent)),
                std::fs::File::from(OwnedFd::from(child)),
            ))
        }

        let (parent_stdin, child_stdin) = pair()?;
        let (parent_stdout, child_stdout) = pair()?;
        let (parent_stderr, child_stderr) = pair()?;
        let stdio = Self {
            parent_stdin: Some(parent_stdin),
            parent_stdout: Some(parent_stdout),
            parent_stderr: Some(parent_stderr),
            child_stdin,
            child_stdout,
            child_stderr,
        };
        stdio.verify()?;
        Ok(stdio)
    }

    fn verify(&self) -> Result<(), CageError> {
        for file in [
            self.parent_stdin.as_ref(),
            self.parent_stdout.as_ref(),
            self.parent_stderr.as_ref(),
            Some(&self.child_stdin),
            Some(&self.child_stdout),
            Some(&self.child_stderr),
        ] {
            let file = file.ok_or(CageError::TargetStdioUnavailable)?;
            if linux::descriptor_identity(file, None)?.kind() != ResourceKind::UnixSocket {
                return Err(CageError::InvalidTargetStdio);
            }
        }
        Ok(())
    }

    fn entries(&self) -> Result<[FdTableEntry; 3], CageError> {
        let entry = |slot, purpose, file: &std::fs::File| -> Result<FdTableEntry, CageError> {
            Ok(FdTableEntry {
                slot,
                purpose,
                identity: linux::descriptor_identity(file, None)?,
                path: None,
                binding_digest: None,
                broker_peer_identity: None,
                close_on_exec: true,
            })
        };
        Ok([
            entry(
                TARGET_STDIN_FD_SLOT,
                FdPurpose::TargetStdin,
                &self.child_stdin,
            )?,
            entry(
                TARGET_STDOUT_FD_SLOT,
                FdPurpose::TargetStdout,
                &self.child_stdout,
            )?,
            entry(
                TARGET_STDERR_FD_SLOT,
                FdPurpose::TargetStderr,
                &self.child_stderr,
            )?,
        ])
    }

    pub(crate) fn child_file(&self, purpose: &FdPurpose) -> Option<&std::fs::File> {
        match purpose {
            FdPurpose::TargetStdin => Some(&self.child_stdin),
            FdPurpose::TargetStdout => Some(&self.child_stdout),
            FdPurpose::TargetStderr => Some(&self.child_stderr),
            _ => None,
        }
    }

    fn take_parent(&mut self) -> Option<(std::fs::File, std::fs::File, std::fs::File)> {
        if self.parent_stdin.is_none()
            || self.parent_stdout.is_none()
            || self.parent_stderr.is_none()
        {
            return None;
        }
        Some((
            self.parent_stdin.take()?,
            self.parent_stdout.take()?,
            self.parent_stderr.take()?,
        ))
    }
}

impl CompiledCage {
    #[must_use]
    pub fn profile(&self) -> &CompiledSandboxProfile {
        &self.profile
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    /// Inspect the compiled pre-launch plan. Target stdio descriptors are bound
    /// internally by `launch`, so this view is not yet a cage-init wire plan.
    pub fn plan(&self) -> &CageInitPlan {
        &self.plan
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    #[must_use]
    pub fn admitted(&self) -> &AdmittedManifest {
        &self.admitted
    }

    #[must_use]
    pub fn runtime(&self) -> &RetainedRuntimeResources {
        &self.runtime
    }

    #[must_use]
    pub fn broker_ipc(&self) -> Option<&BrokerIpc> {
        self.broker_ipc.as_ref()
    }

    /// Canonical bytes to place in a sealed profile artifact.
    pub fn canonical_profile_bytes(&self) -> Result<Vec<u8>, CageError> {
        Ok(chio_core::canonical_json_bytes(&self.profile)?)
    }

    /// Canonical bytes for the launch-bound cage-init plan descriptor.
    ///
    /// Publicly compiled plans do not yet own target stdio, so only the launch
    /// path can produce this wire artifact after binding all three descriptors.
    pub fn canonical_plan_bytes(&self) -> Result<Vec<u8>, CageError> {
        #[cfg(target_os = "linux")]
        {
            if self.target_stdio.is_none() {
                return Err(CageError::TargetStdioUnavailable);
            }
            Ok(chio_core::canonical_json_bytes(&self.plan)?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageError::UnsupportedPlatform)
        }
    }

    /// Revalidate all retained identities and hashed artifacts before launch.
    pub fn verify_retained_bindings(&self) -> Result<(), CageError> {
        #[cfg(target_os = "linux")]
        {
            linux::verify_admitted_resources(&self.admitted)?;
            linux::verify_runtime_resources(&self.runtime)?;
            if let Some(broker) = self.broker_ipc.as_ref() {
                linux::verify_broker_ipc(broker)?;
            }
            if let Some(target_stdio) = self.target_stdio.as_ref() {
                target_stdio.verify()?;
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageError::UnsupportedPlatform)
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bind_target_stdio(
        &mut self,
        target_stdio: CompiledTargetStdio,
    ) -> Result<(), CageError> {
        if self.target_stdio.is_some()
            || self.plan.fd_table.iter().any(|entry| {
                matches!(
                    entry.purpose,
                    FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr
                )
            })
        {
            return Err(CageError::TargetStdioAlreadyBound);
        }
        self.plan.fd_table.extend(target_stdio.entries()?);
        self.plan.fd_table.sort_by_key(|entry| entry.slot);
        if self
            .plan
            .fd_table
            .windows(2)
            .any(|entries| entries[0].slot == entries[1].slot)
        {
            return Err(CageError::DuplicateFdSlot);
        }
        self.profile.fd_table_digest = digest(&self.plan.fd_table)?;
        self.profile_digest = digest(&self.profile)?;
        self.plan.profile_digest.clone_from(&self.profile_digest);
        self.plan_digest = digest(&self.plan)?;
        self.target_stdio = Some(target_stdio);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn target_stdio(&self) -> Option<&CompiledTargetStdio> {
        self.target_stdio.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_parent_stdio(
        &mut self,
    ) -> Option<(std::fs::File, std::fs::File, std::fs::File)> {
        self.target_stdio.as_mut()?.take_parent()
    }
}

/// Consume registry-issued native-cage authorization and retain every filesystem grant.
pub fn admit(
    authorization: VerifiedCageManifest<'_>,
    ceilings: &OperatorCeilings,
) -> Result<AdmittedManifest, CageError> {
    let manifest_digest = authorization.manifest_digest().to_string();
    let signed_manifest_digest = authorization.signed_manifest_digest().to_string();
    let registry_digest = authorization.registry_digest().to_string();
    let cage_authorization_digest = authorization.authorization_digest().to_string();
    let permissions = authorization
        .signed_manifest()
        .manifest
        .required_permissions
        .as_ref()
        .ok_or(CageError::MissingRequiredPermissions)?;

    ceilings.validate()?;
    let read_paths = to_path_set(permissions.read_paths.as_deref())?;
    let write_paths = to_path_set(permissions.write_paths.as_deref())?;
    let network_destinations = permissions
        .network_destinations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let environment_variables = permissions
        .environment_variables
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();

    if !read_paths.is_disjoint(&write_paths) {
        return Err(CageError::AmbiguousFilesystemAccess);
    }
    if !read_paths.is_subset(&ceilings.read_paths)
        || !write_paths.is_subset(&ceilings.write_paths)
        || !network_destinations.is_subset(&ceilings.network_destinations)
        || !environment_variables.is_subset(&ceilings.environment_variables)
        || !ceilings
            .native_syscall_profiles
            .contains(&permissions.native_syscall_profile)
    {
        return Err(CageError::OperatorCeilingExceeded);
    }
    let forbidden_paths = ceilings
        .forbidden_paths
        .as_ref()
        .ok_or(CageError::MissingForbiddenPathPolicy)?;
    reject_forbidden_path_overlaps(&read_paths, &write_paths, forbidden_paths)?;
    let operator_ceiling_digest = ceilings.digest()?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            manifest_digest,
            signed_manifest_digest,
            registry_digest,
            cage_authorization_digest,
            operator_ceiling_digest,
            read_paths,
            write_paths,
            network_destinations,
            environment_variables,
        );
        Err(CageError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    {
        SandboxArchitecture::current()?;
        let forbidden_resources = linux::retain_forbidden(forbidden_paths)?;
        let read_resources = linux::retain_read_grants(&read_paths)?;
        let write_resources = linux::retain_write_grants(&write_paths)?;
        reject_descriptor_aliases(&forbidden_resources, &read_resources, &write_resources)?;
        Ok(AdmittedManifest {
            manifest_digest,
            signed_manifest_digest,
            registry_digest,
            cage_authorization_digest,
            operator_ceiling_digest,
            read_resources,
            write_resources,
            forbidden_resources,
            network_destinations,
            environment_variables,
            native_syscall_profile: permissions.native_syscall_profile,
        })
    }
}

/// Retain and hash every trusted runtime input without reopening it by name.
pub fn retain_runtime_resources(
    paths: &RuntimeResourcePaths,
) -> Result<RetainedRuntimeResources, CageError> {
    paths.execution_identity.validate()?;
    if paths.max_artifact_bytes == 0 || paths.max_artifact_bytes > DEFAULT_MAX_ARTIFACT_BYTES {
        return Err(CageError::InvalidLimit("max artifact bytes"));
    }
    if paths.runtime_files.len() > MAX_RUNTIME_RESOURCES {
        return Err(CageError::ResourceLimitExceeded("runtime files"));
    }
    validate_absolute_path(&paths.helper)?;
    validate_absolute_path(&paths.target)?;
    validate_absolute_path(&paths.working_directory)?;
    for path in &paths.runtime_files {
        validate_absolute_path(path)?;
    }
    let target_argv = paths.target_argv.clone().unwrap_or_else(|| {
        paths
            .target
            .to_str()
            .map(str::to_string)
            .into_iter()
            .collect()
    });
    validate_target_argv(&target_argv)?;

    #[cfg(not(target_os = "linux"))]
    {
        Err(CageError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    {
        SandboxArchitecture::current()?;
        let helper = linux::retain_runtime_artifact(
            &paths.helper,
            RuntimeArtifactRole::CageInitHelper,
            paths.max_artifact_bytes,
        )?;
        let target = linux::retain_runtime_artifact(
            &paths.target,
            RuntimeArtifactRole::TargetExecutable,
            paths.max_artifact_bytes,
        )?;
        let working_directory = linux::retain_runtime_artifact(
            &paths.working_directory,
            RuntimeArtifactRole::WorkingDirectory,
            paths.max_artifact_bytes,
        )?;
        let runtime_files = paths
            .runtime_files
            .iter()
            .map(|path| {
                linux::retain_runtime_artifact(
                    path,
                    RuntimeArtifactRole::RuntimeFile,
                    paths.max_artifact_bytes,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        reject_runtime_aliases(&helper, &target, &working_directory, &runtime_files)?;
        Ok(RetainedRuntimeResources {
            helper,
            target,
            working_directory,
            runtime_files,
            target_argv,
            execution_identity: paths.execution_identity.clone(),
        })
    }
}

/// Validate an already-connected broker descriptor and bind its authentication proof.
#[cfg(target_os = "linux")]
pub fn retain_broker_ipc(
    file: std::fs::File,
    authentication_digest: impl Into<String>,
    expected_peer_identity: BrokerPeerIdentity,
) -> Result<BrokerIpc, CageError> {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let authentication_digest = authentication_digest.into();
    SandboxArchitecture::current()?;
    validate_sha256_hex(&authentication_digest, "broker authentication digest")?;
    let descriptor = OwnedFd::from(file);
    let stream = UnixStream::from(descriptor);
    stream
        .peer_addr()
        .map_err(|_| CageError::InvalidBrokerDescriptor)?;
    let descriptor = OwnedFd::from(stream);
    let file = std::fs::File::from(descriptor);
    let identity = linux::descriptor_identity(&file, None)?;
    if identity.kind != ResourceKind::UnixSocket {
        return Err(CageError::InvalidBrokerDescriptor);
    }
    let peer_identity = linux::broker_peer_identity(&file)?;
    if peer_identity != expected_peer_identity {
        return Err(CageError::BrokerPeerIdentityMismatch);
    }
    Ok(BrokerIpc {
        authentication_digest,
        identity,
        peer_identity,
        file,
    })
}

/// Non-Linux platforms cannot produce a broker descriptor accepted for launch.
#[cfg(not(target_os = "linux"))]
pub fn retain_broker_ipc(
    _file: std::fs::File,
    _authentication_digest: impl Into<String>,
    _expected_peer_identity: BrokerPeerIdentity,
) -> Result<BrokerIpc, CageError> {
    Err(CageError::UnsupportedPlatform)
}

/// Compile descriptor-owned admission into a deterministic deny-all plan.
pub fn compile(
    admitted: AdmittedManifest,
    runtime: RetainedRuntimeResources,
    parent_environment: &BTreeMap<String, String>,
    broker_ipc: Option<BrokerIpc>,
) -> Result<CompiledCage, CageError> {
    if admitted.read_resources.len() > MAX_READ_GRANTS {
        return Err(CageError::ResourceLimitExceeded("read grants"));
    }
    if admitted.write_resources.len() > MAX_WRITE_GRANTS {
        return Err(CageError::ResourceLimitExceeded("write grants"));
    }
    let brokered_profile =
        admitted.native_syscall_profile == NativeSyscallProfile::BrokeredNativeV1;
    if brokered_profile != broker_ipc.is_some()
        || (!admitted.network_destinations.is_empty() && broker_ipc.is_none())
    {
        return Err(CageError::BrokerProfileMismatch);
    }

    #[cfg(target_os = "linux")]
    {
        linux::verify_admitted_resources(&admitted)?;
        linux::verify_runtime_resources(&runtime)?;
        validate_runtime_file_authority(&admitted, &runtime)?;
        if let Some(broker) = broker_ipc.as_ref() {
            linux::verify_broker_ipc(broker)?;
        }
    }
    if !cfg!(target_os = "linux") {
        let _ = (&runtime, parent_environment, &broker_ipc);
        return Err(CageError::UnsupportedPlatform);
    }

    let architecture = SandboxArchitecture::current()?;
    let environment = build_environment(&admitted.environment_variables, parent_environment)?;
    let fd_table = build_fd_table(&admitted, &runtime, broker_ipc.as_ref())?;
    let landlock = build_landlock_plan(&admitted, &fd_table)?;
    let seccomp = build_seccomp_plan(architecture, admitted.native_syscall_profile)?;
    let resource_limits = ResourceLimitPlan {
        nofile_soft: CHILD_NOFILE_LIMIT,
        nofile_hard: CHILD_NOFILE_LIMIT,
    };
    let fd_table_digest = digest(&fd_table)?;
    let landlock_plan_digest = digest(&landlock)?;
    let seccomp_profile_digest = digest(&seccomp)?;
    let resource_limits_digest = digest(&resource_limits)?;
    let execution_identity_digest = digest(&runtime.execution_identity)?;
    let environment_digest = digest(&environment)?;
    let declared_network_destinations_digest = digest(&admitted.network_destinations)?;
    let environment_names = environment.keys().cloned().collect::<BTreeSet<_>>();
    let profile = CompiledSandboxProfile {
        schema: COMPILED_SANDBOX_PROFILE_SCHEMA,
        compiler_version: CAGE_COMPILER_VERSION,
        manifest_digest: admitted.manifest_digest.clone(),
        cage_authorization_digest: admitted.cage_authorization_digest.clone(),
        operator_ceiling_digest: admitted.operator_ceiling_digest.clone(),
        fd_table_digest,
        landlock_plan_digest,
        seccomp_profile_digest,
        resource_limits_digest,
        execution_identity_digest,
        environment_names,
        environment_digest,
        declared_network_destinations_digest,
        helper_binding_digest: runtime.helper.binding_digest.clone(),
        target_binding_digest: runtime.target.binding_digest.clone(),
        native_syscall_profile: admitted.native_syscall_profile,
        network_mode: NetworkMode::Blocked,
        required_enforcement: RequiredEnforcement {
            landlock_full: true,
            seccomp_default_deny: true,
            ptrace_exec_observation: true,
        },
    };
    let profile_digest = digest(&profile)?;
    let broker_authentication_digest = broker_ipc
        .as_ref()
        .map(|ipc| ipc.authentication_digest.clone());
    let plan = CageInitPlan {
        schema: CAGE_INIT_PLAN_SCHEMA.to_string(),
        compiler_version: CAGE_COMPILER_VERSION.to_string(),
        manifest_digest: admitted.manifest_digest.clone(),
        profile_digest: profile_digest.clone(),
        plan_fd_slot: PLAN_FD_SLOT,
        status_fd_slot: STATUS_FD_SLOT,
        helper_fd_slot: HELPER_FD_SLOT,
        target_fd_slot: TARGET_FD_SLOT,
        working_directory_fd_slot: WORKING_DIRECTORY_FD_SLOT,
        target_argv: runtime.target_argv.clone(),
        fd_table,
        landlock,
        seccomp,
        resource_limits,
        execution_identity: runtime.execution_identity.clone(),
        environment,
        broker_authentication_digest,
    };
    let plan_digest = digest(&plan)?;
    Ok(CompiledCage {
        profile,
        profile_digest,
        plan,
        plan_digest,
        admitted,
        runtime,
        broker_ipc,
        #[cfg(target_os = "linux")]
        target_stdio: None,
    })
}

fn to_path_set(values: Option<&[String]>) -> Result<BTreeSet<PathBuf>, CageError> {
    values
        .unwrap_or_default()
        .iter()
        .map(|value| {
            let path = PathBuf::from(value);
            validate_absolute_path(&path)?;
            Ok(path)
        })
        .collect()
}

fn validate_absolute_path(path: &Path) -> Result<(), CageError> {
    let text = path
        .to_str()
        .ok_or_else(|| CageError::InvalidPath(path.to_path_buf()))?;
    let canonical_components = text.strip_prefix('/').is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix.ends_with('/')
            && suffix
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
    });
    if !path.is_absolute()
        || path == Path::new("/")
        || !canonical_components
        || text.trim() != text
        || text.chars().any(char::is_control)
        || text.as_bytes().contains(&0)
    {
        return Err(CageError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_target_argv(target_argv: &[String]) -> Result<(), CageError> {
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

fn path_texts(paths: &BTreeSet<PathBuf>) -> Result<Vec<&str>, CageError> {
    paths
        .iter()
        .map(|path| {
            path.to_str()
                .ok_or_else(|| CageError::InvalidPath(path.clone()))
        })
        .collect()
}

fn reject_forbidden_path_overlaps(
    read_paths: &BTreeSet<PathBuf>,
    write_paths: &BTreeSet<PathBuf>,
    forbidden_paths: &BTreeSet<PathBuf>,
) -> Result<(), CageError> {
    for allowed in read_paths.iter().chain(write_paths) {
        for forbidden in forbidden_paths {
            if allowed.starts_with(forbidden) || forbidden.starts_with(allowed) {
                return Err(CageError::ForbiddenPathOverlap {
                    allowed: allowed.clone(),
                    forbidden: forbidden.clone(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_descriptor_aliases(
    forbidden: &[RetainedResource],
    read: &[RetainedResource],
    write: &[RetainedResource],
) -> Result<(), CageError> {
    for allowed in read.iter().chain(write) {
        for denied in forbidden {
            if allowed.identity.same_object(denied.identity) {
                return Err(CageError::ForbiddenDescriptorAlias {
                    allowed: allowed.path.clone(),
                    forbidden: denied.path.clone(),
                });
            }
        }
    }
    let mut resources = read.iter().chain(write);
    let mut seen = Vec::<&RetainedResource>::new();
    for resource in &mut resources {
        if let Some(previous) = seen
            .iter()
            .find(|previous| previous.identity.same_object(resource.identity))
        {
            return Err(CageError::GrantDescriptorAlias {
                first: previous.path.clone(),
                second: resource.path.clone(),
            });
        }
        seen.push(resource);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_runtime_aliases(
    helper: &RetainedRuntimeArtifact,
    target: &RetainedRuntimeArtifact,
    working_directory: &RetainedRuntimeArtifact,
    runtime_files: &[RetainedRuntimeArtifact],
) -> Result<(), CageError> {
    let artifacts = std::iter::once(helper)
        .chain(std::iter::once(target))
        .chain(std::iter::once(working_directory))
        .chain(runtime_files);
    let mut seen = Vec::<&RetainedRuntimeArtifact>::new();
    for artifact in artifacts {
        if let Some(previous) = seen.iter().find(|previous| {
            previous
                .resource
                .identity
                .same_object(artifact.resource.identity)
        }) {
            return Err(CageError::RuntimeDescriptorAlias {
                first: previous.resource.path.clone(),
                second: artifact.resource.path.clone(),
            });
        }
        seen.push(artifact);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_runtime_file_authority(
    admitted: &AdmittedManifest,
    runtime: &RetainedRuntimeResources,
) -> Result<(), CageError> {
    for artifact in &runtime.runtime_files {
        for forbidden in &admitted.forbidden_resources {
            if artifact.resource.identity.same_object(forbidden.identity) {
                return Err(CageError::ForbiddenDescriptorAlias {
                    allowed: artifact.resource.path.clone(),
                    forbidden: forbidden.path.clone(),
                });
            }
        }

        let authorized = admitted
            .read_resources
            .iter()
            .find(|resource| resource.path == artifact.resource.path)
            .ok_or_else(|| CageError::UnauthorizedRuntimeFile(artifact.resource.path.clone()))?;
        if authorized.identity != artifact.resource.identity {
            return Err(CageError::RuntimeFileAuthorityChanged(
                artifact.resource.path.clone(),
            ));
        }
    }
    Ok(())
}

fn build_environment(
    allowed_names: &BTreeSet<EnvironmentVariableName>,
    parent: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CageError> {
    let mut environment = BTreeMap::from([
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("TZ".to_string(), "UTC".to_string()),
    ]);
    for name in allowed_names {
        let text = name.as_str();
        if text.len() > 128 || is_credential_or_injection_name(text) {
            return Err(CageError::ForbiddenEnvironmentVariable(text.to_string()));
        }
        if matches!(text, "LANG" | "LC_ALL" | "TZ") {
            continue;
        }
        let Some(value) = parent.get(text) else {
            continue;
        };
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.as_bytes().contains(&0)
            || value.chars().any(char::is_control)
        {
            return Err(CageError::InvalidEnvironmentValue(text.to_string()));
        }
        environment.insert(text.to_string(), value.clone());
    }
    let total_bytes = environment
        .iter()
        .map(|(name, value)| name.len() + value.len() + 2)
        .sum::<usize>();
    if total_bytes > MAX_ENVIRONMENT_BYTES {
        return Err(CageError::ResourceLimitExceeded("environment bytes"));
    }
    Ok(environment)
}

fn is_credential_or_injection_name(name: &str) -> bool {
    let normalized = name.to_ascii_uppercase();
    let name = normalized.as_str();
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("BASH_FUNC_")
        || name.starts_with("MALLOC_")
        || matches!(
            name,
            "BASH_ENV"
                | "DOCKER_CONFIG"
                | "ENV"
                | "GCONV_PATH"
                | "GEM_HOME"
                | "GEM_PATH"
                | "GIT_ASKPASS"
                | "GLIBC_TUNABLES"
                | "GPG_AGENT_INFO"
                | "IFS"
                | "JAVA_TOOL_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "KRB5CCNAME"
                | "LOCPATH"
                | "NETRC"
                | "NLSPATH"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "NPM_CONFIG_USERCONFIG"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PYTHONHOME"
                | "PYTHONINSPECT"
                | "PYTHONPATH"
                | "PYTHONSTARTUP"
                | "RUBYLIB"
                | "RUBYOPT"
                | "RUSTC_WRAPPER"
                | "SSLKEYLOGFILE"
                | "SSL_CERT_DIR"
                | "SSL_CERT_FILE"
                | "SSH_AUTH_SOCK"
                | "SUDO_ASKPASS"
                | "ZDOTDIR"
                | "_JAVA_OPTIONS"
        )
        || [
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "CREDENTIAL",
            "API_KEY",
            "PRIVATE_KEY",
            "ACCESS_KEY",
            "AUTHORIZATION",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}

fn build_fd_table(
    admitted: &AdmittedManifest,
    runtime: &RetainedRuntimeResources,
    broker_ipc: Option<&BrokerIpc>,
) -> Result<Vec<FdTableEntry>, CageError> {
    let mut entries = vec![
        artifact_fd_entry(HELPER_FD_SLOT, FdPurpose::CageInitHelper, &runtime.helper)?,
        artifact_fd_entry(TARGET_FD_SLOT, FdPurpose::TargetExecutable, &runtime.target)?,
        artifact_fd_entry(
            WORKING_DIRECTORY_FD_SLOT,
            FdPurpose::WorkingDirectory,
            &runtime.working_directory,
        )?,
    ];
    for (index, artifact) in runtime.runtime_files.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| CageError::FdSlotOverflow)?;
        entries.push(artifact_fd_entry(
            RUNTIME_FD_SLOT_START
                .checked_add(index)
                .ok_or(CageError::FdSlotOverflow)?,
            FdPurpose::RuntimeFile { index },
            artifact,
        )?);
    }
    for (index, resource) in admitted.read_resources.iter().enumerate() {
        if runtime
            .runtime_files
            .iter()
            .any(|artifact| artifact.resource.identity == resource.identity)
        {
            continue;
        }
        let index = u32::try_from(index).map_err(|_| CageError::FdSlotOverflow)?;
        entries.push(resource_fd_entry(
            READ_GRANT_FD_SLOT_START
                .checked_add(index)
                .ok_or(CageError::FdSlotOverflow)?,
            FdPurpose::ReadGrant { index },
            resource,
        )?);
    }
    for (index, resource) in admitted.write_resources.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| CageError::FdSlotOverflow)?;
        entries.push(resource_fd_entry(
            WRITE_GRANT_FD_SLOT_START
                .checked_add(index)
                .ok_or(CageError::FdSlotOverflow)?,
            FdPurpose::WriteGrant { index },
            resource,
        )?);
    }
    if let Some(ipc) = broker_ipc {
        entries.push(FdTableEntry {
            slot: BROKER_IPC_FD_SLOT,
            purpose: FdPurpose::BrokerIpc,
            identity: ipc.identity,
            path: None,
            binding_digest: Some(ipc.authentication_digest.clone()),
            broker_peer_identity: Some(ipc.peer_identity),
            close_on_exec: false,
        });
    }
    entries.sort_by_key(|entry| entry.slot);
    if entries
        .windows(2)
        .any(|window| window[0].slot == window[1].slot)
    {
        return Err(CageError::DuplicateFdSlot);
    }
    Ok(entries)
}

fn artifact_fd_entry(
    slot: u32,
    purpose: FdPurpose,
    artifact: &RetainedRuntimeArtifact,
) -> Result<FdTableEntry, CageError> {
    Ok(FdTableEntry {
        slot,
        purpose,
        identity: artifact.resource.identity,
        path: Some(path_text(&artifact.resource.path)?.to_string()),
        binding_digest: Some(artifact.binding_digest.clone()),
        broker_peer_identity: None,
        close_on_exec: true,
    })
}
