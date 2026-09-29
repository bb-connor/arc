use super::{PathBuf, SeccompPlanError};

/// Fail-closed cage admission and compilation errors.
#[derive(Debug, thiserror::Error)]
pub enum CageError {
    #[error("canonical cage encoding failed: {0}")]
    Canonical(#[from] chio_core_types::Error),
    #[error("native cage admission requires explicit platform permissions")]
    MissingRequiredPermissions,
    #[error("publisher permissions exceed operator ceilings")]
    OperatorCeilingExceeded,
    #[error("operator policy must explicitly configure the complete forbidden-path set")]
    MissingForbiddenPathPolicy,
    #[error("a path cannot request both read and write access")]
    AmbiguousFilesystemAccess,
    #[error("native cage admission is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("unsupported seccomp architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("required Linux kernel feature is unavailable: {0}")]
    UnsupportedKernelFeature(&'static str),
    #[error("invalid absolute normalized cage path: {0}")]
    InvalidPath(PathBuf),
    #[error("allowed path {allowed} overlaps forbidden path {forbidden}")]
    ForbiddenPathOverlap {
        allowed: PathBuf,
        forbidden: PathBuf,
    },
    #[error("allowed path {allowed} aliases forbidden descriptor {forbidden}")]
    ForbiddenDescriptorAlias {
        allowed: PathBuf,
        forbidden: PathBuf,
    },
    #[error("grant paths {first} and {second} alias the same descriptor identity")]
    GrantDescriptorAlias { first: PathBuf, second: PathBuf },
    #[error("runtime paths {first} and {second} alias the same descriptor identity")]
    RuntimeDescriptorAlias { first: PathBuf, second: PathBuf },
    #[error("runtime file is absent from the verified manifest read authority: {0}")]
    UnauthorizedRuntimeFile(PathBuf),
    #[error("runtime file identity differs from its verified manifest read authority: {0}")]
    RuntimeFileAuthorityChanged(PathBuf),
    #[error("failed to retain path {path}: {source}")]
    RetainPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to enumerate retained directory {path}: {source}")]
    DirectoryEnumeration {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read descriptor metadata for {path}: {source}")]
    DescriptorMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("symbolic links are not admissible: {0}")]
    SymbolicLink(PathBuf),
    #[error("unsupported filesystem object kind: {0}")]
    UnsupportedResourceKind(PathBuf),
    #[error("write grants must name exact regular files: {0}")]
    WritableDirectory(PathBuf),
    #[error("missing writable file has no existing safe parent: {0}")]
    MissingWriteParent(PathBuf),
    #[error("securely created file has unexpected ownership or mode: {0}")]
    UnsafeCreatedFile(PathBuf),
    #[error("descriptor identity changed while retaining path: {0}")]
    DescriptorIdentityChanged(PathBuf),
    #[error("runtime artifact is not an executable regular file: {0}")]
    InvalidExecutable(PathBuf),
    #[error("runtime artifact is too large: {0}")]
    ArtifactTooLarge(PathBuf),
    #[error("runtime artifact content changed while it was hashed: {0}")]
    ArtifactChanged(PathBuf),
    #[error("runtime artifact digest no longer matches its retained descriptor: {0}")]
    ArtifactDigestMismatch(PathBuf),
    #[error("unable to determine mount identity for descriptor: {0}")]
    MissingMountIdentity(PathBuf),
    #[error("invalid limit: {0}")]
    InvalidLimit(&'static str),
    #[error("invalid target execution identity: {0}")]
    InvalidExecutionIdentity(&'static str),
    #[error("applied target execution identity does not match the sealed plan")]
    ExecutionIdentityMismatch,
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(&'static str),
    #[error("invalid broker authentication descriptor")]
    InvalidBrokerDescriptor,
    #[error("failed to create target stdio channel: {0}")]
    TargetStdio(#[source] std::io::Error),
    #[error("target stdio channel is not an authenticated Unix socket")]
    InvalidTargetStdio,
    #[error("target stdio handles are unavailable")]
    TargetStdioUnavailable,
    #[error("target stdio is already bound into the launch plan")]
    TargetStdioAlreadyBound,
    #[error("connected broker peer credentials do not match operator configuration")]
    BrokerPeerIdentityMismatch,
    #[error("brokered syscall profile and authenticated broker descriptor must be paired")]
    BrokerProfileMismatch,
    #[error("invalid SHA-256 digest for {0}")]
    InvalidDigest(&'static str),
    #[error("forbidden environment variable: {0}")]
    ForbiddenEnvironmentVariable(String),
    #[error("invalid environment value for {0}")]
    InvalidEnvironmentValue(String),
    #[error("target argument vector is empty, malformed, or exceeds cage bounds")]
    InvalidTargetArgv,
    #[error("descriptor slot arithmetic overflow")]
    FdSlotOverflow,
    #[error("compiled descriptor table contains a duplicate slot")]
    DuplicateFdSlot,
    #[error("invalid target executable descriptor binding: {0}")]
    InvalidTargetFdBinding(&'static str),
    #[error("invalid seccomp plan: {0}")]
    InvalidSeccompPlan(#[from] SeccompPlanError),
}
