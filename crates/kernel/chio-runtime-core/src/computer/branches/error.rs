use std::fmt;

/// A tree entry kind the managed-branch profile does not materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedKind {
    Symlink,
    Submodule,
    LfsPointer,
    Special,
}

impl fmt::Display for UnsupportedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Symlink => "symlink",
            Self::Submodule => "submodule",
            Self::LfsPointer => "lfs_pointer",
            Self::Special => "special_file",
        })
    }
}

/// Refusals of the git-native managed-branch backend. Every error denies the
/// requested operation. The only durable write an error path makes is the
/// `Conflict` disposition of a publication whose base moved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BranchError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid object identifier")]
    InvalidObjectId,
    #[error("git binary and store paths must be absolute")]
    PathNotAbsolute,
    #[error("the object store declares alternates")]
    AlternatesPresent,
    #[error("the object store carries unsupported configuration: {0}")]
    UnsupportedStoreConfig(String),
    #[error("refused path {path:?}: {reason}")]
    PathRefused { path: String, reason: &'static str },
    #[error("unsupported entry {path:?}: {kind}")]
    UnsupportedEntry { path: String, kind: UnsupportedKind },
    #[error("import source changed while it was read: {0:?}")]
    SourceChanged(String),
    #[error("bound exceeded: {0}")]
    BoundExceeded(&'static str),
    #[error("project {0} already exists")]
    ProjectExists(String),
    #[error("unknown project {0}")]
    UnknownProject(String),
    #[error("branch {0} already exists")]
    BranchExists(String),
    #[error("unknown branch {0}")]
    UnknownBranch(String),
    #[error("stale writer: lease generation {presented}, branch generation {current}")]
    StaleWriter { presented: u64, current: u64 },
    #[error("branch is frozen")]
    BranchFrozen,
    #[error("branch is not frozen")]
    BranchNotFrozen,
    #[error("branch is not sealed")]
    BranchNotSealed,
    #[error("release withheld for a changed path")]
    ReleaseWithheld,
    #[error("branch publication {0} is already recorded; reconcile it by its original identity")]
    PublicationPending(String),
    #[error("branch {0} has no recorded publication")]
    UnknownPublication(String),
    #[error("base conflict: expected {expected}, found {actual}")]
    BaseConflict { expected: String, actual: String },
    #[error("concurrent update of {0}")]
    ConcurrentUpdate(String),
    #[error("corrupt record {0}")]
    CorruptRecord(String),
    #[error("git {0} failed")]
    Git(&'static str),
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for BranchError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind().to_string())
    }
}
