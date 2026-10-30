#[derive(Debug, thiserror::Error)]
pub enum RevocationStoreError {
    #[error(transparent)]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("revocation store io fault: {0}")]
    Io(crate::io_fault::IoFault),

    #[error("revocation store synchronization error: {0}")]
    Sync(String),

    #[error("revocation mutation durable outcome is unknown: {0}")]
    OutcomeUnknown(String),

    #[error(
        "revocation store serving owner fenced (expected epoch {expected_epoch}, actual {actual_epoch:?})"
    )]
    Fenced {
        expected_epoch: u64,
        actual_epoch: Option<u64>,
    },

    #[error("anchored root matches revocation entry {entry_id}")]
    TargetRevoked {
        entry_id: chio_core_types::root_authority::RevocationEntryId,
    },

    #[error("anchored root row missing for {capability_id}")]
    AnchoredRootMissing { capability_id: String },

    #[error("revocation coverage requires the serving-owner state directory")]
    CoverageRequiresServingOwner,

    #[error("a {kind} revocation requires the serving-owner state directory")]
    TargetRequiresServingOwner { kind: &'static str },

    #[error("revocation target tags are invalid: {0}")]
    InvalidTargetTags(&'static str),

    #[error("revocation entry {entry_id} has inconsistent tag rows")]
    InconsistentTagRows { entry_id: String },
}

impl From<std::io::Error> for RevocationStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(crate::io_fault::IoFault::from(error.kind()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub capability_id: String,
    pub revoked_at: i64,
}
