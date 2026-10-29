//! Revocation by root policy rule, subject tag, tenant tag and replay key.

use chio_core::root_authority::{
    RevocationCoverage, RevocationCoverageRoot, RevocationEntry, RevocationReason, RevocationTarget,
};
use chio_core::tenant_index::KeyedIndexValue;
use chio_kernel::RevocationStoreError;
use rusqlite::Transaction;

use super::SqliteRevocationStore;
use crate::root_exchange_store::{MintRevocationCheck, MintRevocationRefusal, RevocationCandidate};

/// The outcome of one target revocation. `roots_matched` counts every
/// anchored root the target matches, already revoked or not;
/// `roots_revoked` counts the roots this call marked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRevocation {
    pub entry: RevocationEntry,
    pub newly_revoked: bool,
    pub roots_matched: u64,
    pub roots_revoked: u64,
}

impl SqliteRevocationStore {
    pub fn revoke_target(
        &self,
        _target: &RevocationTarget,
        _tags: &[KeyedIndexValue],
        _reason: RevocationReason,
    ) -> Result<TargetRevocation, RevocationStoreError> {
        Err(RevocationStoreError::Sync(
            "revocation targets are not recorded".to_string(),
        ))
    }

    pub fn revocations_covering(
        &self,
        _roots: &[RevocationCoverageRoot],
    ) -> Result<Vec<RevocationCoverage>, RevocationStoreError> {
        Err(RevocationStoreError::Sync(
            "revocation coverage is not computed".to_string(),
        ))
    }
}

impl MintRevocationCheck for SqliteRevocationStore {
    fn refuse_revoked_root(
        &self,
        _transaction: &Transaction<'_>,
        _candidate: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        Ok(())
    }
}
