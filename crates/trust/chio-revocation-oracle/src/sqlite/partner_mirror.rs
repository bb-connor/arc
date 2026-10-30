//! Durable mirror of one federation partner's revocation tree.
//!
//! The mirror is a [`SqliteRevocationOracle`] whose leaves are the partner's
//! leaves in the partner's order, so its leaf count is the sync cursor. Beside
//! the tree the same database holds the partner the mirror is stamped for, the
//! partner's last accepted signed root, and the conflicting roots it refused.
//! Leaves and the accepted root commit in one transaction.

use std::path::Path;

use chio_core_types::canonical::UntrustedJsonText;
use rusqlite::{params, Connection, OptionalExtension};

use super::{Result, SqliteRevocationOracle, SqliteRevocationOracleError};
use crate::partner_mirror::{
    check_history, ConflictRecord, PartnerMirrorConflict, PartnerMirrorRefusal,
    MAX_RECORDED_PARTNER_CONFLICTS,
};
use crate::{EpochRoot, PassportRevocationLeaf, RevocationKey, RevocationOracle, SignedEpochRoot};

const SCHEMA: &str = include_str!("partner_mirror.sql");

const STAMP_PARTNER: &str = "INSERT INTO chio_partner_revocation_mirror (singleton, partner_id)
     VALUES (1, ?1) ON CONFLICT (singleton) DO NOTHING";
const SELECT_PARTNER: &str =
    "SELECT partner_id FROM chio_partner_revocation_mirror WHERE singleton = 1";
const SELECT_ACCEPTED: &str =
    "SELECT signed_root FROM chio_partner_revocation_mirror WHERE singleton = 1";
const UPDATE_ACCEPTED: &str =
    "UPDATE chio_partner_revocation_mirror SET signed_root = ?1 WHERE singleton = 1";
const SELECT_CONFLICTS: &str = "SELECT observed_at_unix_ms, reason, accepted_root, offered_root
     FROM chio_partner_revocation_conflicts ORDER BY id ASC";
const CONFLICT_RECORDED: &str = "SELECT EXISTS(SELECT 1 FROM chio_partner_revocation_conflicts
     WHERE offered_root_sha256 = ?1)";
const COUNT_CONFLICTS: &str = "SELECT count(*) FROM chio_partner_revocation_conflicts";
const INSERT_CONFLICT: &str = "INSERT INTO chio_partner_revocation_conflicts
        (observed_at_unix_ms, reason, accepted_root, offered_root, offered_root_sha256)
     VALUES (?1, ?2, ?3, ?4, ?5)";

/// Largest stored signed root, in bytes.
const MAX_STORED_ROOT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartnerMirrorError {
    #[error("partner revocation mirror belongs to `{found}`, not `{expected}`")]
    PartnerMismatch { expected: String, found: String },
    #[error(transparent)]
    Refused(#[from] PartnerMirrorRefusal),
    #[error("{0} exceeds the stored time range")]
    TimeOutOfRange(u64),
    #[error(transparent)]
    Store(#[from] SqliteRevocationOracleError),
}

/// One committed state of a mirror: its accepted root, its tree's root, and
/// the first of the queried subjects the tree holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerMirrorView {
    pub accepted: Option<SignedEpochRoot>,
    pub tree: EpochRoot,
    pub revoked: Option<RevocationKey>,
}

pub struct SqlitePartnerMirror {
    partner_id: String,
    oracle: SqliteRevocationOracle,
}

impl SqlitePartnerMirror {
    /// Opens (creating if absent) the mirror of `partner_id` at `path`. A
    /// mirror stamped for another partner is refused.
    pub fn open(path: &Path, partner_id: &str) -> core::result::Result<Self, PartnerMirrorError> {
        let oracle = SqliteRevocationOracle::open(path)?;
        let (found, _) = oracle.transact(0, |txn| {
            let connection = txn.connection();
            connection.execute_batch(SCHEMA)?;
            connection.execute(STAMP_PARTNER, params![partner_id])?;
            Ok(connection.query_row(SELECT_PARTNER, [], |row| row.get::<_, String>(0))?)
        })?;
        if found != partner_id {
            return Err(PartnerMirrorError::PartnerMismatch {
                expected: partner_id.to_owned(),
                found,
            });
        }
        Ok(Self {
            partner_id: partner_id.to_owned(),
            oracle,
        })
    }

    #[must_use]
    pub fn partner_id(&self) -> &str {
        &self.partner_id
    }

    /// The root this mirror last accepted.
    pub fn accepted(&self) -> Result<Option<SignedEpochRoot>> {
        self.oracle.read(read_accepted)
    }

    /// The accepted root, the tree's root and the first of `subjects` the tree
    /// holds, read from one committed state.
    pub fn view(&self, subjects: &[RevocationKey]) -> Result<PartnerMirrorView> {
        self.oracle.read_with_tree(|connection, tree| {
            Ok(PartnerMirrorView {
                accepted: read_accepted(connection)?,
                tree: tree.epoch_root(),
                revoked: subjects
                    .iter()
                    .find(|subject| tree.contains(subject))
                    .cloned(),
            })
        })
    }

    /// Every recorded conflict, oldest first.
    pub fn conflicts(&self) -> Result<Vec<PartnerMirrorConflict>> {
        self.oracle.read(|connection| {
            let mut statement = connection.prepare(SELECT_CONFLICTS)?;
            let mut rows = statement.query([])?;
            let mut conflicts = Vec::new();
            while let Some(row) = rows.next()? {
                let observed: i64 = row.get(0)?;
                let accepted: Option<String> = row.get(2)?;
                conflicts.push(PartnerMirrorConflict {
                    observed_at_unix_ms: u64::try_from(observed)
                        .map_err(|_| corrupt("conflict observation time"))?,
                    reason: row.get(1)?,
                    accepted_root: accepted.as_deref().map(decode_root).transpose()?,
                    offered_root: decode_root(&row.get::<_, String>(3)?)?,
                });
            }
            Ok(conflicts)
        })
    }

    /// Applies `leaves`, each as the mirror's next leaf, and accepts `offered`
    /// only when it moves forward from the accepted root and the rebuilt tree
    /// equals it. The caller has verified `offered`'s signature.
    pub fn apply(
        &self,
        offered: &SignedEpochRoot,
        leaves: &[PassportRevocationLeaf],
        now_unix_ms: u64,
    ) -> core::result::Result<EpochRoot, PartnerMirrorError> {
        let offered_json = encode_root(offered)?;
        let want = leaf_count(&offered.root);
        let ((), root) = self.oracle.write(now_unix_ms, |txn| {
            let accepted = read_accepted(txn.connection())?;
            let mut have = leaf_count(&txn.epoch_root());
            match &accepted {
                Some(accepted) => {
                    if !txn.epoch_root().same_tree(&accepted.root) {
                        return Err(PartnerMirrorRefusal::Diverged.into());
                    }
                    check_history(&accepted.root, &offered.root)?;
                }
                None if have != 0 => return Err(PartnerMirrorRefusal::Diverged.into()),
                None => {}
            }
            for leaf in leaves {
                if have >= want {
                    break;
                }
                if Some(leaf.seq) != have.checked_add(1) {
                    return Err(PartnerMirrorRefusal::OutOfSequence {
                        seq: leaf.seq,
                        have,
                    }
                    .into());
                }
                let inserted = txn.revoke(&leaf.to_revocation_key()).map_err(|error| {
                    PartnerMirrorRefusal::InvalidLeaf {
                        seq: leaf.seq,
                        reason: error.to_string(),
                    }
                })?;
                if !inserted {
                    return Err(PartnerMirrorRefusal::DuplicateLeaf { seq: leaf.seq }.into());
                }
                have = leaf.seq;
            }
            if !txn.epoch_root().same_tree(&offered.root) {
                return Err(PartnerMirrorRefusal::RootMismatch {
                    epoch: offered.root.epoch,
                }
                .into());
            }
            txn.connection()
                .execute(UPDATE_ACCEPTED, params![offered_json])
                .map_err(SqliteRevocationOracleError::from)?;
            Ok::<(), PartnerMirrorError>(())
        })?;
        Ok(root)
    }

    /// Records `offered` as a conflict once, keyed by the SHA-256 of its
    /// canonical JSON, and records nothing new once the mirror holds
    /// [`MAX_RECORDED_PARTNER_CONFLICTS`] conflicts.
    pub fn record_conflict(
        &self,
        reason: &str,
        offered: &SignedEpochRoot,
        now_unix_ms: u64,
    ) -> core::result::Result<ConflictRecord, PartnerMirrorError> {
        let observed = i64::try_from(now_unix_ms)
            .map_err(|_| PartnerMirrorError::TimeOutOfRange(now_unix_ms))?;
        let offered_json = encode_root(offered)?;
        let digest = chio_core_types::sha256_hex(offered_json.as_bytes());
        let (record, _) = self.oracle.transact(now_unix_ms, |txn| {
            let connection = txn.connection();
            let recorded: bool =
                connection.query_row(CONFLICT_RECORDED, params![digest], |row| row.get(0))?;
            if recorded {
                return Ok(ConflictRecord::AlreadyRecorded);
            }
            let count: i64 = connection.query_row(COUNT_CONFLICTS, [], |row| row.get(0))?;
            if u64::try_from(count)
                .ok()
                .is_none_or(|count| count >= MAX_RECORDED_PARTNER_CONFLICTS)
            {
                return Ok(ConflictRecord::LogFull);
            }
            let accepted: Option<String> = connection
                .query_row(SELECT_ACCEPTED, [], |row| row.get(0))
                .optional()?
                .flatten();
            connection.execute(
                INSERT_CONFLICT,
                params![observed, reason, accepted, offered_json, digest],
            )?;
            Ok(ConflictRecord::Recorded)
        })?;
        Ok(record)
    }
}

fn read_accepted(connection: &Connection) -> Result<Option<SignedEpochRoot>> {
    let root: Option<String> = connection.query_row(SELECT_ACCEPTED, [], |row| row.get(0))?;
    root.as_deref().map(decode_root).transpose()
}

fn leaf_count(root: &EpochRoot) -> u64 {
    u64::try_from(root.leaf_count).unwrap_or(u64::MAX)
}

fn corrupt(what: &str) -> SqliteRevocationOracleError {
    SqliteRevocationOracleError::CorruptRecord(what.to_owned())
}

fn encode_root(root: &SignedEpochRoot) -> Result<String> {
    chio_core_types::canonical_json_bytes(root)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| corrupt("partner signed root"))
}

fn decode_root(json: &str) -> Result<SignedEpochRoot> {
    UntrustedJsonText::from_wire(json.as_bytes(), MAX_STORED_ROOT_BYTES)
        .and_then(|text| text.decode_signed())
        .map_err(|_| corrupt("partner signed root"))
}

#[cfg(test)]
#[path = "partner_mirror_tests.rs"]
mod tests;
