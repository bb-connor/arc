//! Per-partner mirrors of a federation partner's passport revocation feed.
//!
//! A mirror is its own durable revocation oracle kept beside this operator's
//! revocation partner registry, plus the partner's last accepted signed root.
//! The mirror's leaf count is its cursor: a partner leaf is applied only as the
//! next leaf, so the mirror's sequence numbers equal the partner's. A sync
//! verifies the partner's signed root against the authority key pinned in the
//! registry, fetches the leaves after the mirror's leaf count, replays them
//! into a staged tree and commits only when the staged root equals the signed
//! root and the signed root does not roll back the accepted one. A refused sync
//! leaves the mirror unchanged; a root that contradicts the accepted history is
//! recorded as a conflict.
//!
//! Every fetch happens before the mirror's write transaction opens.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_revocation_oracle::{
    verify_fresh_epoch_root, EpochRoot, FreshnessConfig, PassportRevocationLeaf, RevocationKey,
    RevocationOracleError, SignedEpochRoot, SqliteRevocationOracle, SqliteRevocationOracleError,
};
use chio_security_types::clock::Clock;
use rusqlite::{params, OptionalExtension};

use crate::passport_revocation_feed::{
    passport_revocation_root_verifier, PassportRevocationLeavesPage,
    MAX_PASSPORT_REVOCATION_PAGE_LEAVES, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::revocation_partner::{RevocationPartner, RevocationPartnerRegistry};

/// Most leaves one sync replays. A partner further ahead than this is refused.
pub const MAX_PARTNER_SYNC_LEAVES: u64 = 65_536;

/// Largest amount a partner's signed root may be dated after this operator's
/// clock.
pub const MAX_PARTNER_ROOT_FUTURE_SKEW_MS: u64 = 5_000;

/// Most distinct conflicting roots one mirror records. A mirror at the bound
/// refuses every further conflicting root with
/// [`PartnerRevocationError::ConflictLogFull`].
pub const MAX_RECORDED_PARTNER_CONFLICTS: i64 = 256;

/// Largest stored signed root, in bytes.
const MAX_STORED_ROOT_BYTES: usize = 16 * 1024;

const MIRROR_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chio_partner_revocation_mirror (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partner_id TEXT NOT NULL CHECK (length(partner_id) BETWEEN 1 AND 64),
    signed_root TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS chio_partner_revocation_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at_unix_ms INTEGER NOT NULL,
    reason TEXT NOT NULL,
    accepted_root TEXT,
    offered_root TEXT NOT NULL,
    offered_root_sha256 TEXT NOT NULL UNIQUE CHECK (length(offered_root_sha256) = 64)
) STRICT;
";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartnerRevocationError {
    #[error("partner `{0}` revocation mirror unavailable: {1}")]
    MirrorUnavailable(String, String),
    #[error("partner revocation mirror belongs to `{found}`, not `{expected}`")]
    PartnerMismatch { expected: String, found: String },
    #[error("partner `{0}` revocation mirror holds no verified root")]
    NoVerifiedRoot(String),
    #[error(
        "partner `{0}` revocation root signature does not verify against the pinned authority key"
    )]
    UnverifiableRoot(String),
    #[error("partner `{partner_id}` revocation root is dated {issued_at_unix_ms}, after {now_unix_ms} plus the allowed skew")]
    FutureRoot {
        partner_id: String,
        issued_at_unix_ms: u64,
        now_unix_ms: u64,
    },
    #[error("partner `{partner_id}` revocation root from {issued_at_unix_ms} is older than its {ttl_ms} ms freshness TTL at {now_unix_ms}")]
    StaleRoot {
        partner_id: String,
        issued_at_unix_ms: u64,
        now_unix_ms: u64,
        ttl_ms: u64,
    },
    #[error("partner `{partner_id}` revocation root epoch {offered} rolls back accepted epoch {accepted}")]
    Rollback {
        partner_id: String,
        accepted: u64,
        offered: u64,
    },
    #[error("partner `{partner_id}` revocation root issued at {offered} predates the accepted root issued at {accepted}")]
    AttestationRollback {
        partner_id: String,
        accepted: u64,
        offered: u64,
    },
    #[error("partner `{partner_id}` signed two different revocation roots for epoch {epoch}")]
    Equivocation { partner_id: String, epoch: u64 },
    #[error("partner `{partner_id}` revocation leaves rebuild a root that differs from the signed root at epoch {epoch}")]
    RootMismatch { partner_id: String, epoch: u64 },
    #[error("partner `{partner_id}` is {behind} revocation leaves ahead, beyond the {MAX_PARTNER_SYNC_LEAVES}-leaf sync bound")]
    TooFarBehind { partner_id: String, behind: u64 },
    #[error("partner `{0}` revocation root document is malformed: {1}")]
    MalformedRoot(String, String),
    #[error("partner `{0}` revocation leaves page is malformed: {1}")]
    MalformedPage(String, String),
    #[error("partner `{0}` revocation leaves ended before the signed root's leaf count")]
    TruncatedLeaves(String),
    #[error("partner `{partner_id}` revocation leaf {seq} repeats a revoked key")]
    DuplicateLeaf { partner_id: String, seq: u64 },
    #[error("partner `{0}` revocation feed fetch failed: {1}")]
    Fetch(String, String),
    #[error("revocation clock unavailable: {0}")]
    Clock(String),
    #[error("partner `{0}` revocation mirror already records {MAX_RECORDED_PARTNER_CONFLICTS} conflicting roots")]
    ConflictLogFull(String),
    #[error("`{subject}` is revoked by partner `{partner_id}`")]
    Revoked { partner_id: String, subject: String },
}

/// Where a partner's signed root and leaf pages come from.
pub trait PartnerRevocationSource {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError>;
    fn leaves_after(
        &mut self,
        after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError>;
}

/// A partner's signed root and the leaves a mirror lacks, fetched and checked
/// page by page but not yet applied.
#[derive(Debug)]
pub struct StagedPartnerSync {
    offered: SignedEpochRoot,
    leaves: Vec<PassportRevocationLeaf>,
}

impl StagedPartnerSync {
    pub fn leaves(&self) -> &[PassportRevocationLeaf] {
        &self.leaves
    }
}

/// The mirror of `partner_id` kept beside the revocation partner registry at
/// `registry`: `<registry file name>.partner-<partner_id>.revocations.sqlite3`.
pub fn partner_revocation_mirror_path(
    registry: &Path,
    partner_id: &str,
) -> Result<PathBuf, PartnerRevocationError> {
    let name = registry
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PartnerRevocationError::MirrorUnavailable(
                partner_id.to_owned(),
                "revocation partner registry path has no UTF-8 file name".to_owned(),
            )
        })?;
    Ok(registry.with_file_name(format!("{name}.partner-{partner_id}.revocations.sqlite3")))
}

/// A partner root that contradicted the mirror's accepted history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerRevocationConflict {
    pub observed_at_unix_ms: u64,
    pub reason: String,
    pub accepted_root: Option<SignedEpochRoot>,
    pub offered_root: SignedEpochRoot,
}

pub struct PartnerRevocationMirror {
    partner_id: String,
    oracle: SqliteRevocationOracle,
}

impl PartnerRevocationMirror {
    /// Opens (creating if absent) the mirror of `partner_id` at `path`. A
    /// mirror stamped for another partner is refused.
    pub fn open(path: &Path, partner_id: &str) -> Result<Self, PartnerRevocationError> {
        let unavailable = mirror_unavailable(partner_id);
        let oracle = SqliteRevocationOracle::open(path).map_err(&unavailable)?;
        let mut found = None;
        oracle
            .transact(0, |txn| {
                let connection = txn.connection();
                connection.execute_batch(MIRROR_SCHEMA)?;
                connection.execute(
                    "INSERT INTO chio_partner_revocation_mirror (singleton, partner_id)
                     VALUES (1, ?1) ON CONFLICT (singleton) DO NOTHING",
                    params![partner_id],
                )?;
                found = Some(connection.query_row(
                    "SELECT partner_id FROM chio_partner_revocation_mirror WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )?);
                Ok(())
            })
            .map_err(&unavailable)?;
        match found {
            Some(found) if found == partner_id => Ok(Self {
                partner_id: partner_id.to_owned(),
                oracle,
            }),
            Some(found) => Err(PartnerRevocationError::PartnerMismatch {
                expected: partner_id.to_owned(),
                found,
            }),
            None => Err(unavailable(SqliteRevocationOracleError::UnstampedDatabase)),
        }
    }

    #[must_use]
    pub fn partner_id(&self) -> &str {
        &self.partner_id
    }

    /// The root this mirror last accepted.
    pub fn accepted(&self) -> Result<Option<SignedEpochRoot>, PartnerRevocationError> {
        self.oracle
            .read(read_accepted)
            .map_err(mirror_unavailable(&self.partner_id))
    }

    /// Every recorded conflict, oldest first.
    pub fn conflicts(&self) -> Result<Vec<PartnerRevocationConflict>, PartnerRevocationError> {
        self.oracle
            .read(|connection| {
                let mut statement = connection.prepare(
                    "SELECT observed_at_unix_ms, reason, accepted_root, offered_root
                     FROM chio_partner_revocation_conflicts ORDER BY id ASC",
                )?;
                let mut rows = statement.query([])?;
                let mut conflicts = Vec::new();
                while let Some(row) = rows.next()? {
                    let observed: i64 = row.get(0)?;
                    let accepted: Option<String> = row.get(2)?;
                    conflicts.push(PartnerRevocationConflict {
                        observed_at_unix_ms: u64::try_from(observed)
                            .map_err(|_| corrupt("conflict observation time"))?,
                        reason: row.get(1)?,
                        accepted_root: accepted.as_deref().map(decode_root).transpose()?,
                        offered_root: decode_root(&row.get::<_, String>(3)?)?,
                    });
                }
                Ok(conflicts)
            })
            .map_err(mirror_unavailable(&self.partner_id))
    }

    /// Refuses unless the accepted root verifies against `partner`'s pinned
    /// key, is fresh at `now_unix_ms` under `partner`'s freshness TTL, and
    /// equals the mirror's tree.
    pub fn require_fresh(
        &self,
        partner: &RevocationPartner,
        now_unix_ms: u64,
    ) -> Result<SignedEpochRoot, PartnerRevocationError> {
        let accepted = self
            .accepted()?
            .ok_or_else(|| PartnerRevocationError::NoVerifiedRoot(self.partner_id.clone()))?;
        verify_signature(partner, &accepted)?;
        let root = &accepted.root;
        check_not_future(partner, root, now_unix_ms)?;
        let config = FreshnessConfig::with_offline_grace(partner.revocation_freshness_ttl_ms(), 0);
        verify_fresh_epoch_root(root, now_unix_ms.max(root.issued_at_unix_ms), config).map_err(
            |_| PartnerRevocationError::StaleRoot {
                partner_id: partner.partner_id.clone(),
                issued_at_unix_ms: root.issued_at_unix_ms,
                now_unix_ms,
                ttl_ms: partner.revocation_freshness_ttl_ms(),
            },
        )?;
        let local = self
            .oracle
            .current_epoch_root()
            .map_err(mirror_unavailable(&self.partner_id))?;
        if !same_tree(&local, root) {
            return Err(diverged(&self.partner_id));
        }
        Ok(accepted)
    }

    /// Refuses unless the mirror is fresh at `now_unix_ms` and holds none of
    /// `subjects`.
    pub fn check_passport(
        &self,
        partner: &RevocationPartner,
        subjects: &[RevocationKey],
        now_unix_ms: u64,
    ) -> Result<(), PartnerRevocationError> {
        self.require_fresh(partner, now_unix_ms)?;
        for subject in subjects {
            let revoked = self
                .oracle
                .is_revoked(subject)
                .map_err(mirror_unavailable(&self.partner_id))?;
            if revoked {
                return Err(PartnerRevocationError::Revoked {
                    partner_id: self.partner_id.clone(),
                    subject: subject.subject_id.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Stages the partner's feed from `source`, then commits it at the time
    /// `clock` reads after the fetch.
    pub fn sync(
        &self,
        partner: &RevocationPartner,
        source: &mut dyn PartnerRevocationSource,
        clock: &dyn Clock,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        let staged = self.stage(partner, source)?;
        self.commit(partner, staged, clock)
    }

    /// Fetches the partner's signed root and the leaves the mirror lacks from
    /// `source`. Nothing is written.
    pub fn stage(
        &self,
        partner: &RevocationPartner,
        source: &mut dyn PartnerRevocationSource,
    ) -> Result<StagedPartnerSync, PartnerRevocationError> {
        let offered = source.signed_root()?;
        verify_signature(partner, &offered)?;
        let have = self
            .accepted()?
            .map_or(0, |accepted| leaf_count(&accepted.root));
        let behind = leaf_count(&offered.root).saturating_sub(have);
        if behind > MAX_PARTNER_SYNC_LEAVES {
            return Err(PartnerRevocationError::TooFarBehind {
                partner_id: partner.partner_id.clone(),
                behind,
            });
        }
        let mut after = have;
        let mut leaves = Vec::new();
        while crate::integer::count(leaves.len()) < behind {
            let page = source.leaves_after(after)?;
            check_page(partner, &page, after)?;
            after = page.leaves.last().map_or(after, |leaf| leaf.seq);
            leaves.extend(page.leaves);
        }
        Ok(StagedPartnerSync { offered, leaves })
    }

    /// Applies `staged` at the time `clock` reads now.
    pub fn commit(
        &self,
        partner: &RevocationPartner,
        staged: StagedPartnerSync,
        clock: &dyn Clock,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        let now = clock
            .unix_millis()
            .map_err(|error| PartnerRevocationError::Clock(error.to_string()))?
            .get();
        self.apply(partner, &staged.offered, &staged.leaves, now)
    }

    /// Applies `leaves`, each as the mirror's next leaf, and commits `offered`
    /// only when the staged root equals it. No network I/O runs here.
    pub fn apply(
        &self,
        partner: &RevocationPartner,
        offered: &SignedEpochRoot,
        leaves: &[PassportRevocationLeaf],
        now_unix_ms: u64,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        verify_signature(partner, offered)?;
        check_not_future(partner, &offered.root, now_unix_ms)?;
        let offered_json = encode_root(offered).map_err(mirror_unavailable(&self.partner_id))?;
        let want = leaf_count(&offered.root);
        let mut refusal = None;
        let outcome = self.oracle.transact(now_unix_ms, |txn| {
            let accepted = read_accepted(txn.connection())?;
            let mut have = crate::integer::count(txn.epoch_root().leaf_count);
            match &accepted {
                Some(accepted) => {
                    if !same_tree(&txn.epoch_root(), &accepted.root) {
                        refusal = Some(diverged(&partner.partner_id));
                        return Err(refused());
                    }
                    if let Err(error) = check_history(partner, accepted, offered) {
                        refusal = Some(error);
                        return Err(refused());
                    }
                }
                None if have != 0 => {
                    refusal = Some(diverged(&partner.partner_id));
                    return Err(refused());
                }
                None => {}
            }
            for leaf in leaves {
                if have >= want {
                    break;
                }
                if Some(leaf.seq) != have.checked_add(1) {
                    refusal = Some(PartnerRevocationError::MalformedPage(
                        partner.partner_id.clone(),
                        format!("leaf {} does not follow mirror leaf {have}", leaf.seq),
                    ));
                    return Err(refused());
                }
                let inserted = match txn.revoke(&leaf.to_revocation_key()) {
                    Ok(inserted) => inserted,
                    Err(error) => {
                        refusal = Some(PartnerRevocationError::MalformedPage(
                            partner.partner_id.clone(),
                            format!("leaf {} is not a valid revocation key: {error}", leaf.seq),
                        ));
                        return Err(refused());
                    }
                };
                if !inserted {
                    refusal = Some(PartnerRevocationError::DuplicateLeaf {
                        partner_id: partner.partner_id.clone(),
                        seq: leaf.seq,
                    });
                    return Err(refused());
                }
                have = leaf.seq;
            }
            if !same_tree(&txn.epoch_root(), &offered.root) {
                refusal = Some(PartnerRevocationError::RootMismatch {
                    partner_id: partner.partner_id.clone(),
                    epoch: offered.root.epoch,
                });
                return Err(refused());
            }
            txn.connection().execute(
                "UPDATE chio_partner_revocation_mirror SET signed_root = ?1 WHERE singleton = 1",
                params![offered_json],
            )?;
            Ok(())
        });
        match (outcome, refusal) {
            (Ok(((), root)), None) => Ok(root),
            (_, Some(refusal)) => {
                if matches!(
                    refusal,
                    PartnerRevocationError::Equivocation { .. }
                        | PartnerRevocationError::RootMismatch { .. }
                        | PartnerRevocationError::Rollback { .. }
                        | PartnerRevocationError::AttestationRollback { .. }
                ) {
                    self.record_conflict(&refusal, &offered_json, now_unix_ms)?;
                }
                Err(refusal)
            }
            (Err(error), None) => Err(mirror_unavailable(&self.partner_id)(error)),
        }
    }

    /// Records a conflicting signed root once, keyed by the SHA-256 of its
    /// canonical JSON, refusing a new one when the mirror already holds the
    /// bound.
    fn record_conflict(
        &self,
        refusal: &PartnerRevocationError,
        offered_json: &str,
        now_unix_ms: u64,
    ) -> Result<(), PartnerRevocationError> {
        let observed = i64::try_from(now_unix_ms).map_err(|_| {
            PartnerRevocationError::Clock(format!("{now_unix_ms} exceeds the stored time range"))
        })?;
        let digest = chio_core::sha256_hex(offered_json.as_bytes());
        let reason = refusal.to_string();
        let mut full = false;
        self.oracle
            .transact(now_unix_ms, |txn| {
                let connection = txn.connection();
                let recorded: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM chio_partner_revocation_conflicts
                     WHERE offered_root_sha256 = ?1)",
                    params![digest],
                    |row| row.get(0),
                )?;
                if recorded {
                    return Ok(());
                }
                let count: i64 = connection.query_row(
                    "SELECT count(*) FROM chio_partner_revocation_conflicts",
                    [],
                    |row| row.get(0),
                )?;
                if count >= MAX_RECORDED_PARTNER_CONFLICTS {
                    full = true;
                    return Ok(());
                }
                let accepted: Option<String> = connection
                    .query_row(
                        "SELECT signed_root FROM chio_partner_revocation_mirror WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                connection.execute(
                    "INSERT INTO chio_partner_revocation_conflicts
                        (observed_at_unix_ms, reason, accepted_root, offered_root,
                         offered_root_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![observed, reason, accepted, offered_json, digest],
                )?;
                Ok(())
            })
            .map_err(mirror_unavailable(&self.partner_id))?;
        if full {
            return Err(PartnerRevocationError::ConflictLogFull(
                self.partner_id.clone(),
            ));
        }
        Ok(())
    }
}

/// One open mirror handle per partner, so each check catches up incrementally
/// instead of replaying the mirror's tree.
#[derive(Default)]
pub struct PartnerMirrorCache {
    mirrors: Mutex<BTreeMap<String, CachedMirror>>,
}

struct CachedMirror {
    path: PathBuf,
    mirror: Arc<PartnerRevocationMirror>,
}

impl PartnerMirrorCache {
    /// The mirror of `partner_id` beside the registry at `registry_path`,
    /// opened on first use and reopened when its path changes.
    pub fn mirror(
        &self,
        registry_path: &Path,
        partner_id: &str,
    ) -> Result<Arc<PartnerRevocationMirror>, PartnerRevocationError> {
        let path = partner_revocation_mirror_path(registry_path, partner_id)?;
        let mut mirrors = self.lock(partner_id)?;
        if let Some(cached) = mirrors.get(partner_id) {
            if cached.path == path {
                return Ok(Arc::clone(&cached.mirror));
            }
        }
        let mirror = Arc::new(PartnerRevocationMirror::open(&path, partner_id)?);
        mirrors.insert(
            partner_id.to_owned(),
            CachedMirror {
                path,
                mirror: Arc::clone(&mirror),
            },
        );
        Ok(mirror)
    }

    /// Drops the handle of every partner `registry` no longer lists.
    pub fn retain(
        &self,
        registry: &RevocationPartnerRegistry,
    ) -> Result<(), PartnerRevocationError> {
        self.lock("")?
            .retain(|partner_id, _| registry.get(partner_id).is_some());
        Ok(())
    }

    /// The partner ids with an open handle.
    pub fn partner_ids(&self) -> Result<Vec<String>, PartnerRevocationError> {
        Ok(self.lock("")?.keys().cloned().collect())
    }

    fn lock(
        &self,
        partner_id: &str,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, CachedMirror>>, PartnerRevocationError>
    {
        self.mirrors.lock().map_err(|_| {
            PartnerRevocationError::MirrorUnavailable(
                partner_id.to_owned(),
                "partner mirror cache is poisoned".to_owned(),
            )
        })
    }
}

fn mirror_unavailable(
    partner_id: &str,
) -> impl Fn(SqliteRevocationOracleError) -> PartnerRevocationError + '_ {
    move |error| PartnerRevocationError::MirrorUnavailable(partner_id.to_owned(), error.to_string())
}

fn diverged(partner_id: &str) -> PartnerRevocationError {
    PartnerRevocationError::MirrorUnavailable(
        partner_id.to_owned(),
        "mirror tree does not match its accepted root".to_owned(),
    )
}

fn refused() -> SqliteRevocationOracleError {
    SqliteRevocationOracleError::Oracle(RevocationOracleError::InvalidEpochTransition)
}

fn corrupt(what: &str) -> SqliteRevocationOracleError {
    SqliteRevocationOracleError::CorruptRecord(what.to_owned())
}

fn encode_root(root: &SignedEpochRoot) -> Result<String, SqliteRevocationOracleError> {
    chio_core::canonical_json_bytes(root)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| corrupt("partner signed root"))
}

fn decode_root(json: &str) -> Result<SignedEpochRoot, SqliteRevocationOracleError> {
    crate::json_input::read(json.as_bytes(), MAX_STORED_ROOT_BYTES)
        .map_err(|_| corrupt("partner signed root"))
}

fn read_accepted(
    connection: &rusqlite::Connection,
) -> Result<Option<SignedEpochRoot>, SqliteRevocationOracleError> {
    let root: Option<String> = connection.query_row(
        "SELECT signed_root FROM chio_partner_revocation_mirror WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    root.as_deref().map(decode_root).transpose()
}

fn leaf_count(root: &EpochRoot) -> u64 {
    crate::integer::count(root.leaf_count)
}

fn same_tree(left: &EpochRoot, right: &EpochRoot) -> bool {
    left.epoch == right.epoch
        && left.root_hash == right.root_hash
        && left.leaf_count == right.leaf_count
}

fn verify_signature(
    partner: &RevocationPartner,
    root: &SignedEpochRoot,
) -> Result<(), PartnerRevocationError> {
    root.verify(&passport_revocation_root_verifier(
        &partner.authority_public_key,
    ))
    .map_err(|_| PartnerRevocationError::UnverifiableRoot(partner.partner_id.clone()))
}

fn check_not_future(
    partner: &RevocationPartner,
    root: &EpochRoot,
    now_unix_ms: u64,
) -> Result<(), PartnerRevocationError> {
    if root.issued_at_unix_ms > now_unix_ms.saturating_add(MAX_PARTNER_ROOT_FUTURE_SKEW_MS) {
        return Err(PartnerRevocationError::FutureRoot {
            partner_id: partner.partner_id.clone(),
            issued_at_unix_ms: root.issued_at_unix_ms,
            now_unix_ms,
        });
    }
    Ok(())
}

fn check_history(
    partner: &RevocationPartner,
    accepted: &SignedEpochRoot,
    offered: &SignedEpochRoot,
) -> Result<(), PartnerRevocationError> {
    let partner_id = partner.partner_id.clone();
    if offered.root.epoch < accepted.root.epoch {
        return Err(PartnerRevocationError::Rollback {
            partner_id,
            accepted: accepted.root.epoch,
            offered: offered.root.epoch,
        });
    }
    if offered.root.epoch == accepted.root.epoch && !same_tree(&offered.root, &accepted.root) {
        return Err(PartnerRevocationError::Equivocation {
            partner_id,
            epoch: offered.root.epoch,
        });
    }
    if offered.root.issued_at_unix_ms < accepted.root.issued_at_unix_ms {
        return Err(PartnerRevocationError::AttestationRollback {
            partner_id,
            accepted: accepted.root.issued_at_unix_ms,
            offered: offered.root.issued_at_unix_ms,
        });
    }
    Ok(())
}

fn check_page(
    partner: &RevocationPartner,
    page: &PassportRevocationLeavesPage,
    after: u64,
) -> Result<(), PartnerRevocationError> {
    let malformed = |reason: &str| {
        PartnerRevocationError::MalformedPage(partner.partner_id.clone(), reason.to_owned())
    };
    if page.schema != PASSPORT_REVOCATION_LEAVES_SCHEMA {
        return Err(malformed("unsupported schema"));
    }
    if page.after != after {
        return Err(malformed("page cursor does not match the request"));
    }
    if page.leaves.is_empty() {
        return Err(PartnerRevocationError::TruncatedLeaves(
            partner.partner_id.clone(),
        ));
    }
    if page.leaves.len() > MAX_PASSPORT_REVOCATION_PAGE_LEAVES {
        return Err(malformed("page exceeds the leaf bound"));
    }
    let mut previous = after;
    for leaf in &page.leaves {
        if Some(leaf.seq) != previous.checked_add(1) {
            return Err(malformed("leaf sequence is not contiguous"));
        }
        previous = leaf.seq;
    }
    Ok(())
}

#[cfg(test)]
#[path = "passport_revocation_mirror_tests.rs"]
mod tests;
