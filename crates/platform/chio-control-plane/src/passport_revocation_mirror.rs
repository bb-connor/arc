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
    verify_fresh_epoch_root, ConflictRecord, EpochRoot, FreshnessConfig, PartnerMirrorError,
    PartnerMirrorRefusal, PassportRevocationLeaf, RevocationKey, SignedEpochRoot,
    SqlitePartnerMirror, MAX_RECORDED_PARTNER_CONFLICTS, MAX_REVOCATION_SUBJECT_BYTES,
};
use chio_security_types::clock::Clock;

use crate::passport_revocation_feed::{
    passport_revocation_root_verifier, PassportRevocationLeavesPage,
    MAX_PASSPORT_REVOCATION_PAGE_LEAVES, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::revocation_partner::{RevocationPartner, RevocationPartnerRegistry};

/// Most leaves one sync stages and applies. A partner further ahead than this
/// is refused. The final page may carry leaves past the offered root, up to one
/// page in all; those are dropped unstaged.
pub const MAX_PARTNER_SYNC_LEAVES: u64 = 65_536;

/// Largest amount a partner's signed root may be dated after this operator's
/// clock.
pub const MAX_PARTNER_ROOT_FUTURE_SKEW_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartnerRevocationError {
    #[error("partner `{0}` revocation mirror unavailable: {1}")]
    MirrorUnavailable(String, String),
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
    #[error("partner `{partner_id}` {error}")]
    Mirror {
        partner_id: String,
        error: PartnerMirrorError,
    },
    #[error("partner `{partner_id}` is {behind} revocation leaves ahead, beyond the {MAX_PARTNER_SYNC_LEAVES}-leaf sync bound")]
    TooFarBehind { partner_id: String, behind: u64 },
    #[error("partner `{0}` revocation root document is malformed: {1}")]
    MalformedRoot(String, String),
    #[error("partner `{0}` revocation leaves page is malformed: {1}")]
    MalformedPage(String, String),
    #[error("partner `{0}` revocation leaves ended before the signed root's leaf count")]
    TruncatedLeaves(String),
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

pub struct PartnerRevocationMirror {
    store: SqlitePartnerMirror,
}

impl PartnerRevocationMirror {
    /// Opens (creating if absent) the mirror of `partner_id` at `path`. A
    /// mirror stamped for another partner is refused.
    pub fn open(path: &Path, partner_id: &str) -> Result<Self, PartnerRevocationError> {
        let store = SqlitePartnerMirror::open(path, partner_id)
            .map_err(|error| mirror_error(partner_id, error))?;
        Ok(Self { store })
    }

    #[must_use]
    pub fn partner_id(&self) -> &str {
        self.store.partner_id()
    }

    /// The root this mirror last accepted.
    pub fn accepted(&self) -> Result<Option<SignedEpochRoot>, PartnerRevocationError> {
        self.store
            .accepted()
            .map_err(|error| mirror_error(self.partner_id(), error))
    }

    /// Refuses unless the accepted root verifies against `partner`'s pinned
    /// key, is fresh at `now_unix_ms` under `partner`'s freshness TTL, and
    /// equals the mirror's tree.
    pub fn require_fresh(
        &self,
        partner: &RevocationPartner,
        now_unix_ms: u64,
    ) -> Result<SignedEpochRoot, PartnerRevocationError> {
        self.fresh_view(partner, &[], now_unix_ms)
            .map(|(accepted, _)| accepted)
    }

    /// Reads the accepted root, the mirror tree's root and the first of
    /// `subjects` the tree holds, then requires that accepted root to verify
    /// against `partner`'s pinned key, be fresh at `now_unix_ms` and equal the
    /// tree.
    fn fresh_view(
        &self,
        partner: &RevocationPartner,
        subjects: &[RevocationKey],
        now_unix_ms: u64,
    ) -> Result<(SignedEpochRoot, Option<RevocationKey>), PartnerRevocationError> {
        let view = self
            .store
            .view(subjects)
            .map_err(|error| mirror_error(self.partner_id(), error))?;
        let accepted = view
            .accepted
            .ok_or_else(|| PartnerRevocationError::NoVerifiedRoot(self.partner_id().to_owned()))?;
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
        if !view.tree.same_tree(root) {
            return Err(mirror_error(
                self.partner_id(),
                PartnerMirrorRefusal::Diverged,
            ));
        }
        Ok((accepted, view.revoked))
    }

    /// Refuses unless the mirror is fresh at `now_unix_ms` and holds none of
    /// `subjects`.
    pub fn check_passport(
        &self,
        partner: &RevocationPartner,
        subjects: &[RevocationKey],
        now_unix_ms: u64,
    ) -> Result<(), PartnerRevocationError> {
        let (_, revoked) = self.fresh_view(partner, subjects, now_unix_ms)?;
        if let Some(subject) = revoked {
            return Err(PartnerRevocationError::Revoked {
                partner_id: self.partner_id().to_owned(),
                subject: subject.subject_id.as_str().to_owned(),
            });
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
            let room = usize::try_from(behind)
                .unwrap_or(usize::MAX)
                .saturating_sub(leaves.len());
            leaves.extend(page.leaves.into_iter().take(room));
            after = leaves.last().map_or(after, |leaf| leaf.seq);
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
        let error = match self.store.apply(offered, leaves, now_unix_ms) {
            Ok(root) => return Ok(root),
            Err(error) => error,
        };
        let conflict =
            matches!(&error, PartnerMirrorError::Refused(refusal) if refusal.is_conflict());
        let error = mirror_error(self.partner_id(), error);
        if conflict {
            self.record_conflict(&error, offered, now_unix_ms)?;
        }
        Err(error)
    }

    /// Records a conflicting signed root once, refusing a new one when the
    /// mirror already holds the bound.
    fn record_conflict(
        &self,
        refusal: &PartnerRevocationError,
        offered: &SignedEpochRoot,
        now_unix_ms: u64,
    ) -> Result<(), PartnerRevocationError> {
        match self
            .store
            .record_conflict(&refusal.to_string(), offered, now_unix_ms)
        {
            Ok(ConflictRecord::Recorded | ConflictRecord::AlreadyRecorded) => Ok(()),
            Ok(ConflictRecord::LogFull) => Err(PartnerRevocationError::ConflictLogFull(
                self.partner_id().to_owned(),
            )),
            Err(error) => Err(mirror_error(self.partner_id(), error)),
        }
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

fn mirror_error(partner_id: &str, error: impl Into<PartnerMirrorError>) -> PartnerRevocationError {
    PartnerRevocationError::Mirror {
        partner_id: partner_id.to_owned(),
        error: error.into(),
    }
}

fn leaf_count(root: &EpochRoot) -> u64 {
    crate::integer::count(root.leaf_count)
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
        if leaf.subject.len() > MAX_REVOCATION_SUBJECT_BYTES {
            return Err(malformed(
                "leaf subject exceeds the revocation subject bound",
            ));
        }
        previous = leaf.seq;
    }
    Ok(())
}

#[cfg(test)]
#[path = "passport_revocation_mirror_tests.rs"]
mod tests;
