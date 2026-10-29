//! Revocation by root policy rule, subject tag, tenant tag and replay key.
//!
//! A target entry is recorded once and, in the same IMMEDIATE transaction,
//! marks every anchored root it matches in `revoked_capabilities`, so the
//! existing admission and capture readers refuse those roots. A subject or
//! tenant entry carries its tag under every loaded tenant index generation in
//! `revocation_entry_tags`, and every match is on `(tag_key_id, tag)`.

use std::collections::{BTreeMap, BTreeSet};

use chio_core::root_authority::{
    RevocationCoverage, RevocationCoverageRoot, RevocationEntry, RevocationEntryId,
    RevocationReason, RevocationTarget, RevocationTargetKind, Sha256Digest,
};
use chio_core::tenant_index::KeyedIndexValue;
use chio_kernel::RevocationStoreError;
use rusqlite::{params, OptionalExtension, Transaction};

use super::{commit_mutation, map_serving_owner_error, stored_entry, SqliteRevocationStore};
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

#[cfg(test)]
thread_local! {
    /// How many roots a target revocation on this thread marks before it
    /// fails, so a test can stop the fan-out part way through.
    pub(super) static FAN_OUT_FAILS_AFTER: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

const ENTRY_COLUMNS: &str = "entry_seq, entry_id, target_kind, target_value, revoked_at, reason";

impl SqliteRevocationStore {
    /// Records the entry for `target` and marks every anchored root it
    /// matches revoked, expired roots included, in one IMMEDIATE transaction.
    ///
    /// `tags` is the tag of an `anchor_subject` or `tenant_tag` target under
    /// every loaded generation, the one named by `active_key_id` first; the
    /// first value is the target value. Every other kind carries no tags and
    /// no active generation. A stored entry keeps its first `revoked_at`,
    /// reason and tags.
    pub fn revoke_target(
        &self,
        target: &RevocationTarget,
        tags: &[KeyedIndexValue],
        active_key_id: Option<&Sha256Digest>,
        reason: RevocationReason,
    ) -> Result<TargetRevocation, RevocationStoreError> {
        check_target_tags(target, tags, active_key_id)?;
        if self.serving_owner.is_none() && target.kind() != RevocationTargetKind::CapabilityId {
            return Err(RevocationStoreError::TargetRequiresServingOwner {
                kind: target.kind().as_str(),
            });
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let revoked_at = self.clock.now_secs()?;
        let (entry_id, newly_revoked) =
            self.record_revocation_entry(&transaction, target, revoked_at, reason)?;
        if newly_revoked {
            for tag in tags {
                transaction.execute(
                    "INSERT INTO revocation_entry_tags (entry_id, tag_key_id, tag)
                     VALUES (?1, ?2, ?3)",
                    params![
                        entry_id.as_str(),
                        tag.key_id.to_bare_hex(),
                        tag.value.to_bare_hex()
                    ],
                )?;
            }
        }
        let matched = matching_capabilities(&transaction, target, &entry_id)?;
        let mut roots_revoked = 0_u64;
        for capability_id in &matched {
            #[cfg(test)]
            if FAN_OUT_FAILS_AFTER.with(std::cell::Cell::get) == Some(roots_revoked) {
                return Err(RevocationStoreError::Sync(
                    "injected fan-out failure".to_string(),
                ));
            }
            if self.mark_revoked(&transaction, capability_id, revoked_at, &entry_id)? {
                roots_revoked += 1;
            }
        }
        let entry = load_entry(&transaction, &entry_id)?;
        let revocation = TargetRevocation {
            entry,
            newly_revoked,
            roots_matched: crate::integer::checked(matched.len())?,
            roots_revoked,
        };
        if !newly_revoked && roots_revoked == 0 {
            transaction.rollback()?;
            return Ok(revocation);
        }
        commit_mutation(self, transaction)?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .sync_authority_anchor(&connection)
                .map_err(map_serving_owner_error)?;
        }
        Ok(revocation)
    }

    /// The entries that cover each exported root: an entry whose target the
    /// root's anchored row matches covers the root id, and a `capability_id`
    /// entry covers its capability when the root or its capability ids name
    /// it. Read from one snapshot of `root_exchange_roots`,
    /// `revocation_entries` and `revocation_entry_tags`, expired roots
    /// included, in `entry_seq` order. A root without its anchored row fails
    /// the whole call.
    pub fn revocations_covering(
        &self,
        roots: &[RevocationCoverageRoot],
    ) -> Result<Vec<RevocationCoverage>, RevocationStoreError> {
        if self.serving_owner.is_none() {
            return Err(RevocationStoreError::CoverageRequiresServingOwner);
        }
        self.read(|transaction| {
            let mut covering: BTreeMap<i64, (RevocationEntry, BTreeSet<String>)> = BTreeMap::new();
            for root in roots {
                for (entry_seq, entry) in entries_matching_root(transaction, root)? {
                    covering
                        .entry(entry_seq)
                        .or_insert_with(|| (entry, BTreeSet::new()))
                        .1
                        .insert(root.root_capability_id.clone());
                }
                let capability_ids = std::iter::once(&root.root_capability_id)
                    .chain(root.capability_ids.iter())
                    .collect::<BTreeSet<_>>();
                for capability_id in capability_ids {
                    let Some((entry_seq, entry)) = optional_entry(
                        transaction,
                        &format!(
                            "SELECT {ENTRY_COLUMNS} FROM revocation_entries
                             WHERE target_kind = 'capability_id' AND target_value = ?1"
                        ),
                        params![capability_id],
                    )?
                    else {
                        continue;
                    };
                    covering
                        .entry(entry_seq)
                        .or_insert_with(|| (entry, BTreeSet::new()))
                        .1
                        .insert(capability_id.clone());
                }
            }
            Ok(covering
                .into_values()
                .map(|(entry, covered)| RevocationCoverage {
                    entry,
                    covered_capability_ids: covered.into_iter().collect(),
                })
                .collect())
        })
    }
}

/// The production mint check: the lowest `entry_seq` entry the candidate
/// matches refuses the mint, read inside the mint transaction so no entry
/// can commit between the check and the root.
impl MintRevocationCheck for SqliteRevocationStore {
    fn refuse_revoked_root(
        &self,
        transaction: &Transaction<'_>,
        candidate: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        match first_matching_entry(transaction, candidate) {
            Ok(None) => Ok(()),
            Ok(Some(entry_id)) => Err(MintRevocationRefusal::Revoked {
                entry_id: entry_id.to_string(),
            }),
            Err(error) => Err(MintRevocationRefusal::Unavailable(error.to_string())),
        }
    }
}

fn check_target_tags(
    target: &RevocationTarget,
    tags: &[KeyedIndexValue],
    active_key_id: Option<&Sha256Digest>,
) -> Result<(), RevocationStoreError> {
    let invalid = |detail| Err(RevocationStoreError::InvalidTargetTags(detail));
    if !is_tag_kind(target.kind()) {
        return match (tags.is_empty(), active_key_id) {
            (false, _) => invalid("only a tag target carries tags"),
            (true, Some(_)) => invalid("only a tag target names an active generation"),
            (true, None) => Ok(()),
        };
    }
    let Some(active_key_id) = active_key_id else {
        return invalid("a tag target names its active generation");
    };
    let Some(active) = tags.first() else {
        return invalid("a tag target needs its tag under every loaded generation");
    };
    if active.key_id != *active_key_id {
        return invalid("the first tag is not under the active generation");
    }
    if active.value.to_bare_hex() != target.value() {
        return invalid("the first tag is the target value under the active generation");
    }
    let generations = tags.iter().map(|tag| tag.key_id).collect::<BTreeSet<_>>();
    if generations.len() != tags.len() {
        return invalid("each generation carries one tag");
    }
    Ok(())
}

const fn is_tag_kind(kind: RevocationTargetKind) -> bool {
    matches!(
        kind,
        RevocationTargetKind::AnchorSubject | RevocationTargetKind::TenantTag
    )
}

/// The capability ids `target` marks, ordered: the capability itself, or
/// every anchored root whose target column matches.
fn matching_capabilities(
    transaction: &Transaction<'_>,
    target: &RevocationTarget,
    entry_id: &RevocationEntryId,
) -> Result<Vec<String>, RevocationStoreError> {
    let (sql, value) = match target.kind() {
        RevocationTargetKind::CapabilityId => return Ok(vec![target.value().to_string()]),
        RevocationTargetKind::RootPolicyRule => (
            "SELECT capability_id FROM root_exchange_roots
             WHERE root_policy_rule_id = ?1 ORDER BY capability_id",
            target.value(),
        ),
        RevocationTargetKind::ReplayKey => (
            "SELECT capability_id FROM root_exchange_roots
             WHERE replay_key_digest = ?1 ORDER BY capability_id",
            target.value(),
        ),
        RevocationTargetKind::AnchorSubject => (
            "SELECT roots.capability_id FROM root_exchange_roots AS roots
             JOIN revocation_entry_tags AS tags
               ON tags.tag_key_id = roots.tag_key_id AND tags.tag = roots.subject_tag
             WHERE tags.entry_id = ?1 ORDER BY roots.capability_id",
            entry_id.as_str(),
        ),
        RevocationTargetKind::TenantTag => (
            "SELECT roots.capability_id FROM root_exchange_roots AS roots
             JOIN revocation_entry_tags AS tags
               ON tags.tag_key_id = roots.tag_key_id AND tags.tag = roots.tenant_tag
             WHERE tags.entry_id = ?1 ORDER BY roots.capability_id",
            entry_id.as_str(),
        ),
    };
    let mut statement = transaction.prepare(sql)?;
    let rows = statement
        .query_map(params![value], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Every entry the anchored row of `root` matches, by the fan-out rule.
fn entries_matching_root(
    transaction: &Transaction<'_>,
    root: &RevocationCoverageRoot,
) -> Result<Vec<(i64, RevocationEntry)>, RevocationStoreError> {
    let row = transaction
        .query_row(
            "SELECT root_policy_rule_id, tag_key_id, subject_tag, tenant_tag, replay_key_digest
             FROM root_exchange_roots WHERE capability_id = ?1",
            params![root.root_capability_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((rule_id, tag_key_id, subject_tag, tenant_tag, replay_key_digest)) = row else {
        return Err(RevocationStoreError::AnchoredRootMissing {
            capability_id: root.root_capability_id.clone(),
        });
    };
    entries(
        transaction,
        &format!(
            "SELECT {ENTRY_COLUMNS} FROM revocation_entries AS entries
             WHERE (target_kind = 'root_policy_rule' AND target_value = ?1)
                OR (target_kind = 'replay_key' AND target_value = ?2)
                OR EXISTS (
                    SELECT 1 FROM revocation_entry_tags AS tags
                    WHERE tags.entry_id = entries.entry_id AND tags.tag_key_id = ?3
                      AND ((entries.target_kind = 'anchor_subject' AND tags.tag = ?4)
                        OR (entries.target_kind = 'tenant_tag' AND tags.tag = ?5))
                )
             ORDER BY entry_seq"
        ),
        params![
            rule_id,
            replay_key_digest,
            tag_key_id,
            subject_tag,
            tenant_tag
        ],
    )
}

/// The lowest `entry_seq` entry the candidate matches: its capability id,
/// root policy rule or replay key, or its subject or tenant tag under any
/// loaded generation.
fn first_matching_entry(
    transaction: &Transaction<'_>,
    candidate: &RevocationCandidate<'_>,
) -> Result<Option<RevocationEntryId>, RevocationStoreError> {
    let mut first = optional_seq(
        transaction,
        "SELECT entry_seq, entry_id FROM revocation_entries
         WHERE (target_kind = 'capability_id' AND target_value = ?1)
            OR (target_kind = 'root_policy_rule' AND target_value = ?2)
            OR (target_kind = 'replay_key' AND target_value = ?3)
         ORDER BY entry_seq LIMIT 1",
        params![
            candidate.capability_id,
            candidate.root_policy_rule_id,
            candidate.replay_key_digest.to_bare_hex()
        ],
    )?;
    for tags in candidate.tag_candidates {
        for (kind, tag) in [
            (RevocationTargetKind::AnchorSubject, &tags.subject),
            (RevocationTargetKind::TenantTag, &tags.tenant),
        ] {
            let found = optional_seq(
                transaction,
                "SELECT entries.entry_seq, entries.entry_id
                 FROM revocation_entry_tags AS tags
                 JOIN revocation_entries AS entries ON entries.entry_id = tags.entry_id
                 WHERE tags.tag_key_id = ?1 AND tags.tag = ?2 AND entries.target_kind = ?3
                 ORDER BY entries.entry_seq LIMIT 1",
                params![
                    tag.key_id.to_bare_hex(),
                    tag.value.to_bare_hex(),
                    kind.as_str()
                ],
            )?;
            first = match (first, found) {
                (Some(current), Some(next)) if next.0 < current.0 => Some(next),
                (None, next) => next,
                (current, _) => current,
            };
        }
    }
    first
        .map(|(_, entry_id)| {
            RevocationEntryId::parse(&entry_id).map_err(|error| {
                RevocationStoreError::Sync(format!("stored revocation entry id: {error}"))
            })
        })
        .transpose()
}

fn optional_seq(
    transaction: &Transaction<'_>,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Option<(i64, String)>, RevocationStoreError> {
    Ok(transaction
        .query_row(sql, params, |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?)
}

type EntryRow = (i64, String, String, String, i64, String);

fn entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode(row: EntryRow) -> Result<(i64, RevocationEntry), RevocationStoreError> {
    let (entry_seq, entry_id, kind, value, revoked_at, reason) = row;
    Ok((
        entry_seq,
        stored_entry(&entry_id, &kind, &value, revoked_at, &reason)?,
    ))
}

fn entries(
    transaction: &Transaction<'_>,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<(i64, RevocationEntry)>, RevocationStoreError> {
    let mut statement = transaction.prepare(sql)?;
    let rows = statement
        .query_map(params, entry_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(decode).collect()
}

fn optional_entry(
    transaction: &Transaction<'_>,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Option<(i64, RevocationEntry)>, RevocationStoreError> {
    transaction
        .query_row(sql, params, entry_row)
        .optional()?
        .map(decode)
        .transpose()
}

fn load_entry(
    transaction: &Transaction<'_>,
    entry_id: &RevocationEntryId,
) -> Result<RevocationEntry, RevocationStoreError> {
    optional_entry(
        transaction,
        &format!("SELECT {ENTRY_COLUMNS} FROM revocation_entries WHERE entry_id = ?1"),
        params![entry_id.as_str()],
    )?
    .map(|(_, entry)| entry)
    .ok_or_else(|| RevocationStoreError::Sync("recorded revocation entry is absent".to_string()))
}

/// Refuses a catalog whose tag rows disagree with their entries: a subject
/// or tenant entry has exactly one tag row whose tag is its target value,
/// and every other entry has none.
pub(super) fn verify_entry_tags(
    transaction: &rusqlite::Connection,
) -> Result<(), RevocationStoreError> {
    let inconsistent = transaction
        .query_row(
            "SELECT entries.entry_id FROM revocation_entries AS entries
             WHERE (entries.target_kind IN ('anchor_subject', 'tenant_tag')
                    AND (SELECT COUNT(*) FROM revocation_entry_tags AS tags
                         WHERE tags.entry_id = entries.entry_id
                           AND tags.tag = entries.target_value) <> 1)
                OR (entries.target_kind NOT IN ('anchor_subject', 'tenant_tag')
                    AND EXISTS (SELECT 1 FROM revocation_entry_tags AS tags
                                WHERE tags.entry_id = entries.entry_id))
             ORDER BY entries.entry_seq LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let orphan = transaction
        .query_row(
            "SELECT tags.entry_id FROM revocation_entry_tags AS tags
             WHERE NOT EXISTS (SELECT 1 FROM revocation_entries AS entries
                               WHERE entries.entry_id = tags.entry_id)
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match inconsistent.or(orphan) {
        Some(entry_id) => Err(RevocationStoreError::InconsistentTagRows { entry_id }),
        None => Ok(()),
    }
}
