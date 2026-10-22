//! The `revocation_entry` projection: every revocation entry has exactly one
//! global commit, and every such commit names a stored entry.

use super::*;

#[derive(Serialize)]
struct RevocationEntryReference<'a> {
    format: &'static str,
    entry_seq: u64,
    entry_id: &'a str,
    target_kind: &'a str,
    target_value: &'a str,
    revoked_at: i64,
    reason: &'a str,
}

pub(super) fn reference_digest(
    connection: &Connection,
    entry_id: &str,
    entry_seq: u64,
) -> Result<String, SqliteServingOwnerError> {
    let (target_kind, target_value, revoked_at, reason) = connection
        .query_row(
            r#"
            SELECT target_kind, target_value, revoked_at, reason
            FROM revocation_entries
            WHERE entry_id = ?1 AND entry_seq = ?2
            "#,
            params![
                entry_id,
                sqlite_u64(entry_seq, "revocation entry sequence")?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid("revocation entry projection reference is absent"))?;
    digest(&RevocationEntryReference {
        format: "chio.sqlite-authority-revocation-entry-reference.v1",
        entry_seq,
        entry_id,
        target_kind: &target_kind,
        target_value: &target_value,
        revoked_at,
        reason: &reason,
    })
}

/// Coverage: one commit per entry at its `entry_seq`. Absence: no commit
/// whose entry is missing. An entry that revoked no capability is covered
/// like any other.
pub(super) fn verify_coverage(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let incomplete = connection.query_row(
        r#"
        SELECT
            EXISTS(
                SELECT 1 FROM revocation_entries AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'revocation_entry'
                      AND global.projection_key = local.entry_id
                      AND global.projection_sequence = local.entry_seq
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'revocation_entry'
                  AND NOT EXISTS(
                      SELECT 1 FROM revocation_entries AS local
                      WHERE local.entry_id = global.projection_key
                        AND local.entry_seq = global.projection_sequence
                  )
            )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if incomplete {
        return Err(invalid("revocation entry projection coverage is not exact"));
    }
    Ok(())
}
