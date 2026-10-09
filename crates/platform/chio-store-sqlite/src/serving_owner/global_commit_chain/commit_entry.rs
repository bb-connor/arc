use super::*;

pub(super) struct CommitChainEntry<'a> {
    pub(super) mutation_kind: &'a str,
    pub(super) projection_kind: &'a str,
    pub(super) projection_key: &'a str,
    pub(super) projection_sequence: u64,
    pub(super) projection_reference_digest: &'a str,
    pub(super) authority_projection_digest: &'a str,
    pub(super) store_uuid: &'a str,
    pub(super) store_lease_id: Option<&'a str>,
    pub(super) store_owner_epoch: u64,
}

pub(super) fn append_entry(
    transaction: &Transaction<'_>,
    params: CommitChainEntry<'_>,
) -> Result<(), SqliteServingOwnerError> {
    let CommitChainEntry {
        mutation_kind,
        projection_kind,
        projection_key,
        projection_sequence,
        projection_reference_digest,
        authority_projection_digest,
        store_uuid,
        store_lease_id,
        store_owner_epoch,
    } = params;
    let current = load_global_commit_head(transaction)?;
    let next = current
        .head_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("global authority commit sequence overflowed"))?;
    let chain_digest = chain_digest(&ChainEntry {
        format: "chio.sqlite-authority-global-commit.v1",
        previous_chain_digest: &current.chain_digest,
        commit_sequence: next,
        mutation_kind,
        projection_kind,
        projection_key,
        projection_sequence,
        projection_reference_digest,
        authority_projection_digest,
        store_uuid,
        store_lease_id,
        store_owner_epoch,
    })?;
    let inserted = transaction.execute(
        r#"
        INSERT INTO authority_global_commits (
            commit_sequence, mutation_kind, projection_kind, projection_key,
            projection_sequence, projection_reference_digest,
            authority_projection_digest, previous_chain_digest, chain_digest,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            sqlite_u64(next, "commit_sequence")?,
            mutation_kind,
            projection_kind,
            projection_key,
            sqlite_u64(projection_sequence, "projection_sequence")?,
            projection_reference_digest,
            authority_projection_digest,
            &current.chain_digest,
            &chain_digest,
            store_uuid,
            store_lease_id,
            sqlite_u64(store_owner_epoch, "store_owner_epoch")?,
        ],
    )?;
    let advanced = transaction.execute(
        r#"
        UPDATE authority_global_commit_meta
        SET head_sequence = ?1, head_chain_digest = ?2
        WHERE singleton = 1 AND head_sequence = ?3 AND head_chain_digest = ?4
        "#,
        params![
            sqlite_u64(next, "commit_sequence")?,
            chain_digest,
            sqlite_u64(current.head_sequence, "current_commit_sequence")?,
            current.chain_digest,
        ],
    )?;
    if inserted != 1 || advanced != 1 {
        return Err(invalid(
            "global authority commit chain did not advance exactly once",
        ));
    }
    Ok(())
}
