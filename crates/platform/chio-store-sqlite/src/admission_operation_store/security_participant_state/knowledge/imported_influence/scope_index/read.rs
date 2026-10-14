//! Warm scope reads: authenticate one requested scope against the protected
//! root, then fetch and rehash that scope's actual current sealed source rows.
//! The work is bounded by the proof depth and by the scope's own membership,
//! never by the history of any other scope. No cached source-body summary is
//! ever returned as proof.
use super::model::{
    decode_members, leaf_payload, max_member_bytes, member_digest, verify_leaf_proof, IndexRoot,
    MAX_PROOF_BYTES, MAX_PROOF_DEPTH, MAX_SCOPE_MEMBERS, MAX_SOURCE_ROW_BYTES,
};
use super::*;
use crate::admission_operation_store::security_participant_migration::MAX_TOTAL_BYTES;
use crate::security_state::decode_retained_security_row;

/// Work charged per requested scope before any index row is read: a present
/// scope verifies one proof and an absent scope verifies two adjacent proofs.
const SCOPE_PROOF_WORK: u32 = 2 * (MAX_PROOF_DEPTH as u32 + 1);
/// Work charged for authenticating the protected root.
pub(in crate::admission_operation_store) const ROOT_WORK: u32 = 1;

/// One current sealed source row selected by a scope.
pub(in crate::admission_operation_store) struct ScopeMember {
    pub(in crate::admission_operation_store) ordinal: u16,
    pub(in crate::admission_operation_store) row_index: u32,
    pub(in crate::admission_operation_store) row_digest: String,
}

struct StoredLeaf {
    leaf_index: u64,
    scope_key: String,
    member_count: u64,
    member_digest: String,
    inclusion_proof: Vec<u8>,
}

/// Where a requested key sits relative to the stored leaves.
enum Position {
    Exact,
    Before,
    After,
}

impl Position {
    fn filter(&self) -> (&'static str, &'static str) {
        match self {
            Self::Exact => ("=", "ASC"),
            Self::Before => ("<", "DESC"),
            Self::After => (">", "ASC"),
        }
    }
}

/// A stored 64-character lowercase hex value, as the writer produces.
fn stored_digest(value: Option<String>) -> Result<String, AdmissionOperationStoreError> {
    value
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| invalid("imported scope index leaf is malformed"))
}

/// Fetch the nearest stored leaf at this position. The key, digest and proof
/// columns are returned only inside their type and byte bounds, so an
/// oversized or mistyped value is never materialized.
fn fetch_leaf(
    connection: &Connection,
    authority: &str,
    scope_key: &str,
    position: &Position,
) -> Result<Option<StoredLeaf>, AdmissionOperationStoreError> {
    let (comparison, order) = position.filter();
    let stored = connection
        .query_row(
            &format!(
                "SELECT leaf_index,
                        CASE WHEN typeof(scope_key) = 'text'
                              AND length(CAST(scope_key AS BLOB)) = 64 THEN scope_key END,
                        member_count,
                        CASE WHEN typeof(member_digest) = 'text'
                              AND length(CAST(member_digest AS BLOB)) = 64 THEN member_digest END,
                        CASE WHEN typeof(inclusion_proof) = 'blob'
                              AND length(inclusion_proof) BETWEEN 1 AND ?3 THEN inclusion_proof END
                 FROM security_participant_state_imported_scope_index
                 WHERE security_authority_id = ?1 AND scope_key {comparison} ?2
                 ORDER BY scope_key {order} LIMIT 1"
            ),
            params![
                authority,
                scope_key,
                i64::try_from(MAX_PROOF_BYTES).map_err(invalid)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((leaf_index, stored_key, member_count, digest, proof)) = stored else {
        return Ok(None);
    };
    let member_count = u64::try_from(member_count).map_err(invalid)?;
    if member_count == 0 || member_count > MAX_SCOPE_MEMBERS {
        return Err(invalid("imported scope membership exceeds bounds"));
    }
    Ok(Some(StoredLeaf {
        leaf_index: u64::try_from(leaf_index).map_err(invalid)?,
        scope_key: stored_digest(stored_key)?,
        member_count,
        member_digest: stored_digest(digest)?,
        inclusion_proof: proof.ok_or_else(|| invalid("imported scope proof exceeds bounds"))?,
    }))
}

fn authenticate_leaf(
    root: &IndexRoot,
    leaf: &StoredLeaf,
) -> Result<(), AdmissionOperationStoreError> {
    verify_leaf_proof(
        root,
        leaf.leaf_index,
        &leaf_payload(&leaf.scope_key, leaf.member_count, &leaf.member_digest)?,
        &leaf.inclusion_proof,
    )
}

/// Authenticate one requested scope: its exact leaf when present, or the two
/// immediately adjacent leaves (an authenticated endpoint standing in for a
/// missing neighbor) whose consecutive leaf indices leave no room for it.
fn authenticate_scope(
    connection: &Connection,
    authority: &str,
    root: &IndexRoot,
    scope_key: &str,
) -> Result<Option<StoredLeaf>, AdmissionOperationStoreError> {
    if root.leaf_count() == 0 {
        return Ok(None);
    }
    if let Some(leaf) = fetch_leaf(connection, authority, scope_key, &Position::Exact)? {
        authenticate_leaf(root, &leaf)?;
        return Ok(Some(leaf));
    }
    let lower = fetch_leaf(connection, authority, scope_key, &Position::Before)?;
    let upper = fetch_leaf(connection, authority, scope_key, &Position::After)?;
    for neighbor in lower.iter().chain(upper.iter()) {
        authenticate_leaf(root, neighbor)?;
    }
    let first_gap = match &lower {
        Some(leaf) => leaf
            .leaf_index
            .checked_add(1)
            .ok_or_else(|| invalid("imported scope leaf index exhausted"))?,
        None => 0,
    };
    let end_gap = upper
        .as_ref()
        .map_or(root.leaf_count(), |leaf| leaf.leaf_index);
    if first_gap != end_gap {
        return Err(invalid("imported scope absence is unauthenticated"));
    }
    Ok(None)
}

/// The authenticated current members of one scope, or none when the scope is
/// genuinely absent. Every selected source row is fetched by primary key within
/// its byte bound, decoded under the retained codec, must still match the
/// queried flow, and the complete member digest is recomputed against the
/// authenticated leaf. A missing, changed, repointed or reordered member
/// refuses.
pub(in crate::admission_operation_store) fn read_scope_members(
    connection: &Connection,
    authority: &str,
    root: &IndexRoot,
    key: &FlowStateKey,
    scope_key: &str,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Vec<ScopeMember>, AdmissionOperationStoreError> {
    budget.charge(SCOPE_PROOF_WORK).map_err(invalid)?;
    let Some(leaf) = authenticate_scope(connection, authority, root, scope_key)? else {
        return Ok(Vec::new());
    };
    budget
        .charge(u32::try_from(leaf.member_count).map_err(invalid)?)
        .map_err(invalid)?;
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT CASE WHEN typeof(members) = 'blob' AND length(members) BETWEEN 2 AND ?3
                         THEN members END
             FROM security_participant_state_imported_scope_index
             WHERE security_authority_id = ?1 AND scope_key = ?2",
            params![
                authority,
                leaf.scope_key,
                i64::try_from(max_member_bytes(leaf.member_count)).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let references = decode_members(
        &encoded.ok_or_else(|| invalid("imported scope membership exceeds bounds"))?,
        leaf.member_count,
    )?;
    let mut statement = connection
        .prepare(
            "SELECT canonical_row FROM security_participant_migration_rows
             WHERE security_authority_id = ?1 AND table_name = ?2 AND row_index = ?3
               AND typeof(canonical_row)='blob' AND length(canonical_row) BETWEEN 1 AND ?4",
        )
        .map_err(sqlite_error)?;
    let mut committed = Vec::with_capacity(references.len());
    let mut members = Vec::with_capacity(references.len());
    // Every scope is a subset of the bounded sealed inventory. Enforce its
    // aggregate byte ceiling even if current source rows were enlarged after
    // initialization, before allocating or decoding the next member.
    let mut remaining_bytes = MAX_TOTAL_BYTES;
    let row_limit = u64::try_from(MAX_SOURCE_ROW_BYTES).map_err(invalid)?;
    for (ordinal, row_index) in references {
        let table = RELEVANT_TABLES[usize::from(ordinal)];
        let bytes: Vec<u8> = statement
            .query_row(
                params![
                    authority,
                    table,
                    i64::from(row_index),
                    i64::try_from(remaining_bytes.min(row_limit)).map_err(invalid)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| invalid("imported scope member is absent or exceeds its byte bound"))?;
        remaining_bytes = remaining_bytes
            .checked_sub(u64::try_from(bytes.len()).map_err(invalid)?)
            .ok_or_else(|| invalid("imported scope exceeds the source byte bound"))?;
        let values = decode_retained_security_row(table, &bytes).map_err(invalid)?;
        if !matches_flow(table, &values, key)? {
            return Err(invalid(
                "imported scope member no longer matches its queried flow",
            ));
        }
        let row_digest = sha256_hex(&bytes);
        committed.push((table, row_index, row_digest.clone()));
        members.push(ScopeMember {
            ordinal,
            row_index,
            row_digest,
        });
    }
    if member_digest(&leaf.scope_key, &committed)? != leaf.member_digest {
        return Err(invalid(
            "imported scope member bytes differ from their committed digest",
        ));
    }
    Ok(members)
}
