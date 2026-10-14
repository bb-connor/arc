//! Construction of the expected scope index from the sealed source rows.
use super::model::{
    encode_members, member_digest, ExpectedScopeIndex, MemberReference, ScopeLeaf,
    MAX_MEMBER_ROW_INDEX, MAX_SCOPE_MEMBERS,
};
use super::*;
use crate::security_state::decode_retained_security_row;
use std::collections::BTreeMap;

/// Build the complete expected index for one authority. Callers hold a source
/// already rehashed against its pinned inventory by `load_imported_source`, so
/// only the flow-bearing tables are read, once, in table and row order.
/// Lifecycle metadata contributes no member, exactly as the reader's match
/// rules prescribe.
pub(super) fn build_expected_index(
    connection: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
) -> Result<ExpectedScopeIndex, AdmissionOperationStoreError> {
    let authority = binding.security_authority_id().as_str();
    // Members are pushed in (table ordinal, row index) order, which is the
    // strict order every scope's member list must have.
    let mut scopes: BTreeMap<String, Vec<(MemberReference, String)>> = BTreeMap::new();
    let mut statement = connection
        .prepare(
            "SELECT row_index, canonical_row FROM security_participant_migration_rows
             WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
        )
        .map_err(sqlite_error)?;
    for (ordinal, table) in RELEVANT_TABLES.iter().enumerate() {
        let ordinal = u16::try_from(ordinal).map_err(invalid)?;
        let mut rows = statement
            .query(params![authority, table])
            .map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let row_index =
                u32::try_from(row.get::<_, i64>(0).map_err(sqlite_error)?).map_err(invalid)?;
            if row_index > MAX_MEMBER_ROW_INDEX {
                return Err(invalid("imported source row index exceeds bounds"));
            }
            let bytes = row
                .get_ref(1)
                .map_err(sqlite_error)?
                .as_blob()
                .map_err(invalid)?;
            let values = decode_retained_security_row(table, bytes).map_err(invalid)?;
            let row_digest = sha256_hex(bytes);
            for scope in assigned_scopes(table, &values)? {
                scopes
                    .entry(scope.scope_key(binding)?)
                    .or_default()
                    .push(((ordinal, row_index), row_digest.clone()));
            }
        }
    }
    let leaves = scopes
        .into_iter()
        .map(|(scope_key, members)| scope_leaf(scope_key, members))
        .collect::<Result<Vec<_>, _>>()?;
    ExpectedScopeIndex::from_leaves(leaves)
}

fn scope_leaf(
    scope_key: String,
    members: Vec<(MemberReference, String)>,
) -> Result<ScopeLeaf, AdmissionOperationStoreError> {
    let member_count = u64::try_from(members.len()).map_err(invalid)?;
    if member_count > MAX_SCOPE_MEMBERS {
        return Err(invalid("imported scope membership exceeds bounds"));
    }
    let references: Vec<MemberReference> =
        members.iter().map(|(reference, _)| *reference).collect();
    let committed: Vec<(&'static str, u32, String)> = members
        .into_iter()
        .map(|((ordinal, row_index), digest)| {
            (RELEVANT_TABLES[usize::from(ordinal)], row_index, digest)
        })
        .collect();
    Ok(ScopeLeaf {
        member_digest: member_digest(&scope_key, &committed)?,
        members: encode_members(&references)?,
        member_count,
        scope_key,
    })
}
