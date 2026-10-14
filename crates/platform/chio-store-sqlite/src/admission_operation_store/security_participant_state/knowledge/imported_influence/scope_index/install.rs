//! Installation of the scope index rows and root, and their exact comparison
//! with an index rebuilt from the genuine sealed source.
use super::build::build_expected_index;
use super::model::{
    max_member_bytes, ExpectedScopeIndex, IndexRoot, MAX_PROOF_BYTES, MAX_SCOPE_MEMBERS,
};
use super::root::{authenticate_root, count_roots, save_root};
use super::*;

/// Build, persist and read back the index and its single protected root inside
/// the owning hydration transaction. The caller holds a source already
/// verified by `load_imported_source`. Nothing is visible before that
/// transaction commits, and the read-back refuses before it can.
pub(in crate::admission_operation_store) fn install_imported_scope_index(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    let binding = initialization.admission_binding()?;
    let authority = binding.security_authority_id().as_str();
    let expected = build_expected_index(tx, &binding)?;
    let mut statement = tx
        .prepare(
            "INSERT INTO security_participant_state_imported_scope_index
             (security_authority_id, leaf_index, scope_key, member_count, member_digest,
              inclusion_proof, members)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(sqlite_error)?;
    for (index, leaf) in expected.leaves().iter().enumerate() {
        statement
            .execute(params![
                authority,
                i64::try_from(index).map_err(invalid)?,
                leaf.scope_key,
                i64::try_from(leaf.member_count).map_err(invalid)?,
                leaf.member_digest,
                expected.proof_bytes(index)?,
                leaf.members
            ])
            .map_err(sqlite_error)?;
    }
    save_root(
        tx,
        owner,
        &binding,
        &IndexRoot::bind(
            &binding,
            initialization,
            expected.root(),
            expected.leaf_count(),
        )?,
    )?;
    verify_against(tx, &binding, initialization, &expected)
}

/// Rebuild the complete expected index and compare the installed leaves,
/// membership references, proofs and root exactly. The caller holds a source
/// already rehashed by `load_imported_source`.
pub(in crate::admission_operation_store) fn verify_imported_scope_index(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    let binding = initialization.admission_binding()?;
    let expected = build_expected_index(connection, &binding)?;
    verify_against(connection, &binding, initialization, &expected)
}

/// Index rows without a current initialization, and root records beyond the
/// initialized authorities, belong to an unsupported format or a forged
/// custody and refuse. A store whose schema predates the index has neither.
pub(in crate::admission_operation_store) fn verify_imported_scope_index_coverage(
    connection: &Connection,
    initialized_authorities: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let schema_present: bool = connection
        .query_row(
            "SELECT COUNT(*) = 2 FROM sqlite_schema
             WHERE name IN ('security_participant_state_imported_scope_index',
                            'admission_operation_recovery_records')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !schema_present {
        return Ok(());
    }
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_imported_scope_index AS child
             LEFT JOIN security_participant_state_initializations AS parent
             ON child.security_authority_id = parent.security_authority_id
             WHERE parent.security_authority_id IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invalid("imported scope index has no initialized authority"));
    }
    if count_roots(connection, initialized_authorities)? != initialized_authorities {
        return Err(invalid(
            "imported scope index roots differ from the initialized authorities",
        ));
    }
    Ok(())
}

fn verify_against(
    connection: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    initialization: &SecurityParticipantStateInitialization,
    expected: &ExpectedScopeIndex,
) -> Result<(), AdmissionOperationStoreError> {
    verify_installed_leaves(
        connection,
        binding.security_authority_id().as_str(),
        expected,
    )?;
    let installed = authenticate_root(connection, binding, initialization)?;
    if installed
        != IndexRoot::bind(
            binding,
            initialization,
            expected.root(),
            expected.leaf_count(),
        )?
    {
        return Err(invalid(
            "imported scope index root differs from its genuine sealed source",
        ));
    }
    Ok(())
}

/// Stream the installed rows in leaf order against the expected leaves. One
/// extra row detects excess custody without reading an unbounded inventory.
fn verify_installed_leaves(
    connection: &Connection,
    authority: &str,
    expected: &ExpectedScopeIndex,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT leaf_index,
                    CASE WHEN typeof(scope_key)='text' AND length(CAST(scope_key AS BLOB))=64
                         THEN scope_key END,
                    member_count,
                    CASE WHEN typeof(member_digest)='text' AND length(CAST(member_digest AS BLOB))=64
                         THEN member_digest END,
                    CASE WHEN typeof(inclusion_proof)='blob' AND length(inclusion_proof) BETWEEN 1 AND ?3
                         THEN inclusion_proof END,
                    CASE WHEN typeof(members)='blob' AND length(members) BETWEEN 2 AND ?4
                         THEN members END
             FROM security_participant_state_imported_scope_index
             WHERE security_authority_id = ?1 ORDER BY leaf_index LIMIT ?2",
        )
        .map_err(sqlite_error)?;
    let limit = i64::try_from(expected.leaves().len())
        .map_err(invalid)?
        .saturating_add(1);
    let mut rows = statement
        .query(params![
            authority,
            limit,
            i64::try_from(MAX_PROOF_BYTES).map_err(invalid)?,
            i64::try_from(max_member_bytes(MAX_SCOPE_MEMBERS)).map_err(invalid)?
        ])
        .map_err(sqlite_error)?;
    for (index, leaf) in expected.leaves().iter().enumerate() {
        let Some(row) = rows.next().map_err(sqlite_error)? else {
            return Err(invalid("installed imported scope leaf is absent"));
        };
        let matches = row.get::<_, i64>(0).map_err(sqlite_error)?
            == i64::try_from(index).map_err(invalid)?
            && row.get::<_, String>(1).map_err(sqlite_error)? == leaf.scope_key
            && row.get::<_, i64>(2).map_err(sqlite_error)?
                == i64::try_from(leaf.member_count).map_err(invalid)?
            && row.get::<_, String>(3).map_err(sqlite_error)? == leaf.member_digest
            && row.get::<_, Vec<u8>>(4).map_err(sqlite_error)? == expected.proof_bytes(index)?
            && row.get::<_, Vec<u8>>(5).map_err(sqlite_error)? == leaf.members;
        if !matches {
            return Err(invalid(
                "installed imported scope leaf differs from the genuine source",
            ));
        }
    }
    if rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invalid(
            "installed imported scope leaves exceed the genuine source",
        ));
    }
    Ok(())
}
