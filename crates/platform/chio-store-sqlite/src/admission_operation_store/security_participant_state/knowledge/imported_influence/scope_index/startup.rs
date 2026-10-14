//! Startup publication of the imported scope index root for genuine
//! initializations that were hydrated before the index existed.
//!
//! Only an initialization recorded under a historical native catalog may lack
//! its root, and only while the root key has no retained custody and the
//! authority has no index rows. Every other missing, partial or erased root
//! refuses; a normal open never rebuilds one.
use super::install::install_imported_scope_index;
use super::root::record_key;
use super::*;
use crate::admission_operation_store::security_participant_state::schema;

fn startup_error(error: AdmissionOperationStoreError) -> crate::SqliteServingOwnerError {
    crate::SqliteServingOwnerError::Invalid(error.to_string())
}

/// Whether this initialization is a genuine historical hydration still waiting
/// for its root. Returns false once the protected root exists. A root-less
/// initialization of the current catalog, or one whose root or index custody
/// was partly erased, is an error.
pub(in crate::admission_operation_store) fn historical_root_pending(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<bool, AdmissionOperationStoreError> {
    let authority = initialization.security_authority_id().as_str();
    let key = record_key(authority);
    // Refuses when retained history names a root whose row disappeared.
    if protected::raw_checked(connection, &key)?.is_some() {
        return Ok(false);
    }
    let custody: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM admission_operation_recovery_events WHERE record_key=?1)
                  + (SELECT COUNT(*) FROM authority_global_commits
                     WHERE projection_kind='recovery' AND projection_key=?1)",
            [&key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let indexed: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_imported_scope_index
             WHERE security_authority_id=?1)",
            [authority],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if custody != 0 || indexed {
        return Err(invalid(
            "imported scope index root lost its retained custody",
        ));
    }
    if !initialization.requires_imported_influence_upgrade()? {
        return Err(invalid(
            "native initialization is missing its imported scope index root",
        ));
    }
    Ok(true)
}

/// Publish the root and index of every genuinely pending historical
/// initialization in one immediate transaction under the current owner and
/// anchor, then sync the anchor before serving. All original initialization
/// ids, digests, source bytes and global commits stay unchanged.
pub(crate) fn publish_imported_influence_roots_at_startup(
    connection: &mut Connection,
    owner: &SqliteServingOwner,
) -> Result<usize, crate::SqliteServingOwnerError> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(crate::SqliteServingOwnerError::from)?;
    verify_active_owner(&tx, owner, Some(&owner.fence)).map_err(startup_error)?;
    owner.verify_authority_anchor(&tx)?;
    let published = publish_pending(&tx, owner).map_err(startup_error)?;
    tx.commit().map_err(|error| {
        owner.outcome_unknown(format!(
            "imported influence root startup commit outcome unknown: {error}"
        ))
    })?;
    if published != 0 {
        owner.sync_authority_anchor(connection)?;
    }
    Ok(published)
}

fn publish_pending(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<usize, AdmissionOperationStoreError> {
    let present: bool = tx
        .query_row(
            "SELECT COUNT(*) = 3 FROM sqlite_schema
             WHERE name IN ('security_participant_state_initializations',
                            'security_participant_state_imported_scope_index',
                            'admission_operation_recovery_records')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !present {
        return Ok(0);
    }
    if schema::recorded_version(tx)? != schema::CURRENT_VERSION {
        return Err(invalid(
            "imported influence publication requires the current catalog",
        ));
    }
    // This bounded enumeration verifies every sealed imported source inside
    // this transaction. The exact metadata read also checks the original
    // initialization's global reference before the new root is published.
    let bindings = records::initialized_authority_bindings(tx)?;
    let mut published = 0;
    for binding in bindings {
        let initialization = records::load_current_metadata(tx, &binding)?;
        if historical_root_pending(tx, &initialization)? {
            install_imported_scope_index(tx, owner, &initialization)?;
            published += 1;
        }
    }
    Ok(published)
}
