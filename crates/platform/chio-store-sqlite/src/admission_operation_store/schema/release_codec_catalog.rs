//! The one supported same-format catalog transition that admits release roots
//! and chunks in the private codec guards and installs the knowledge release
//! lookup index. For the current format it accepts exactly three catalogs:
//! the current catalog with the index (no write), the current codec guards
//! without the index, and the prior codec guards without the index. It
//! replaces only those two guards and creates only that index; no row, event,
//! global commit, initialization or signed byte changes.
use super::*;

/// The exact supported format-44 guard pair before release roots and chunks.
const PRIOR_CODEC_GUARDS: &str = include_str!("release_codec_catalog/prior_codec_guards.sql");
const CODEC_GUARD_SQL: &str = include_str!("../../recovery_knowledge_encoding_atoms.sql");
const RELEASE_INDEX_SQL: &str = include_str!("../../recovery_knowledge_join_release_index.sql");
const RELEASE_INDEX_NAME: &str = "idx_recovery_knowledge_join_release";
const CODEC_GUARDS: [&str; 2] = [
    "admission_operation_recovery_codec_guard_insert",
    "admission_operation_recovery_codec_guard_update",
];

/// A store already on the current catalog returns without writing. Only the
/// exact supported current catalogs transition, inside one IMMEDIATE
/// transaction: the exact A/B catalog is validated first, then its complete
/// inventory is verified unchanged, then only the admitted catalog changes
/// are made (the two codec guards for the prior form, and the release lookup
/// index for both), and the complete current invariants are verified before
/// commit. Any other catalog difference refuses before any mutation.
pub(super) fn complete_supported_transition(
    connection: &mut Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if verify_admission_operation_schema(connection, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
        .is_ok()
    {
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    let actual = admission_operation_schema_catalog(&transaction)?;
    let current_guards = admission_operation_schema_catalog(&current_guards_model()?)?;
    let prior = admission_operation_schema_catalog(&prior_model()?)?;
    if actual != current_guards && actual != prior {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }
    let prior_codec_guards = actual == prior;
    verify_admission_operation_inventory(&transaction)?;
    if prior_codec_guards {
        for guard in CODEC_GUARDS {
            transaction
                .execute_batch(&format!("DROP TRIGGER {guard};"))
                .map_err(sqlite_error)?;
        }
        transaction
            .execute_batch(current_codec_guards()?)
            .map_err(sqlite_error)?;
    }
    transaction
        .execute_batch(RELEASE_INDEX_SQL)
        .map_err(sqlite_error)?;
    verify_admission_operation_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

/// The compiled current catalog with only the release lookup index absent:
/// the exact current-codec-guard supported predecessor (B).
fn current_guards_model() -> Result<Connection, AdmissionOperationStoreError> {
    let model = expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    model
        .execute_batch(&format!("DROP INDEX {RELEASE_INDEX_NAME};"))
        .map_err(sqlite_error)?;
    Ok(model)
}

/// The compiled current catalog with only the release lookup index absent
/// and the two codec guards in their exact prior supported form (A).
fn prior_model() -> Result<Connection, AdmissionOperationStoreError> {
    let model = current_guards_model()?;
    for guard in CODEC_GUARDS {
        model
            .execute_batch(&format!("DROP TRIGGER {guard};"))
            .map_err(sqlite_error)?;
    }
    model
        .execute_batch(PRIOR_CODEC_GUARDS)
        .map_err(sqlite_error)?;
    Ok(model)
}

/// The exact current guard pair from the installed codec catalog source.
fn current_codec_guards() -> Result<&'static str, AdmissionOperationStoreError> {
    let start = CODEC_GUARD_SQL
        .find("CREATE TRIGGER admission_operation_recovery_codec_guard_insert")
        .ok_or_else(|| invariant("codec guard catalog source is incomplete"))?;
    let end = CODEC_GUARD_SQL
        .find("CREATE TRIGGER admission_operation_recovery_encoding_chunk_immutable")
        .filter(|end| *end > start)
        .ok_or_else(|| invariant("codec guard catalog source is incomplete"))?;
    Ok(&CODEC_GUARD_SQL[start..end])
}

#[cfg(all(test, unix))]
mod tests;
