//! Exact predecessor recovery catalogs cannot carry successor-only authority.
use super::*;

/// Successor indexes never participate in an exact predecessor catalog.
pub(super) const SQL: &str = include_str!("../../recovery_origin_presence.sql");

const SUCCESSOR_RECORD_PREFIXES: &[&str] = &[
    "recovery-workflow-capacity:*",
    "recovery-workflow-allocation:*",
    "knowledge-influence:*",
    "knowledge-influence-ready:*",
    "knowledge-influence-head:*",
    "knowledge-label-repair:*",
    "knowledge-influence-hold:*",
    "knowledge-reference:*",
    "knowledge-reference-owner:*",
    "knowledge-reference-ready:*",
    "knowledge-object-custody:*",
    "knowledge-object-owner:*",
    "knowledge-checkpoint-head:*",
    "knowledge-checkpoint-retired:*",
    "knowledge-checkpoint:v2:*",
    "knowledge-publication:v2:*",
    "knowledge-release:v2:*",
    "knowledge-restore:v2:*",
    "knowledge-pin:v2:*",
    "protected-setup-retired:*",
    "protected-setup:v2:*",
    "protected-setup-context:*",
    "protected-setup-tenant:*",
    "product-disposition:*",
];

pub(super) fn verify_predecessor(
    tx: &Connection,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(version, 35 | 36) {
        return Ok(());
    }
    verify_admission_operation_schema(tx, version)?;
    verify_admission_operation_inventory(tx)?;
    if version == 35 {
        let future: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'deployment-history:*' OR record_key GLOB 'workflow-quota:*'
                    OR (kind='workflow' AND (json_type(payload,'$.captured_deployment') IS NOT NULL
                         OR json_type(payload,'$.historical_hold') IS NOT NULL)))",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "predecessor recovery schema contains future custody",
            ));
        }
    }
    for prefix in SUCCESSOR_RECORD_PREFIXES {
        let future: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB ?1)",
                [prefix],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "predecessor recovery schema contains successor authority",
            ));
        }
    }
    let future: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records r
             WHERE (r.record_key GLOB 'workflow-quota:*' AND json_type(r.payload,'$.native_hold') IS NOT NULL)
                OR (r.kind='deployment' AND json_type(r.payload,'$.setup_policy') IS NOT NULL)
                OR (r.record_key GLOB 'knowledge-restore:*' AND (
                    json_type(r.payload,'$.actor_binding') IS NOT NULL OR
                    json_type(r.payload,'$.installation_generation') IS NOT NULL))
                OR (r.kind='deployment' AND EXISTS(
                    SELECT 1 FROM json_each(r.payload,'$.actors') actor,
                         json_each(actor.value,'$.permissions') permission
                    WHERE permission.value='inspect_explanation_graph')))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "predecessor recovery schema contains successor members",
        ));
    }
    Ok(())
}
