//! Exact local-event references for the global authority commit chain.

use super::*;

pub(super) fn projection_reference_digest(
    connection: &Connection,
    kind: &str,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    match kind {
        "native_dispatch_ledger" => {
            crate::admission_operation_store::native_dispatch_ledger_projection_reference(
                connection, key, sequence,
            )
        }
        "security_participant_nonce_preflight" => {
            crate::admission_operation_store::security_participant_nonce_preflight_projection_reference(
                connection, key, sequence,
            )
        }
        "security_participant_output" => {
            crate::admission_operation_store::security_participant_output_projection_reference(
                connection, key, sequence,
            )
        }
        "security_participant_egress" => {
            crate::admission_operation_store::security_participant_egress_projection_reference(
                connection, key, sequence,
            )
        }
        "security_participant_state" => {
            crate::admission_operation_store::security_participant_state_projection_reference(
                connection, key, sequence,
            )
        }
        "security_participant_migration" => {
            crate::admission_operation_store::security_participant_projection_reference(
                connection, key, sequence,
            )
        }
        "dpop_replay_migration" => {
            crate::admission_operation_store::dpop_replay_projection_reference(
                connection, key, sequence,
            )
        }
        "governed_approval_replay_migration" => {
            crate::admission_operation_store::governed_approval_replay_projection_reference(
                connection, key, sequence,
            )
        }
        "runtime_replay_migration" => {
            crate::admission_operation_store::runtime_replay_projection_reference(
                connection, key, sequence,
            )
        }
        "admission" => connection
            .query_row(
                r#"
                SELECT chain_digest FROM admission_operation_commits
                WHERE commit_sequence = ?1 AND operation_id = ?2
                "#,
                params![sqlite_u64(sequence, "admission commit sequence")?, key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("admission projection reference is absent")),
        "budget" => budget_event_reference_digest(connection, key, sequence),
        "payment" => payment_journal_reference_digest(connection, key, sequence),
        "revocation" => revocation_reference_digest(connection, key, sequence),
        "frost" => connection
            .query_row(
                r#"
                SELECT chain_digest FROM frost_projection_commits
                WHERE projection_key = ?1 AND projection_sequence = ?2
                "#,
                params![key, sqlite_u64(sequence, "FROST projection sequence")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("FROST projection reference is absent")),
        "economic" => connection
            .query_row(
                r#"
                SELECT commit_digest FROM economic_state_stage_commits
                WHERE batch_id = ?1 AND stage_version = ?2
                "#,
                params![key, sqlite_u64(sequence, "economic stage version")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("economic projection reference is absent")),
        "channel_release_publication" => {
            channel_release_projection_reference_digest(connection, key, sequence)
        }
        "factor_assignment_authority_set" => {
            factor_assignment_authority_set_reference_digest(connection, key, sequence)
        }
        "fiscal" => connection
            .query_row(
                r#"
                SELECT commit_digest FROM fiscal_projection_commits
                WHERE projection_key = ?1 AND projection_sequence = ?2
                "#,
                params![key, sqlite_u64(sequence, "fiscal projection sequence")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("fiscal projection reference is absent")),
        "finding_challenge" => {
            if key != "market" {
                return Err(invalid("finding challenge projection key is invalid"));
            }
            connection
                .query_row(
                    r#"
                    SELECT commit_digest FROM finding_challenge_projection_commits
                    WHERE projection_sequence = ?1
                    "#,
                    [sqlite_u64(
                        sequence,
                        "finding challenge projection sequence",
                    )?],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| invalid("finding challenge projection reference is absent"))
        }
        "finding_status" => {
            if key != "status" {
                return Err(invalid("finding status projection key is invalid"));
            }
            connection
                .query_row(
                    r#"
                    SELECT commit_digest FROM finding_status_projection_commits
                    WHERE projection_sequence = ?1
                    "#,
                    [sqlite_u64(sequence, "finding status projection sequence")?],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| invalid("finding status projection reference is absent"))
        }
        _ => Err(invalid("unknown global authority projection kind")),
    }
}
