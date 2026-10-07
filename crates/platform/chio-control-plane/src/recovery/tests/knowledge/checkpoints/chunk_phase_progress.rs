//! Test-only numeric progress at an already failed real chunk fixture phase.
//! This child is registered only under the private checkpoint test module.
use super::*;

pub(super) fn checkpoint_chunk_failure_progress(f: &KnowledgeFixture) -> serde_json::Value {
    let authority = match f.actor(RecoveryPermission::KnowledgeRead) {
        Ok(actor) => serde_json::json!({
            "accepted": actor.permission() == RecoveryPermission::KnowledgeRead,
            "error_class": null,
        }),
        Err(error) => serde_json::json!({
            "accepted": false,
            "error_class": checkpoint_chunk_test_error_class(error.as_ref()),
        }),
    };
    let native = match now_ms() {
        Err(_) => serde_json::json!({
            "readable": false,
            "snapshot_present": null,
            "stored_generation_present": null,
            "label_bytes": null,
            "label_top": null,
            "error_class": "diagnostic_clock_unavailable",
        }),
        Ok(now) => match f
            .f
            .authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now,
            ) {
            Ok(observation) => {
                let labels = observation.snapshot().map(|snapshot| {
                    [
                        &snapshot.principal_label,
                        &snapshot.lineage_label,
                        &snapshot.session_label,
                    ]
                });
                let bytes = labels.map(|labels| {
                    labels.map(|label| {
                        chio_core_types::canonical_json_bytes(label)
                            .ok()
                            .map(|bytes| bytes.len())
                    })
                });
                let top =
                    labels.map(|labels| labels.map(|label| matches!(label, InformationLabel::Top)));
                serde_json::json!({
                    "readable": true,
                    "snapshot_present": observation.snapshot().is_some(),
                    "stored_generation_present": observation.stored_context_generation().is_some(),
                    "label_bytes": bytes,
                    "label_top": top,
                    "error_class": null,
                })
            }
            Err(error) => serde_json::json!({
                "readable": false,
                "snapshot_present": null,
                "stored_generation_present": null,
                "label_bytes": null,
                "label_top": null,
                "error_class": checkpoint_chunk_test_error_class(&error),
            }),
        },
    };
    // READ_ONLY prevents this diagnostic from creating a database during a
    // reopen failure. These aggregate numbers supply no row/source authority.
    let database = match rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Err(_) => database_failure("diagnostic_database_open"),
        Ok(connection) => {
            let counts = connection.query_row(
                "SELECT count(*),
                    coalesce(sum(record_key GLOB 'knowledge-join:*'),0),
                    coalesce(sum(record_key GLOB 'knowledge-restore:*'),0),
                    coalesce(sum(record_key GLOB 'knowledge-encoding-chunk:*'),0),
                    max(CASE WHEN record_key GLOB 'knowledge-join:*' THEN length(payload) END),
                    max(CASE WHEN record_key GLOB 'knowledge-restore:*' THEN length(payload) END),
                    max(CASE WHEN record_key GLOB 'knowledge-encoding-chunk:*' THEN length(payload) END),
                    (SELECT count(*) FROM admission_operation_recovery_events),
                    (SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1)
                 FROM admission_operation_recovery_records",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?, row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?, row.get::<_, i64>(8)?,
                )),
            );
            match counts {
                Err(_) => database_failure("diagnostic_database_counts"),
                Ok((
                    records,
                    journals,
                    restores,
                    chunks,
                    journal_bytes,
                    restore_bytes,
                    chunk_bytes,
                    events,
                    global,
                )) => {
                    serde_json::json!({
                        "readable": true,
                        "records": records,
                        "journals": journals,
                        "restores": restores,
                        "chunks": chunks,
                        "maximum_journal_payload_bytes": journal_bytes,
                        "maximum_restore_payload_bytes": restore_bytes,
                        "maximum_chunk_payload_bytes": chunk_bytes,
                        "retained_events": events,
                        "global_sequence": global,
                        "error_class": null,
                    })
                }
            }
        }
    };
    serde_json::json!({
        "current_read_authority": authority,
        "native": native,
        "database": database,
    })
}

fn database_failure(error_class: &'static str) -> serde_json::Value {
    serde_json::json!({
        "readable": false,
        "records": null,
        "journals": null,
        "restores": null,
        "chunks": null,
        "maximum_journal_payload_bytes": null,
        "maximum_restore_payload_bytes": null,
        "maximum_chunk_payload_bytes": null,
        "retained_events": null,
        "global_sequence": null,
        "error_class": error_class,
    })
}
