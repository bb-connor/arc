//! Explicit authority-scoped declassification compaction queries.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const CANDIDATES_AFTER: ReadQuery = ReadQuery {
    parameters: 4,
    legacy: r#"SELECT tenant_id, grant_id
                        FROM security_declassification_uses
                        WHERE state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?1
                          AND (tenant_id > ?2 OR (tenant_id = ?2 AND grant_id > ?3))
                        ORDER BY tenant_id, grant_id LIMIT ?4"#,
    native: r#"SELECT tenant_id, grant_id
                        FROM security_participant_state_declassification_uses
                        WHERE security_authority_id = ?1 AND state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?2
                          AND (tenant_id > ?3 OR (tenant_id = ?3 AND grant_id > ?4))
                        ORDER BY tenant_id, grant_id LIMIT ?5"#,
};

pub(in crate::security_state) const CANDIDATES_FIRST: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT tenant_id, grant_id
                        FROM security_declassification_uses
                        WHERE state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?1
                        ORDER BY tenant_id, grant_id LIMIT ?2"#,
    native: r#"SELECT tenant_id, grant_id
                        FROM security_participant_state_declassification_uses
                        WHERE security_authority_id = ?1 AND state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?2
                        ORDER BY tenant_id, grant_id LIMIT ?3"#,
};

pub(in crate::security_state) const BEGIN_COMPACTION: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET compaction_active = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 0"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET compaction_active = 1
                WHERE security_authority_id = ?1 AND singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 0"#,
};

pub(in crate::security_state) const INSERT_TOMBSTONE: WriteQuery = WriteQuery {
    parameters: 16,
    legacy: r#"INSERT INTO security_declassification_tombstones (
                    tenant_id, grant_id, request_hash, terminal_state,
                    consumption_evidence_id, consumption_body_hash,
                    consumption_transition_id, consumption_occurred_at,
                    consumption_sink_record_hash, outcome_evidence_id,
                    outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                    outcome_sink_record_hash, policy_hash, compacted_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16
                )"#,
    native: r#"INSERT INTO security_participant_state_declassification_tombstones (
                    security_authority_id, tenant_id, grant_id, request_hash, terminal_state,
                    consumption_evidence_id, consumption_body_hash,
                    consumption_transition_id, consumption_occurred_at,
                    consumption_sink_record_hash, outcome_evidence_id,
                    outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                    outcome_sink_record_hash, policy_hash, compacted_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16, ?17
                )"#,
};

pub(in crate::security_state) const DELETE_EVIDENCE: WriteQuery = WriteQuery {
    parameters: 2,
    legacy: r#"DELETE FROM security_declassification_receipt_outbox WHERE tenant_id = ?1 AND grant_id = ?2"#,
    native: r#"DELETE FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3"#,
};

pub(in crate::security_state) const DELETE_USE: WriteQuery = WriteQuery {
    parameters: 2,
    legacy: r#"DELETE FROM security_declassification_uses WHERE tenant_id = ?1 AND grant_id = ?2"#,
    native: r#"DELETE FROM security_participant_state_declassification_uses WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3"#,
};

pub(in crate::security_state) const END_COMPACTION: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET compaction_active = 0
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 1"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET compaction_active = 0
                WHERE security_authority_id = ?1 AND singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 1"#,
};
