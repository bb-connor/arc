//! Explicit authority-scoped declassification uses queries.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const STATUS: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_declassification_lifecycle WHERE singleton = 1"#,
    native: r#"SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_participant_state_declassification_lifecycle WHERE security_authority_id = ?1 AND singleton = 1"#,
};

pub(in crate::security_state) const HAS_TOMBSTONE: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT EXISTS (
                    SELECT 1
                    FROM security_declassification_tombstones
                    WHERE tenant_id = ?1 AND grant_id = ?2
                )"#,
    native: r#"SELECT EXISTS (
                    SELECT 1
                    FROM security_participant_state_declassification_tombstones
                    WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3
                )"#,
};

pub(in crate::security_state) const INSERT_USE: WriteQuery = WriteQuery {
    parameters: 7,
    legacy: r#"INSERT INTO security_declassification_uses (
                            grant_id, tenant_id, request_hash, state, consumed_at,
                            grant_expires_at, retain_until, consumption_binding
                        ) VALUES (
                            ?1, ?2, ?3, 'consumed_pending_dispatch', ?4, ?5, ?6, ?7
                        )"#,
    native: r#"INSERT INTO security_participant_state_declassification_uses (
                            security_authority_id, grant_id, tenant_id, request_hash, state, consumed_at,
                            grant_expires_at, retain_until, consumption_binding
                        ) VALUES (?1, ?2, ?3, ?4, 'consumed_pending_dispatch', ?5, ?6, ?7, ?8
                        )"#,
};

pub(in crate::security_state) const UPDATE_OUTCOME: WriteQuery = WriteQuery {
    parameters: 6,
    legacy: r#"UPDATE security_declassification_uses
                SET state = ?4, transition_id = ?5, outcome_binding = ?6
                WHERE grant_id = ?1 AND tenant_id = ?2 AND request_hash = ?3
                  AND state = 'consumed_pending_dispatch' AND transition_id IS NULL"#,
    native: r#"UPDATE security_participant_state_declassification_uses
                SET state = ?5, transition_id = ?6, outcome_binding = ?7
                WHERE security_authority_id = ?1 AND grant_id = ?2 AND tenant_id = ?3 AND request_hash = ?4
                  AND state = 'consumed_pending_dispatch' AND transition_id IS NULL"#,
};
