//! Closed flow query catalog. Authority is the first native parameter.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const INSERT_FENCE: WriteQuery = WriteQuery {
    parameters: 10,
    legacy: r#"INSERT INTO security_egress_fences (
                        fence_id, tenant_id, principal_id, lineage_id, session_id,
                        isolation_epoch_id, request_id, request_hash, context_generation, expires_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
    native: r#"INSERT INTO security_participant_state_egress_fences (
                        security_authority_id, fence_id, tenant_id, principal_id, lineage_id, session_id,
                        isolation_epoch_id, request_id, request_hash, context_generation, expires_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
};

pub(in crate::security_state) const COMMIT_FENCE: WriteQuery = WriteQuery {
    parameters: 4,
    legacy: r#"UPDATE security_egress_fences
                SET dispatch_commitment_id = ?2, committed_at = ?3
                WHERE fence_id = ?1 AND tenant_id = ?4
                  AND dispatch_commitment_id IS NULL AND committed_at IS NULL"#,
    native: r#"UPDATE security_participant_state_egress_fences
                SET dispatch_commitment_id = ?3, committed_at = ?4
                WHERE security_authority_id = ?1 AND fence_id = ?2 AND tenant_id = ?5
                  AND dispatch_commitment_id IS NULL AND committed_at IS NULL"#,
};

pub(in crate::security_state) const LOAD_FENCE: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_egress_fences WHERE tenant_id = ?1 AND fence_id = ?2"#,
    native: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_participant_state_egress_fences WHERE security_authority_id = ?1 AND tenant_id = ?2 AND fence_id = ?3"#,
};

pub(in crate::security_state) const LOAD_REQUEST_FENCE: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_egress_fences WHERE tenant_id = ?1 AND request_id = ?2"#,
    native: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_participant_state_egress_fences WHERE security_authority_id = ?1 AND tenant_id = ?2 AND request_id = ?3"#,
};

pub(in crate::security_state) const ALL_FENCES: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_egress_fences"#,
    native: r#"SELECT fence_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, request_id, request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at FROM security_participant_state_egress_fences WHERE security_authority_id = ?1"#,
};
