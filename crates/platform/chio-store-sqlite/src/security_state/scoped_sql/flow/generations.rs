//! Closed flow query catalog. Authority is the first native parameter.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const LOAD_SEQUENCE: ReadQuery = ReadQuery {
    parameters: 1,
    legacy: r#"SELECT last_generation FROM security_flow_sequences WHERE tenant_id = ?1"#,
    native: r#"SELECT last_generation FROM security_participant_state_flow_sequences WHERE security_authority_id = ?1 AND tenant_id = ?2"#,
};

pub(in crate::security_state) const MAX_GENERATION: ReadQuery = ReadQuery {
    parameters: 1,
    legacy: r#"SELECT MAX(generation) FROM (
                SELECT generation FROM security_principal_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_lineage_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_session_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_flow_contexts WHERE tenant_id = ?1
            )"#,
    native: r#"SELECT MAX(generation) FROM (
                SELECT generation FROM security_participant_state_principal_flow_state WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM security_participant_state_lineage_flow_state WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM security_participant_state_session_flow_state WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM security_participant_state_flow_contexts WHERE security_authority_id = ?1 AND tenant_id = ?2
            )"#,
};

pub(in crate::security_state) const STORE_SEQUENCE: WriteQuery = WriteQuery {
    parameters: 2,
    legacy: r#"INSERT INTO security_flow_sequences (tenant_id, last_generation)
            VALUES (?1, ?2)
            ON CONFLICT (tenant_id) DO UPDATE SET last_generation = excluded.last_generation"#,
    native: r#"INSERT INTO security_participant_state_flow_sequences (security_authority_id, tenant_id, last_generation)
            VALUES (?1, ?2, ?3)
            ON CONFLICT (security_authority_id, tenant_id) DO UPDATE SET last_generation = excluded.last_generation"#,
};

pub(in crate::security_state) const INVALIDATE_PRINCIPAL: WriteQuery = WriteQuery {
    parameters: 4,
    legacy: r#"UPDATE security_flow_contexts SET generation = ?4
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3"#,
    native: r#"UPDATE security_participant_state_flow_contexts SET generation = ?5
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND isolation_epoch_id = ?4"#,
};

pub(in crate::security_state) const INVALIDATE_LINEAGE: WriteQuery = WriteQuery {
    parameters: 3,
    legacy: r#"UPDATE security_flow_contexts SET generation = ?3
                WHERE tenant_id = ?1 AND lineage_id = ?2"#,
    native: r#"UPDATE security_participant_state_flow_contexts SET generation = ?4
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND lineage_id = ?3"#,
};

pub(in crate::security_state) const INVALIDATE_SESSION: WriteQuery = WriteQuery {
    parameters: 5,
    legacy: r#"UPDATE security_flow_contexts SET generation = ?5
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4"#,
    native: r#"UPDATE security_participant_state_flow_contexts SET generation = ?6
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
                  AND session_id = ?4 AND isolation_epoch_id = ?5"#,
};

pub(in crate::security_state) const STORE_CONTEXT: WriteQuery = WriteQuery {
    parameters: 6,
    legacy: r#"INSERT INTO security_flow_contexts (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
            )
            DO UPDATE SET generation = excluded.generation"#,
    native: r#"INSERT INTO security_participant_state_flow_contexts (
                security_authority_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (security_authority_id, tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
            )
            DO UPDATE SET generation = excluded.generation"#,
};
