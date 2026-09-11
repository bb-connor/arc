//! Closed flow query catalog. Authority is the first native parameter.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const STORE_PRINCIPAL: WriteQuery = WriteQuery {
    parameters: 6,
    legacy: r#"INSERT INTO security_principal_flow_state (
                tenant_id, principal_id, isolation_epoch_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (tenant_id, principal_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
    native: r#"INSERT INTO security_participant_state_principal_flow_state (
                security_authority_id, tenant_id, principal_id, isolation_epoch_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (security_authority_id, tenant_id, principal_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
};

pub(in crate::security_state) const STORE_LINEAGE: WriteQuery = WriteQuery {
    parameters: 5,
    legacy: r#"INSERT INTO security_lineage_flow_state (
                tenant_id, lineage_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (tenant_id, lineage_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
    native: r#"INSERT INTO security_participant_state_lineage_flow_state (
                security_authority_id, tenant_id, lineage_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (security_authority_id, tenant_id, lineage_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
};

pub(in crate::security_state) const STORE_MEMBERSHIP: WriteQuery = WriteQuery {
    parameters: 4,
    legacy: r#"INSERT INTO security_session_memberships (
                tenant_id, principal_id, session_id, isolation_epoch_id
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO NOTHING"#,
    native: r#"INSERT INTO security_participant_state_session_memberships (
                security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id) DO NOTHING"#,
};

pub(in crate::security_state) const STORE_SESSION: WriteQuery = WriteQuery {
    parameters: 7,
    legacy: r#"INSERT INTO security_session_flow_state (
                tenant_id, principal_id, session_id, isolation_epoch_id,
                label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
    native: r#"INSERT INTO security_participant_state_session_flow_state (
                security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id,
                label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT (security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation"#,
};

pub(in crate::security_state) const LOAD_PRINCIPAL: ReadQuery = ReadQuery {
    parameters: 3,
    legacy: r#"SELECT label_json, label_hash, generation
            FROM security_principal_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3"#,
    native: r#"SELECT label_json, label_hash, generation
            FROM security_participant_state_principal_flow_state
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND isolation_epoch_id = ?4"#,
};

pub(in crate::security_state) const LOAD_LINEAGE: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT label_json, label_hash, generation
            FROM security_lineage_flow_state
            WHERE tenant_id = ?1 AND lineage_id = ?2"#,
    native: r#"SELECT label_json, label_hash, generation
            FROM security_participant_state_lineage_flow_state
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND lineage_id = ?3"#,
};

pub(in crate::security_state) const LOAD_SESSION: ReadQuery = ReadQuery {
    parameters: 4,
    legacy: r#"SELECT label_json, label_hash, generation
            FROM security_session_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2
              AND session_id = ?3 AND isolation_epoch_id = ?4"#,
    native: r#"SELECT label_json, label_hash, generation
            FROM security_participant_state_session_flow_state
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5"#,
};

pub(in crate::security_state) const LOAD_CONTEXT: ReadQuery = ReadQuery {
    parameters: 5,
    legacy: r#"SELECT generation FROM security_flow_contexts
            WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5"#,
    native: r#"SELECT generation FROM security_participant_state_flow_contexts
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND lineage_id = ?4
              AND session_id = ?5 AND isolation_epoch_id = ?6"#,
};

pub(in crate::security_state) const HAS_MEMBERSHIP: ReadQuery = ReadQuery {
    parameters: 4,
    legacy: r#"SELECT EXISTS(
                SELECT 1 FROM security_session_memberships
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
            )"#,
    native: r#"SELECT EXISTS(
                SELECT 1 FROM security_participant_state_session_memberships
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
                  AND session_id = ?4 AND isolation_epoch_id = ?5
            )"#,
};

pub(in crate::security_state) const ALL_CONTEXTS: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation FROM security_flow_contexts"#,
    native: r#"SELECT tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation FROM security_participant_state_flow_contexts WHERE security_authority_id = ?1"#,
};
