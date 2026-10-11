//! Closed flow query catalog. Authority is the first native parameter.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const LOAD_TRANSITION: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT tenant_id, transition_kind, request_hash FROM security_transitions WHERE tenant_id = ?1 AND transition_id = ?2"#,
    native: r#"SELECT tenant_id, transition_kind, request_hash FROM security_participant_state_transitions WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3"#,
};

pub(in crate::security_state) const INSERT_TRANSITION: WriteQuery = WriteQuery {
    parameters: 4,
    legacy: r#"INSERT INTO security_transitions (transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4)"#,
    native: r#"INSERT INTO security_participant_state_transitions (security_authority_id, transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4, ?5)"#,
};
