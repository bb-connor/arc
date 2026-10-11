//! Closed flow query catalog. Authority is the first native parameter.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const HAS_EPOCH: ReadQuery = ReadQuery {
    parameters: 4,
    legacy: r#"SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )"#,
    native: r#"SELECT EXISTS(
                SELECT 1 FROM security_participant_state_isolation_epochs
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND lineage_id = ?4
                  AND isolation_epoch_id = ?5
            )"#,
};

pub(in crate::security_state) const HAS_PRINCIPAL_EPOCH: ReadQuery = ReadQuery {
    parameters: 3,
    legacy: r#"SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            )"#,
    native: r#"SELECT EXISTS(
                SELECT 1 FROM security_participant_state_isolation_epochs
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND isolation_epoch_id = ?4
            )"#,
};

pub(in crate::security_state) const COPY_EPOCH: WriteQuery = WriteQuery {
    parameters: 5,
    legacy: r#"INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                )
                SELECT tenant_id, principal_id, ?3, isolation_epoch_id,
                       previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                       evidence_receipt_ref, ?5, effective_at
                FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?4
                ORDER BY lineage_id
                LIMIT 1"#,
    native: r#"INSERT INTO security_participant_state_isolation_epochs (
                    security_authority_id, tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                )
                SELECT ?1, tenant_id, principal_id, ?4, isolation_epoch_id,
                       previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                       evidence_receipt_ref, ?6, effective_at
                FROM security_participant_state_isolation_epochs
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3 AND isolation_epoch_id = ?5
                ORDER BY lineage_id
                LIMIT 1"#,
};

pub(in crate::security_state) const COUNT_PRIOR_EPOCHS: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT COUNT(*) FROM security_isolation_epochs WHERE tenant_id = ?1 AND principal_id = ?2"#,
    native: r#"SELECT COUNT(*) FROM security_participant_state_isolation_epochs WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3"#,
};

pub(in crate::security_state) const INSERT_GENESIS: WriteQuery = WriteQuery {
    parameters: 5,
    legacy: r#"INSERT INTO security_isolation_epochs (
                tenant_id, principal_id, lineage_id, isolation_epoch_id,
                previous_isolation_epoch_id, evidence_hash, transition_id, effective_at
            ) VALUES (?1, ?2, ?3, ?4, NULL, zeroblob(32), ?5, 0)"#,
    native: r#"INSERT INTO security_participant_state_isolation_epochs (
                security_authority_id, tenant_id, principal_id, lineage_id, isolation_epoch_id,
                previous_isolation_epoch_id, evidence_hash, transition_id, effective_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, zeroblob(32), ?6, 0)"#,
};

pub(in crate::security_state) const INSERT_EPOCH: WriteQuery = WriteQuery {
    parameters: 10,
    legacy: r#"INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
    native: r#"INSERT INTO security_participant_state_isolation_epochs (
                    security_authority_id, tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
};
