//! Explicit authority-scoped declassification records queries.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const MATCHING_IDENTITY: ReadQuery = ReadQuery {
    parameters: 6,
    legacy: "SELECT EXISTS(SELECT 1 FROM security_declassification_evidence_identity
             WHERE tenant_id = ?1 AND evidence_id = ?2 AND transition_id = ?3
               AND grant_id = ?4 AND phase = ?5 AND body_hash = ?6)",
    native:
        "SELECT EXISTS(SELECT 1 FROM security_participant_state_declassification_evidence_identity
             WHERE security_authority_id = ?1 AND tenant_id = ?2 AND evidence_id = ?3
               AND transition_id = ?4 AND grant_id = ?5 AND phase = ?6 AND body_hash = ?7)",
};

pub(in crate::security_state) const LOAD_USE: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT tenant_id, grant_id, request_hash, state, consumed_at,
                   grant_expires_at, retain_until, consumption_binding, outcome_binding
            FROM security_declassification_uses
            WHERE tenant_id = ?1 AND grant_id = ?2"#,
    native: r#"SELECT tenant_id, grant_id, request_hash, state, consumed_at,
                   grant_expires_at, retain_until, consumption_binding, outcome_binding
            FROM security_participant_state_declassification_uses
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3"#,
};

pub(in crate::security_state) const LOAD_EVIDENCE: ReadQuery = ReadQuery {
    parameters: 3,
    legacy: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code FROM security_declassification_receipt_outbox WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3"#,
    native: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3 AND phase_ordinal = ?4"#,
};

pub(in crate::security_state) const PENDING_GRANT: ReadQuery = ReadQuery {
    parameters: 4,
    legacy: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code
    FROM security_declassification_receipt_outbox
    WHERE acknowledged = 0
      AND next_attempt_at <= ?3
      AND tenant_id = ?1 AND grant_id = ?2
    ORDER BY next_attempt_at ASC, phase_ordinal ASC
    LIMIT ?4"#,
    native: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code
    FROM security_participant_state_declassification_receipt_outbox
    WHERE security_authority_id = ?1
      AND acknowledged = 0
      AND next_attempt_at <= ?4
      AND tenant_id = ?2 AND grant_id = ?3
    ORDER BY next_attempt_at ASC, phase_ordinal ASC
    LIMIT ?5"#,
};

pub(in crate::security_state) const PENDING_BATCH: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code
    FROM security_declassification_receipt_outbox
    WHERE acknowledged = 0
      AND next_attempt_at <= ?1
      AND (phase = 'consumption' OR EXISTS (
          SELECT 1 FROM security_declassification_receipt_outbox AS predecessor
          WHERE predecessor.tenant_id = security_declassification_receipt_outbox.tenant_id
            AND predecessor.grant_id = security_declassification_receipt_outbox.grant_id
            AND predecessor.phase = 'consumption'
            AND predecessor.acknowledged = 1
      ))
    ORDER BY ROW_NUMBER() OVER (
        PARTITION BY tenant_id
        ORDER BY next_attempt_at ASC, grant_id ASC, phase_ordinal ASC
    ) ASC, next_attempt_at ASC, tenant_id ASC, grant_id ASC, phase_ordinal ASC
    LIMIT ?2"#,
    native: r#"SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code
    FROM security_participant_state_declassification_receipt_outbox
    WHERE security_authority_id = ?1
      AND acknowledged = 0
      AND next_attempt_at <= ?2
      AND (phase = 'consumption' OR EXISTS (
          SELECT 1 FROM security_participant_state_declassification_receipt_outbox AS predecessor
          WHERE predecessor.security_authority_id = security_participant_state_declassification_receipt_outbox.security_authority_id
            AND predecessor.tenant_id = security_participant_state_declassification_receipt_outbox.tenant_id
            AND predecessor.grant_id = security_participant_state_declassification_receipt_outbox.grant_id
            AND predecessor.phase = 'consumption'
            AND predecessor.acknowledged = 1
      ))
    ORDER BY ROW_NUMBER() OVER (
        PARTITION BY tenant_id
        ORDER BY next_attempt_at ASC, grant_id ASC, phase_ordinal ASC
    ) ASC, next_attempt_at ASC, tenant_id ASC, grant_id ASC, phase_ordinal ASC
    LIMIT ?3"#,
};

pub(in crate::security_state) const INSERT_IDENTITY: WriteQuery = WriteQuery {
    parameters: 6,
    legacy: r#"INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
    native: r#"INSERT INTO security_participant_state_declassification_evidence_identity (
                security_authority_id, evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
};

pub(in crate::security_state) const INSERT_EVIDENCE: WriteQuery = WriteQuery {
    parameters: 14,
    legacy: r#"INSERT INTO security_declassification_receipt_outbox (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
                transition_id, occurred_at, predecessor_evidence_id, acknowledged,
                acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
                last_error_code
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, 0, NULL, NULL, 0, ?13, NULL
            )"#,
    native: r#"INSERT INTO security_participant_state_declassification_receipt_outbox (
                security_authority_id, tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
                transition_id, occurred_at, predecessor_evidence_id, acknowledged,
                acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
                last_error_code
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, 0, NULL, NULL, 0, ?14, NULL
            )"#,
};

pub(in crate::security_state) const LOAD_USE_TRANSITION: ReadQuery = ReadQuery {
    parameters: 2,
    legacy: r#"SELECT transition_id
            FROM security_declassification_uses
            WHERE tenant_id = ?1 AND grant_id = ?2"#,
    native: r#"SELECT transition_id
            FROM security_participant_state_declassification_uses
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3"#,
};
