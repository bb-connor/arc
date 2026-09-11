//! Explicit authority-scoped declassification outbox queries.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const STRANDED_BATCH: ReadQuery = ReadQuery {
    parameters: 1,
    legacy: r#"SELECT
                    evidence.tenant_id, evidence.grant_id, evidence.phase,
                    evidence.phase_ordinal, evidence.request_hash, evidence.state,
                    evidence.transition_binding, evidence.evidence_type,
                    evidence.evidence_id, evidence.canonical_body, evidence.body_hash,
                    evidence.transition_id, evidence.occurred_at,
                    evidence.predecessor_evidence_id, evidence.acknowledged,
                    evidence.acknowledged_at, evidence.durable_sink_record_hash,
                    evidence.attempts,
                    evidence.next_attempt_at, evidence.last_error_code
                FROM security_declassification_receipt_outbox AS evidence
                INNER JOIN security_declassification_uses AS use_record
                    ON use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_declassification_receipt_outbox AS outcome
                      WHERE outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )
                ORDER BY evidence.tenant_id ASC, evidence.grant_id ASC
                LIMIT ?1"#,
    native: r#"SELECT
                    evidence.tenant_id, evidence.grant_id, evidence.phase,
                    evidence.phase_ordinal, evidence.request_hash, evidence.state,
                    evidence.transition_binding, evidence.evidence_type,
                    evidence.evidence_id, evidence.canonical_body, evidence.body_hash,
                    evidence.transition_id, evidence.occurred_at,
                    evidence.predecessor_evidence_id, evidence.acknowledged,
                    evidence.acknowledged_at, evidence.durable_sink_record_hash,
                    evidence.attempts,
                    evidence.next_attempt_at, evidence.last_error_code
                FROM security_participant_state_declassification_receipt_outbox AS evidence
                INNER JOIN security_participant_state_declassification_uses AS use_record
                    ON use_record.security_authority_id = evidence.security_authority_id AND use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.security_authority_id = ?1 AND evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_participant_state_declassification_receipt_outbox AS outcome
                      WHERE outcome.security_authority_id = evidence.security_authority_id AND outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )
                ORDER BY evidence.tenant_id ASC, evidence.grant_id ASC
                LIMIT ?2"#,
};

pub(in crate::security_state) const ACK_EVIDENCE: WriteQuery = WriteQuery {
    parameters: 8,
    legacy: r#"UPDATE security_declassification_receipt_outbox
                SET acknowledged = 1, acknowledged_at = ?7,
                    durable_sink_record_hash = ?8
                WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3
                  AND evidence_id = ?4 AND body_hash = ?5 AND transition_id = ?6
                  AND acknowledged = 0"#,
    native: r#"UPDATE security_participant_state_declassification_receipt_outbox
                SET acknowledged = 1, acknowledged_at = ?8,
                    durable_sink_record_hash = ?9
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3 AND phase_ordinal = ?4
                  AND evidence_id = ?5 AND body_hash = ?6 AND transition_id = ?7
                  AND acknowledged = 0"#,
};

pub(in crate::security_state) const RETRY_EVIDENCE: WriteQuery = WriteQuery {
    parameters: 10,
    legacy: r#"UPDATE security_declassification_receipt_outbox
                SET attempts = ?7, next_attempt_at = ?8, last_error_code = ?9
                WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3
                  AND evidence_id = ?4 AND body_hash = ?5 AND transition_id = ?6
                  AND acknowledged = 0 AND attempts = ?10"#,
    native: r#"UPDATE security_participant_state_declassification_receipt_outbox
                SET attempts = ?8, next_attempt_at = ?9, last_error_code = ?10
                WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3 AND phase_ordinal = ?4
                  AND evidence_id = ?5 AND body_hash = ?6 AND transition_id = ?7
                  AND acknowledged = 0 AND attempts = ?11"#,
};

pub(in crate::security_state) const COUNT_PENDING: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*) FROM security_declassification_receipt_outbox WHERE acknowledged = 0"#,
    native: r#"SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1 AND acknowledged = 0"#,
};

pub(in crate::security_state) const COUNT_STRANDED: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*)
                FROM security_declassification_receipt_outbox AS evidence
                INNER JOIN security_declassification_uses AS use_record
                    ON use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_declassification_receipt_outbox AS outcome
                      WHERE outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )"#,
    native: r#"SELECT COUNT(*)
                FROM security_participant_state_declassification_receipt_outbox AS evidence
                INNER JOIN security_participant_state_declassification_uses AS use_record
                    ON use_record.security_authority_id = evidence.security_authority_id AND use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.security_authority_id = ?1 AND evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_participant_state_declassification_receipt_outbox AS outcome
                      WHERE outcome.security_authority_id = evidence.security_authority_id AND outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )"#,
};
