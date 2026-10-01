//! Explicit authority-scoped declassification integrity queries.

use super::super::ReadQuery;

pub(in crate::security_state) const ALL_USES: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT tenant_id, grant_id FROM security_declassification_uses ORDER BY tenant_id, grant_id"#,
    native: r#"SELECT tenant_id, grant_id FROM security_participant_state_declassification_uses WHERE security_authority_id = ?1 ORDER BY tenant_id, grant_id"#,
};

pub(in crate::security_state) const COUNT_EVIDENCE: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*) FROM security_declassification_receipt_outbox"#,
    native: r#"SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1"#,
};

pub(in crate::security_state) const MISMATCHED_IDENTITY: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*)
            FROM security_declassification_receipt_outbox AS evidence
            LEFT JOIN security_declassification_evidence_identity AS identity_record
              ON identity_record.tenant_id = evidence.tenant_id
             AND identity_record.evidence_id = evidence.evidence_id
            WHERE identity_record.evidence_id IS NULL
               OR identity_record.transition_id != evidence.transition_id
               OR identity_record.tenant_id != evidence.tenant_id
               OR identity_record.grant_id != evidence.grant_id
               OR identity_record.phase != evidence.phase
               OR identity_record.body_hash != evidence.body_hash"#,
    native: r#"SELECT COUNT(*)
            FROM security_participant_state_declassification_receipt_outbox AS evidence
            LEFT JOIN security_participant_state_declassification_evidence_identity AS identity_record
              ON identity_record.security_authority_id = evidence.security_authority_id AND identity_record.tenant_id = evidence.tenant_id
             AND identity_record.evidence_id = evidence.evidence_id
            WHERE evidence.security_authority_id = ?1 AND (identity_record.evidence_id IS NULL
               OR identity_record.transition_id != evidence.transition_id
               OR identity_record.tenant_id != evidence.tenant_id
               OR identity_record.grant_id != evidence.grant_id
               OR identity_record.phase != evidence.phase
               OR identity_record.body_hash != evidence.body_hash)"#,
};

pub(in crate::security_state) const COUNT_TOMBSTONES: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*) FROM security_declassification_tombstones"#,
    native: r#"SELECT COUNT(*) FROM security_participant_state_declassification_tombstones WHERE security_authority_id = ?1"#,
};

pub(in crate::security_state) const LIVE_TOMBSTONE: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*)
            FROM security_declassification_uses AS use_record
            INNER JOIN security_declassification_tombstones AS tombstone
              ON tombstone.tenant_id = use_record.tenant_id
             AND tombstone.grant_id = use_record.grant_id"#,
    native: r#"SELECT COUNT(*)
            FROM security_participant_state_declassification_uses AS use_record
            INNER JOIN security_participant_state_declassification_tombstones AS tombstone
              ON tombstone.security_authority_id = use_record.security_authority_id AND tombstone.tenant_id = use_record.tenant_id
             AND tombstone.grant_id = use_record.grant_id WHERE use_record.security_authority_id = ?1"#,
};

pub(in crate::security_state) const INVALID_TOMBSTONE: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*)
            FROM security_declassification_tombstones AS tombstone
            LEFT JOIN security_declassification_evidence_identity AS consumption
              ON consumption.tenant_id = tombstone.tenant_id
             AND consumption.evidence_id = tombstone.consumption_evidence_id
            LEFT JOIN security_declassification_evidence_identity AS outcome
              ON outcome.tenant_id = tombstone.tenant_id
             AND outcome.evidence_id = tombstone.outcome_evidence_id
            WHERE consumption.evidence_id IS NULL
               OR outcome.evidence_id IS NULL
               OR consumption.transition_id != tombstone.consumption_transition_id
               OR consumption.tenant_id != tombstone.tenant_id
               OR consumption.grant_id != tombstone.grant_id
               OR consumption.phase != 'consumption'
               OR consumption.body_hash != tombstone.consumption_body_hash
               OR outcome.transition_id != tombstone.outcome_transition_id
               OR outcome.tenant_id != tombstone.tenant_id
               OR outcome.grant_id != tombstone.grant_id
               OR outcome.phase != 'outcome'
               OR outcome.body_hash != tombstone.outcome_body_hash
               OR tombstone.consumption_occurred_at <= 0
               OR tombstone.outcome_occurred_at < tombstone.consumption_occurred_at
               OR tombstone.policy_hash = zeroblob(32)
               OR tombstone.consumption_sink_record_hash = zeroblob(32)
               OR tombstone.outcome_sink_record_hash = zeroblob(32)"#,
    native: r#"SELECT COUNT(*)
            FROM security_participant_state_declassification_tombstones AS tombstone
            LEFT JOIN security_participant_state_declassification_evidence_identity AS consumption
              ON consumption.security_authority_id = tombstone.security_authority_id AND consumption.tenant_id = tombstone.tenant_id
             AND consumption.evidence_id = tombstone.consumption_evidence_id
            LEFT JOIN security_participant_state_declassification_evidence_identity AS outcome
              ON outcome.security_authority_id = tombstone.security_authority_id AND outcome.tenant_id = tombstone.tenant_id
             AND outcome.evidence_id = tombstone.outcome_evidence_id
            WHERE tombstone.security_authority_id = ?1 AND (consumption.evidence_id IS NULL
               OR outcome.evidence_id IS NULL
               OR consumption.transition_id != tombstone.consumption_transition_id
               OR consumption.tenant_id != tombstone.tenant_id
               OR consumption.grant_id != tombstone.grant_id
               OR consumption.phase != 'consumption'
               OR consumption.body_hash != tombstone.consumption_body_hash
               OR outcome.transition_id != tombstone.outcome_transition_id
               OR outcome.tenant_id != tombstone.tenant_id
               OR outcome.grant_id != tombstone.grant_id
               OR outcome.phase != 'outcome'
               OR outcome.body_hash != tombstone.outcome_body_hash
               OR tombstone.consumption_occurred_at <= 0
               OR tombstone.outcome_occurred_at < tombstone.consumption_occurred_at
               OR tombstone.policy_hash = zeroblob(32)
               OR tombstone.consumption_sink_record_hash = zeroblob(32)
               OR tombstone.outcome_sink_record_hash = zeroblob(32))"#,
};

pub(in crate::security_state) const COUNT_IDENTITIES: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT COUNT(*) FROM security_declassification_evidence_identity"#,
    native: r#"SELECT COUNT(*) FROM security_participant_state_declassification_evidence_identity WHERE security_authority_id = ?1"#,
};
