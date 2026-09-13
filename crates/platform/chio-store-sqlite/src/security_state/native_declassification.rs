//! Exact one-shot row images for declassification inside an owned egress commit.
//! These are historical data checks, not permission to enable a SQLite writer.

use super::*;
use chio_security_types::ports::DeclassificationOutcomeRequest;
use rusqlite::types::{Value, ValueRef};
use serde::{Deserialize, Serialize};

pub(super) const TABLES: [&str; 3] = [
    "security_declassification_uses",
    "security_declassification_evidence_identity",
    "security_declassification_receipt_outbox",
];

pub(super) fn consumption_changes(
    request: &DeclassificationConsumptionEvidenceCommit,
) -> PortResult<Vec<NativeRowChange>> {
    validate_declassification_consumption_evidence(request)?;
    let consumption = &request.consumption;
    let receipt = &request.receipt;
    let binding = encode_declassification_binding(&request.transition_binding)?;
    let uses = vec![
        Value::Text(consumption.grant_id.as_str().into()),
        Value::Text(consumption.tenant_id.as_str().into()),
        Value::Blob(consumption.request_hash.as_bytes().to_vec()),
        Value::Text("consumed_pending_dispatch".into()),
        Value::Integer(to_i64(consumption.consumed_at_unix_ms)?),
        Value::Integer(to_i64(consumption.grant_expires_at_unix_ms)?),
        Value::Integer(to_i64(declassification_retain_until_unix_ms(
            consumption.grant_expires_at_unix_ms,
        )?)?),
        Value::Blob(binding.clone()),
        Value::Null,
        Value::Null,
    ];
    let identity = vec![
        Value::Text(receipt.evidence_id.as_str().into()),
        Value::Text(receipt.transition_id.as_str().into()),
        Value::Text(consumption.tenant_id.as_str().into()),
        Value::Text(consumption.grant_id.as_str().into()),
        Value::Text("consumption".into()),
        Value::Blob(receipt.body_hash.as_bytes().to_vec()),
    ];
    let outbox = vec![
        Value::Text(consumption.tenant_id.as_str().into()),
        Value::Text(consumption.grant_id.as_str().into()),
        Value::Text("consumption".into()),
        Value::Integer(0),
        Value::Blob(consumption.request_hash.as_bytes().to_vec()),
        Value::Text("consumed_pending_dispatch".into()),
        Value::Blob(binding),
        Value::Text(receipt.evidence_type.as_str().into()),
        Value::Text(receipt.evidence_id.as_str().into()),
        Value::Blob(receipt.canonical_body.as_bytes().to_vec()),
        Value::Blob(receipt.body_hash.as_bytes().to_vec()),
        Value::Text(receipt.transition_id.as_str().into()),
        Value::Integer(to_i64(receipt.occurred_at_unix_ms)?),
        Value::Null,
        Value::Integer(0),
        Value::Null,
        Value::Null,
        Value::Integer(0),
        Value::Integer(to_i64(receipt.occurred_at_unix_ms)?),
        Value::Null,
    ];
    TABLES
        .into_iter()
        .zip([uses, identity, outbox])
        .map(|(table, values)| {
            let refs = values.iter().map(ValueRef::from).collect::<Vec<_>>();
            let encoded = encode_retained_security_values(table, &refs)
                .map_err(|_| PortError::integrity_failure())?;
            Ok(NativeRowChange {
                table: table.into(),
                before: None,
                after: Some(
                    String::from_utf8(encoded).map_err(|_| PortError::integrity_failure())?,
                ),
            })
        })
        .collect()
}

/// A closed outcome command bound to the exact earlier consumption. This data
/// cannot construct the finalization-owned mutation handle.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeDeclassificationOutcome {
    pub consumption: DeclassificationConsumptionEvidenceCommit,
    pub outcome: DeclassificationOutcomeEvidenceCommit,
}

impl NativeDeclassificationOutcome {
    /// `Released` records that the request reached the connector. It does not
    /// assert that its guarded output was delivered or its receipt published.
    pub(crate) fn released(
        consumption: &DeclassificationConsumptionEvidenceCommit,
        commitment: &CommittedEgressFence,
        now: u64,
    ) -> PortResult<Self> {
        use chio_core::receipt::security::{
            ActiveDefenseReceiptHeader, DeclassificationOutcomeReceiptBody,
        };
        validate_declassification_consumption_evidence(consumption)?;
        let ActiveDefenseReceiptBody::DeclassificationConsumption(prior) =
            decode_declassification_receipt(&consumption.receipt)
                .map_err(|_| PortError::invalid_data())?
        else {
            return Err(PortError::invalid_data());
        };
        let consume = &consumption.consumption;
        if now < consume.consumed_at_unix_ms
            || now < commitment.committed_at_unix_ms
            || commitment.request_hash != consume.request_hash
            || consumption.transition_binding
                != (DeclassificationTransitionBinding::Consumption {
                    tenant_id: consume.tenant_id.clone(),
                    grant_id: consume.grant_id.clone(),
                    request_hash: consume.request_hash,
                    request_id: commitment.request_id.clone(),
                })
        {
            return Err(PortError::invalid_data());
        }
        let binding = DeclassificationTransitionBinding::Released {
            tenant_id: consume.tenant_id.clone(),
            grant_id: consume.grant_id.clone(),
            request_hash: consume.request_hash,
            request_id: commitment.request_id.clone(),
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
        };
        let transition_id = derive_declassification_transition_id(&binding)?;
        let body =
            ActiveDefenseReceiptBody::DeclassificationOutcome(DeclassificationOutcomeReceiptBody {
                header: ActiveDefenseReceiptHeader::new(
                    now,
                    consume.tenant_id.clone(),
                    transition_id.clone(),
                    vec![consumption.receipt.evidence_id.clone()],
                )
                .map_err(|_| PortError::invalid_data())?,
                policy: prior.policy,
                grant_id: consume.grant_id.clone(),
                grant_hash: prior.grant_hash,
                request_hash: consume.request_hash,
                event_id: derive_declassification_event_id(&binding)?,
                from_state: DeclassificationUseState::ConsumedPendingDispatch,
                to_state: DeclassificationUseState::Released,
            });
        body.validate().map_err(|_| PortError::invalid_data())?;
        let receipt = ReceiptAppendRequest {
            tenant_id: consume.tenant_id.clone(),
            evidence_type: RecordId::new(body.kind().as_str()).map_err(PortError::from)?,
            evidence_id: body.evidence_id().map_err(|_| PortError::invalid_data())?,
            canonical_body: CanonicalBody::new(
                chio_core::canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?,
            )
            .map_err(|_| PortError::invalid_data())?,
            body_hash: body.body_digest().map_err(|_| PortError::invalid_data())?,
            transition_id: transition_id.clone(),
            occurred_at_unix_ms: now,
        };
        let outcome = DeclassificationOutcomeEvidenceCommit {
            outcome: DeclassificationOutcomeRequest {
                tenant_id: consume.tenant_id.clone(),
                grant_id: consume.grant_id.clone(),
                request_hash: consume.request_hash,
                expected_state: DeclassificationUseState::ConsumedPendingDispatch,
                new_state: DeclassificationUseState::Released,
                transition_id,
            },
            transition_binding: binding,
            predecessor_evidence_id: consumption.receipt.evidence_id.clone(),
            receipt,
        };
        validate_declassification_outcome_evidence(&outcome)?;
        Ok(Self {
            consumption: consumption.clone(),
            outcome,
        })
    }

    pub(crate) fn changes(&self) -> PortResult<Vec<NativeRowChange>> {
        validate_declassification_consumption_evidence(&self.consumption)?;
        validate_declassification_outcome_evidence(&self.outcome)?;
        let pending = consumption_changes(&self.consumption)?;
        let outcome = &self.outcome;
        let consume = &self.consumption.consumption;
        let receipt = &outcome.receipt;
        let binding = encode_declassification_binding(&outcome.transition_binding)?;
        let uses = vec![
            Value::Text(consume.grant_id.as_str().into()),
            Value::Text(consume.tenant_id.as_str().into()),
            Value::Blob(consume.request_hash.as_bytes().to_vec()),
            Value::Text(declassification_state_name(outcome.outcome.new_state).into()),
            Value::Integer(to_i64(consume.consumed_at_unix_ms)?),
            Value::Integer(to_i64(consume.grant_expires_at_unix_ms)?),
            Value::Integer(to_i64(declassification_retain_until_unix_ms(
                consume.grant_expires_at_unix_ms,
            )?)?),
            Value::Blob(encode_declassification_binding(
                &self.consumption.transition_binding,
            )?),
            Value::Blob(binding.clone()),
            Value::Text(receipt.transition_id.as_str().into()),
        ];
        let identity = vec![
            Value::Text(receipt.evidence_id.as_str().into()),
            Value::Text(receipt.transition_id.as_str().into()),
            Value::Text(consume.tenant_id.as_str().into()),
            Value::Text(consume.grant_id.as_str().into()),
            Value::Text("outcome".into()),
            Value::Blob(receipt.body_hash.as_bytes().to_vec()),
        ];
        let outbox = vec![
            Value::Text(consume.tenant_id.as_str().into()),
            Value::Text(consume.grant_id.as_str().into()),
            Value::Text("outcome".into()),
            Value::Integer(1),
            Value::Blob(consume.request_hash.as_bytes().to_vec()),
            Value::Text(declassification_state_name(outcome.outcome.new_state).into()),
            Value::Blob(binding),
            Value::Text(receipt.evidence_type.as_str().into()),
            Value::Text(receipt.evidence_id.as_str().into()),
            Value::Blob(receipt.canonical_body.as_bytes().to_vec()),
            Value::Blob(receipt.body_hash.as_bytes().to_vec()),
            Value::Text(receipt.transition_id.as_str().into()),
            Value::Integer(to_i64(receipt.occurred_at_unix_ms)?),
            Value::Text(outcome.predecessor_evidence_id.as_str().into()),
            Value::Integer(0),
            Value::Null,
            Value::Null,
            Value::Integer(0),
            Value::Integer(to_i64(receipt.occurred_at_unix_ms)?),
            Value::Null,
        ];
        TABLES
            .into_iter()
            .zip([uses, identity, outbox])
            .enumerate()
            .map(|(index, (table, values))| {
                let refs = values.iter().map(ValueRef::from).collect::<Vec<_>>();
                let encoded = encode_retained_security_values(table, &refs)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(NativeRowChange {
                    table: table.into(),
                    before: if index == 0 {
                        pending[0].after.clone()
                    } else {
                        None
                    },
                    after: Some(
                        String::from_utf8(encoded).map_err(|_| PortError::integrity_failure())?,
                    ),
                })
            })
            .collect()
    }

    pub(crate) fn validate_change(&self, change: &NativeRowChange) -> PortResult<()> {
        if self.changes()?.contains(change) {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        }
    }

    pub(crate) fn validate_changes(&self, changes: &[NativeRowChange]) -> PortResult<()> {
        let expected = self.changes()?;
        if changes
            .iter()
            .filter(|change| TABLES.contains(&change.table.as_str()))
            .count()
            != expected.len()
            || expected
                .iter()
                .any(|expected| changes.iter().filter(|actual| *actual == expected).count() != 1)
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}
