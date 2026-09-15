//! Public evidence of an unresolved execution. This grants no settlement authority.
use crate::{common::*, market::Acceptance, review::ReviewRequest};
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationState, SignedAdmissionTerminalProjectionV1,
};
use chio_store_sqlite::SqliteAdmissionOperationStore;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

pub const SCHEMA: &str = "chio.example.review-incident.v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Incident {
    schema: String,
    agreement_sha256: String,
    accepted_bid_sha256: String,
    projection: SignedAdmissionTerminalProjectionV1,
}

pub fn delivery(
    acceptance: &Acceptance,
    database: &Path,
    store: &SqliteAdmissionOperationStore,
    signer: &chio_core_types::Keypair,
) -> Result<Value> {
    // This query is only a bounded locator. The qualified store re-reads and
    // verifies all authoritative data before signing; the raw row grants nothing.
    let db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM admission_operations LIMIT 4097)",
        [],
        |r| r.get(0),
    )?;
    if count > 4096 {
        return Err("incident lookup exceeds this bounded profile".into());
    }
    let mut query = db.prepare("SELECT operation_id FROM admission_operations WHERE terminal=1 AND state='outcome_unknown_after_dispatch' AND json_extract(operation_json,'$.binding.capability_id')=? LIMIT 2")?;
    let ids = query
        .query_map([&acceptance.ask.body.token_offer.id], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() != 1 {
        return Err(
            "no unique committed incident; execution remains uncertain and cannot be replayed"
                .into(),
        );
    }
    let projection = store.export_outcome_unknown_projection(
        &AdmissionOperationId::from_persisted(ids[0].clone())?,
        signer,
    )?;
    let incident = Incident {
        schema: SCHEMA.into(),
        agreement_sha256: digest(&acceptance.quote.agreement)?,
        accepted_bid_sha256: digest(&acceptance.accepted)?,
        projection,
    };
    verify_acceptance(acceptance, &incident)?;
    Ok(serde_json::to_value(incident)?)
}

pub fn verify(request: &ReviewRequest, incident: &Incident) -> Result<String> {
    let a = &request.acceptance;
    request.validate(&Peers {
        buyer: a.quote.agreement.buyer.clone(),
        provider: a.quote.agreement.provider.clone(),
    })?;
    let verified = verify_acceptance(a, incident)?;
    let operation = verified.terminal_operation();
    if operation.binding().action_parameter_hash().as_str() != digest(request)? {
        return Err("incident changes the review request".into());
    }
    Ok(operation.binding().operation_id().as_str().into())
}

fn verify_acceptance(
    a: &Acceptance,
    incident: &Incident,
) -> Result<chio_kernel::admission_operation::VerifiedAdmissionTerminalProjectionV1> {
    a.verify(&Peers {
        buyer: a.quote.agreement.buyer.clone(),
        provider: a.quote.agreement.provider.clone(),
    })?;
    let verified = incident.projection.verify()?;
    let operation = verified.terminal_operation();
    let binding = operation.binding().to_persisted();
    if incident.schema != SCHEMA
        || incident.agreement_sha256 != digest(&a.quote.agreement)?
        || incident.accepted_bid_sha256 != digest(&a.accepted)?
        || verified.signer_key() != &a.quote.agreement.provider
        || operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch
        || binding.capability_id.as_str() != a.ask.body.token_offer.id
        || binding.authorization_capability_hash.as_str() != digest(&a.ask.body.token_offer)?
        || operation.binding().participant_requirements()
            != (chio_kernel::admission_operation::AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                payment: true,
                ..chio_kernel::admission_operation::AdmissionParticipantRequirements::NONE
            })
        || operation.tool_outcome_id().is_some()
    {
        return Err("incident does not bind this unresolved paid review".into());
    }
    Ok(verified)
}
