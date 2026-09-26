//! Native SQL semantics only: every native mutation is test-only and rolled back.

use super::*;
use crate::admission_operation_store::with_flow_sql_fixture;
use chio_security_types::ports::{
    derive_declassification_event_id, derive_declassification_transition_id, CanonicalBody,
    ErrorCode,
};

mod compaction;
mod equivalence;
mod isolation;
mod recovery;
mod snapshot;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const A: &str = "authority-a";
const B: &str = "authority-b";

fn seed_lifecycle(tx: &Transaction<'_>, authority: &str) -> TestResult {
    tx.execute(
        "INSERT INTO security_participant_state_declassification_lifecycle
         (security_authority_id, singleton, schema_version, readiness_cursor,
          reconciliation_active, live_dispatch_sealed, compaction_active)
         VALUES (?1, 1, 2, ?2, 0, 0, 0)",
        params![authority, DECLASSIFICATION_READINESS_CURSOR],
    )?;
    Ok(())
}

fn receipt(body: &ActiveDefenseReceiptBody) -> TestResult<ReceiptAppendRequest> {
    body.validate()?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())?,
        evidence_id: body.evidence_id()?,
        canonical_body: CanonicalBody::new(chio_core::canonical_json_bytes(body)?)?,
        body_hash: body.body_digest()?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

fn consumption(tenant: &str, grant: &str) -> TestResult<DeclassificationConsumptionEvidenceCommit> {
    let mut request = participant_source::declassification_consumption_fixture(grant)?;
    let tenant_id = TenantId::new(tenant)?;
    request.consumption.tenant_id = tenant_id.clone();
    let DeclassificationTransitionBinding::Consumption {
        tenant_id: bound, ..
    } = &mut request.transition_binding
    else {
        return Err("fixture is not a consumption".into());
    };
    *bound = tenant_id.clone();
    let ActiveDefenseReceiptBody::DeclassificationConsumption(mut body) =
        decode_declassification_receipt(&request.receipt).map_err(|()| "invalid fixture")?
    else {
        return Err("fixture is not a consumption receipt".into());
    };
    body.header.tenant_id = tenant_id;
    body.header.transition_id = derive_declassification_transition_id(&request.transition_binding)?;
    body.event_id = derive_declassification_event_id(&request.transition_binding)?;
    request.receipt = receipt(&ActiveDefenseReceiptBody::DeclassificationConsumption(body))?;
    Ok(request)
}

fn release(
    consumed: &DeclassificationConsumptionEvidenceCommit,
) -> TestResult<DeclassificationOutcomeEvidenceCommit> {
    participant_source::declassification_outcome_fixture(consumed)
}

fn rebind_outcome(
    mut request: DeclassificationOutcomeEvidenceCommit,
    binding: DeclassificationTransitionBinding,
) -> TestResult<DeclassificationOutcomeEvidenceCommit> {
    let ActiveDefenseReceiptBody::DeclassificationOutcome(mut body) =
        decode_declassification_receipt(&request.receipt).map_err(|()| "invalid fixture")?
    else {
        return Err("fixture is not an outcome receipt".into());
    };
    let state = binding.terminal_state().ok_or("not terminal")?;
    body.header.transition_id = derive_declassification_transition_id(&binding)?;
    body.event_id = derive_declassification_event_id(&binding)?;
    body.to_state = state;
    request.outcome.new_state = state;
    request.outcome.transition_id = body.header.transition_id.clone();
    request.transition_binding = binding;
    request.receipt = receipt(&ActiveDefenseReceiptBody::DeclassificationOutcome(body))?;
    Ok(request)
}

fn evidence_query(
    consumed: &DeclassificationConsumptionEvidenceCommit,
    phase: DeclassificationEvidencePhase,
) -> DeclassificationEvidenceQuery {
    DeclassificationEvidenceQuery {
        tenant_id: consumed.consumption.tenant_id.clone(),
        grant_id: consumed.consumption.grant_id.clone(),
        phase,
    }
}

fn ack(
    grant: &GrantId,
    evidence: &ReceiptAppendRequest,
    phase: DeclassificationEvidencePhase,
) -> DeclassificationEvidenceAckRequest {
    DeclassificationEvidenceAckRequest {
        tenant_id: evidence.tenant_id.clone(),
        grant_id: grant.clone(),
        phase,
        evidence_id: evidence.evidence_id.clone(),
        body_hash: evidence.body_hash,
        transition_id: evidence.transition_id.clone(),
        durable_sink_record_hash: Digest32::new([5; 32]),
        verified_at_unix_ms: 1_600,
    }
}

fn retry(
    consumed: &DeclassificationConsumptionEvidenceCommit,
) -> TestResult<DeclassificationEvidenceRetryRequest> {
    Ok(DeclassificationEvidenceRetryRequest {
        tenant_id: consumed.consumption.tenant_id.clone(),
        grant_id: consumed.consumption.grant_id.clone(),
        phase: DeclassificationEvidencePhase::Consumption,
        evidence_id: consumed.receipt.evidence_id.clone(),
        body_hash: consumed.receipt.body_hash,
        transition_id: consumed.receipt.transition_id.clone(),
        failed_at_unix_ms: 1_600,
        error_code: ErrorCode::new("sink_unavailable")?,
    })
}

fn compaction_request(
    consumed: &DeclassificationConsumptionEvidenceCommit,
    outcome: &DeclassificationOutcomeEvidenceCommit,
) -> TestResult<DeclassificationCompactionRequest> {
    Ok(DeclassificationCompactionRequest {
        readiness_cursor: RecordId::new(DECLASSIFICATION_READINESS_CURSOR)?,
        tenant_id: consumed.consumption.tenant_id.clone(),
        grant_id: consumed.consumption.grant_id.clone(),
        request_hash: consumed.consumption.request_hash,
        terminal_state: outcome.outcome.new_state,
        consumption_evidence_id: consumed.receipt.evidence_id.clone(),
        consumption_body_hash: consumed.receipt.body_hash,
        consumption_transition_id: consumed.receipt.transition_id.clone(),
        consumption_occurred_at_unix_ms: consumed.receipt.occurred_at_unix_ms,
        consumption_sink_record_hash: Digest32::new([5; 32]),
        outcome_evidence_id: outcome.receipt.evidence_id.clone(),
        outcome_body_hash: outcome.receipt.body_hash,
        outcome_transition_id: outcome.receipt.transition_id.clone(),
        outcome_occurred_at_unix_ms: outcome.receipt.occurred_at_unix_ms,
        outcome_sink_record_hash: Digest32::new([5; 32]),
        policy_hash: Digest32::new([2; 32]),
        compacted_at_unix_ms: declassification_retain_until_unix_ms(2_000)? + 1,
    })
}

fn terminal(
    state: &ScopedMutation<'_>,
    consumed: &DeclassificationConsumptionEvidenceCommit,
) -> TestResult<DeclassificationOutcomeEvidenceCommit> {
    assert_eq!(
        state.commit_declassification_consumption_evidence(consumed, || Ok(1_000))?,
        DeclassificationConsume::Consumed
    );
    let outcome = release(consumed)?;
    state.commit_declassification_outcome_evidence(&outcome)?;
    state.acknowledge_declassification_evidence(&ack(
        &consumed.consumption.grant_id,
        &consumed.receipt,
        DeclassificationEvidencePhase::Consumption,
    ))?;
    state.acknowledge_declassification_evidence(&ack(
        &consumed.consumption.grant_id,
        &outcome.receipt,
        DeclassificationEvidencePhase::Outcome,
    ))?;
    Ok(outcome)
}
