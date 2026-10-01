use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DeclassificationConsumptionReceiptBody, DeclassificationOutcomeReceiptBody,
};
use chio_security_types::ports::{
    declassification_retain_until_unix_ms, derive_declassification_event_id,
    derive_declassification_transition_id, CanonicalBody, DeclassificationCompactionRequest,
    DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePhase,
    DeclassificationOutcomeEvidenceCommit, DeclassificationOutcomeRequest,
    DeclassificationTransitionBinding, DeclassificationUseState, GrantId, ReceiptAppendRequest,
};

use super::*;

fn policy() -> TestResult<ActiveDefensePolicyBinding> {
    Ok(ActiveDefensePolicyBinding {
        policy_version: RecordId::new("policy")?,
        policy_hash: Digest32::new([2; 32]),
    })
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

pub(crate) fn consumption(grant: &str) -> TestResult<DeclassificationConsumptionEvidenceCommit> {
    let binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: key()?.tenant_id,
        grant_id: GrantId::new(grant)?,
        request_hash: Digest32::new([3; 32]),
        request_id: RequestId::new(format!("request-{grant}"))?,
    };
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                1_000,
                binding.tenant_id().clone(),
                derive_declassification_transition_id(&binding)?,
                Vec::new(),
            )?,
            policy: policy()?,
            grant_id: binding.grant_id().clone(),
            grant_hash: Digest32::new([4; 32]),
            request_hash: binding.request_hash(),
            event_id: derive_declassification_event_id(&binding)?,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    );
    Ok(DeclassificationConsumptionEvidenceCommit {
        consumption: DeclassificationConsumeRequest {
            tenant_id: binding.tenant_id().clone(),
            grant_id: binding.grant_id().clone(),
            request_hash: binding.request_hash(),
            consumed_at_unix_ms: 1_000,
            grant_expires_at_unix_ms: 2_000,
        },
        transition_binding: binding,
        receipt: receipt(&body)?,
    })
}

pub(crate) fn release(
    consumed: &DeclassificationConsumptionEvidenceCommit,
) -> TestResult<DeclassificationOutcomeEvidenceCommit> {
    let grant = &consumed.consumption.grant_id;
    let binding = DeclassificationTransitionBinding::Released {
        tenant_id: consumed.consumption.tenant_id.clone(),
        grant_id: grant.clone(),
        request_hash: consumed.consumption.request_hash,
        request_id: RequestId::new(format!("request-{grant}"))?,
        dispatch_commitment_id: RecordId::new(format!("dispatch-{grant}"))?,
    };
    let body =
        ActiveDefenseReceiptBody::DeclassificationOutcome(DeclassificationOutcomeReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                1_500,
                binding.tenant_id().clone(),
                derive_declassification_transition_id(&binding)?,
                vec![consumed.receipt.evidence_id.clone()],
            )?,
            policy: policy()?,
            grant_id: grant.clone(),
            grant_hash: Digest32::new([4; 32]),
            request_hash: binding.request_hash(),
            event_id: derive_declassification_event_id(&binding)?,
            from_state: DeclassificationUseState::ConsumedPendingDispatch,
            to_state: DeclassificationUseState::Released,
        });
    Ok(DeclassificationOutcomeEvidenceCommit {
        outcome: DeclassificationOutcomeRequest {
            tenant_id: binding.tenant_id().clone(),
            grant_id: grant.clone(),
            request_hash: binding.request_hash(),
            expected_state: DeclassificationUseState::ConsumedPendingDispatch,
            new_state: DeclassificationUseState::Released,
            transition_id: derive_declassification_transition_id(&binding)?,
        },
        transition_binding: binding,
        predecessor_evidence_id: consumed.receipt.evidence_id.clone(),
        receipt: receipt(&body)?,
    })
}

pub(super) fn seed_history(store: &SqliteSecurityStateStore) -> TestResult {
    store.seal_declassification_live_dispatch()?;
    for grant in ["pending", "terminal", "compacted"] {
        let consumed = consumption(grant)?;
        assert_eq!(
            store.commit_declassification_consumption_evidence(&consumed)?,
            DeclassificationConsume::Consumed
        );
        if grant == "pending" {
            continue;
        }
        let released = release(&consumed)?;
        store.commit_declassification_outcome_evidence(&released)?;
        if grant != "compacted" {
            continue;
        }
        for (phase, evidence) in [
            (
                DeclassificationEvidencePhase::Consumption,
                &consumed.receipt,
            ),
            (DeclassificationEvidencePhase::Outcome, &released.receipt),
        ] {
            store.acknowledge_declassification_evidence(&DeclassificationEvidenceAckRequest {
                tenant_id: evidence.tenant_id.clone(),
                grant_id: consumed.consumption.grant_id.clone(),
                phase,
                evidence_id: evidence.evidence_id.clone(),
                body_hash: evidence.body_hash,
                transition_id: evidence.transition_id.clone(),
                durable_sink_record_hash: Digest32::new([5; 32]),
                verified_at_unix_ms: 1_600,
            })?;
        }
        store.compact_declassification_evidence(&DeclassificationCompactionRequest {
            readiness_cursor: store.declassification_evidence_readiness_cursor()?,
            tenant_id: consumed.consumption.tenant_id.clone(),
            grant_id: consumed.consumption.grant_id.clone(),
            request_hash: consumed.consumption.request_hash,
            terminal_state: DeclassificationUseState::Released,
            consumption_evidence_id: consumed.receipt.evidence_id.clone(),
            consumption_body_hash: consumed.receipt.body_hash,
            consumption_transition_id: consumed.receipt.transition_id.clone(),
            consumption_occurred_at_unix_ms: 1_000,
            consumption_sink_record_hash: Digest32::new([5; 32]),
            outcome_evidence_id: released.receipt.evidence_id.clone(),
            outcome_body_hash: released.receipt.body_hash,
            outcome_transition_id: released.receipt.transition_id.clone(),
            outcome_occurred_at_unix_ms: 1_500,
            outcome_sink_record_hash: Digest32::new([5; 32]),
            policy_hash: policy()?.policy_hash,
            compacted_at_unix_ms: declassification_retain_until_unix_ms(2_000)? + 1,
        })?;
    }
    Ok(())
}

#[test]
fn retains_pending_terminal_outbox_and_compacted_tombstones_without_resuming_dispatch() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    seed_history(&store)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    let value: serde_json::Value = serde_json::from_slice(&expected.canonical_bytes()?)?;
    let tables = value["tables"].as_array().ok_or("missing tables")?;
    for (table, count) in [
        ("security_declassification_uses", 2),
        ("security_declassification_receipt_outbox", 3),
        ("security_declassification_evidence_identity", 5),
        ("security_declassification_tombstones", 1),
    ] {
        let row = tables
            .iter()
            .find(|entry| entry["table"] == table)
            .ok_or("missing table")?;
        assert_eq!(row["row_count"], count);
    }
    source.seal_exact(&expected)?;
    assert!(store.seal_declassification_live_dispatch().is_err());
    assert!(store.begin_declassification_reconciliation().is_err());
    assert!(store
        .commit_declassification_consumption_evidence(&consumption("pending")?)
        .is_err());
    assert!(store
        .commit_declassification_consumption_evidence(&consumption("new-grant")?)
        .is_err());
    assert!(store
        .commit_declassification_outcome_evidence(&release(&consumption("pending")?)?)
        .is_err());
    drop(store);
    drop(source);
    SqliteSecurityParticipantSource::open(&path)?.verify_seal(&expected)?;
    Ok(())
}

#[test]
fn corrupt_declassification_history_cannot_be_blessed_by_a_new_source_fingerprint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    seed_history(&store)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let legacy = Connection::open(&path)?;
    let ddl: String = legacy.query_row(
        "SELECT sql FROM sqlite_schema
        WHERE name = 'security_declassification_evidence_immutable'",
        [],
        |row| row.get(0),
    )?;
    legacy.execute_batch(
        "DROP TRIGGER security_declassification_evidence_immutable;
        UPDATE security_declassification_receipt_outbox SET canonical_body = CAST('{}' AS BLOB)",
    )?;
    legacy.execute_batch(&ddl)?;
    schema::verify(&legacy, false)?;
    assert!(source.preview(&binding()?).is_err());
    assert!(SqliteSecurityParticipantSource::open(&path).is_err());
    assert!(!schema::has_evidence(&legacy)?);
    Ok(())
}
