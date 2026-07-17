use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationDispositionTransitionV1, ObligationDispositionV1,
};
use chio_settle::channel::{
    ChannelReservationBodyV1, ChannelSignatureV1, SignedChannelReservationV1,
    CHANNEL_RESERVATION_SCHEMA,
};
use rusqlite::params;

use super::*;

struct ObligationArtifact {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    obligation_json: Vec<u8>,
    channel_json: Vec<u8>,
}

struct PerCallArtifact {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    obligation_json: Vec<u8>,
}

fn obligation_artifact(
    at: u64,
    suffix: &str,
    economic_intent: &str,
    source_receipt_id: &str,
    source_receipt_digest: &str,
    units: u64,
) -> AnchoredTestResult<ObligationArtifact> {
    let payer = Keypair::from_seed(&[0x61; 32]);
    let authority = Keypair::from_seed(&[0x62; 32]);
    let channel_id = economic_digest(&format!("channel-{suffix}"));
    let reservation_id = economic_digest(&format!("reservation-{suffix}"));
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: reservation_id.clone(),
        channel_id: channel_id.clone(),
        open_digest: economic_digest(&format!("open-{suffix}")),
        request_id: format!("request-{suffix}"),
        operation_id: economic_digest(&format!("operation-{suffix}")),
        next_sequence: 1,
        prior_state_digest: economic_digest(&format!("prior-state-{suffix}")),
        service_binding_digest: economic_digest(&format!("service-binding-{suffix}")),
        receipt_authority_digest: economic_digest(&format!("receipt-authority-{suffix}")),
        maximum_charge: MonetaryAmount {
            units: units.max(1),
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: units.max(1).to_string(),
        expires_at_unix_ms: at + 60_000,
        disposition_expected_version: 1,
        channel_state_expected_version: 1,
        lifecycle_fence: 1,
    };
    let signed_reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "payer-1".to_owned(),
            1,
            &payer,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "authority-1".to_owned(),
            1,
            &authority,
        )?,
        body: reservation_body,
    };
    let reservation_digest = signed_reservation.digest()?;
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: economic_intent.to_owned(),
        source_receipt_id: source_receipt_id.to_owned(),
        source_receipt_digest: source_receipt_digest.to_owned(),
        debtor_id: "payer-1".to_owned(),
        original_creditor_id: "payee-1".to_owned(),
        original_settlement_destination_ref: "channel:payee-1".to_owned(),
        payee_binding_digest: economic_digest("payee-binding"),
        amount: MonetaryAmount {
            units,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: reservation_digest.clone(),
        created_at_unix_ms: at,
        due_at_unix_ms: at + 86_400_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id,
            reservation_id: reservation_id.clone(),
            authority_digest: reservation_digest.clone(),
        },
    )?;
    let atom_digest = atom.digest()?;
    let obligation_json = canonical_json_bytes(&serde_json::json!({
        "source": {
            "source_authority_digest": atom.pre_action_authority_digest(),
            "source_record_id": atom.obligation_id(),
            "source_record_digest": atom_digest,
            "source_recorded_at_unix_ms": atom.created_at_unix_ms(),
            "consumer_receipt_id": atom.source_receipt_id(),
            "consumer_receipt_digest": atom.source_receipt_digest()
        },
        "atom": atom,
        "disposition_record": disposition
    }))?;
    let channel_json = canonical_json_bytes(&serde_json::json!({
        "reservation_id": reservation_id,
        "reservation_digest": reservation_digest,
        "receipt_id": source_receipt_id,
        "receipt_digest": source_receipt_digest,
        "actual_charge": { "units": units, "currency": "USD" },
        "obligation_atom_id": atom.obligation_id(),
        "obligation_atom_digest": atom.digest()?,
        "signed_reservation": signed_reservation
    }))?;
    Ok(ObligationArtifact {
        atom,
        disposition,
        obligation_json,
        channel_json,
    })
}

fn per_call_artifact(at: u64, suffix: &str) -> AnchoredTestResult<PerCallArtifact> {
    let authority_digest = economic_digest(&format!("per-call-authority-{suffix}"));
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: economic_digest(&format!("per-call-intent-{suffix}")),
        source_receipt_id: format!("per-call-receipt-{suffix}"),
        source_receipt_digest: economic_digest(&format!("per-call-receipt-{suffix}")),
        debtor_id: "payer-1".to_owned(),
        original_creditor_id: "payee-1".to_owned(),
        original_settlement_destination_ref: "per-call:payee-1".to_owned(),
        payee_binding_digest: economic_digest("per-call-payee-binding"),
        amount: MonetaryAmount {
            units: 37,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: authority_digest,
        created_at_unix_ms: at,
        due_at_unix_ms: at + 86_400_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let obligation_json = canonical_json_bytes(&serde_json::json!({
        "source": {
            "source_authority_digest": atom.pre_action_authority_digest(),
            "source_record_id": atom.obligation_id(),
            "source_record_digest": atom.digest()?,
            "source_recorded_at_unix_ms": atom.created_at_unix_ms(),
            "consumer_receipt_id": atom.source_receipt_id(),
            "consumer_receipt_digest": atom.source_receipt_digest()
        },
        "atom": atom,
        "disposition_record": disposition
    }))?;
    Ok(PerCallArtifact {
        atom,
        disposition,
        obligation_json,
    })
}

fn operation(fixture: &Fixture, suffix: &str, at: u64) -> AnchoredTestResult<AdmissionOperationV1> {
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        &format!("obligation-request-{suffix}"),
        &format!("obligation-capability-{suffix}"),
    );
    fixture.store.begin(&operation, &fixture.fence, at)?;
    Ok(operation)
}

fn insert_local_projection(
    transaction: &rusqlite::Transaction<'_>,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
    at: u64,
) -> AnchoredTestResult {
    transaction.execute(
        r#"
        INSERT INTO admission_operation_terminal_projections (
            operation_id, source_operation_version, terminal_operation_version,
            terminal_state, projection_body_digest, projection_digest,
            projection_json, manifest_json, record_count, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, 'completed', ?4, ?5, X'01', X'01', 1, ?6, ?7, ?8, ?9)
        "#,
        params![
            operation.binding().operation_id().as_str(),
            i64::try_from(operation.version())?,
            i64::try_from(operation.version() + 1)?,
            economic_digest("projection-body"),
            economic_digest("projection-manifest"),
            i64::try_from(at)?,
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

fn commit_projection_with_obligation(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    artifact: &ObligationArtifact,
    at: u64,
) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, operation, &fixture.fence, at)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        Some(&artifact.channel_json),
        at,
        at,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

#[test]
fn positive_channel_terminal_projection_persists_exact_obligation_atomically() -> AnchoredTestResult
{
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "positive", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "positive",
        &economic_digest("intent-positive"),
        "receipt-positive",
        &economic_digest("receipt-positive"),
        17,
    )?;
    commit_projection_with_obligation(&fixture, &operation, &artifact, at + 1)?;
    let stored = fixture
        .store
        .load_obligation(artifact.atom.obligation_id())?
        .ok_or("canonical obligation was not persisted")?;
    assert_eq!(stored.atom(), &artifact.atom);
    assert_eq!(stored.disposition(), &artifact.disposition);
    let connection = fixture.store.connection()?;
    let disposition_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1",
        [artifact.atom.obligation_id()],
        |row| row.get(0),
    )?;
    assert_eq!(disposition_count, 2);
    Ok(())
}

#[test]
fn zero_charge_channel_terminal_projection_creates_no_obligation() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "zero", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "zero",
        &economic_digest("intent-zero"),
        "receipt-zero",
        &economic_digest("receipt-zero"),
        1,
    )?;
    let channel: serde_json::Value = serde_json::from_slice(&artifact.channel_json)?;
    let mut channel = channel;
    channel["actual_charge"]["units"] = serde_json::json!(0);
    channel["obligation_atom_id"] = serde_json::Value::Null;
    channel["obligation_atom_digest"] = serde_json::Value::Null;
    let channel_json = canonical_json_bytes(&channel)?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        None,
        Some(&channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    let count: i64 = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM obligation_atoms) + (SELECT COUNT(*) FROM obligation_disposition_records)",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn exact_obligation_replay_is_idempotent() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "replay", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "replay",
        &economic_digest("intent-replay"),
        "receipt-replay",
        &economic_digest("receipt-replay"),
        23,
    )?;
    commit_projection_with_obligation(&fixture, &operation, &artifact, at + 1)?;
    let connection = fixture.store.connection()?;
    for _ in 0..2 {
        super::super::obligation::verify_obligation_projection(
            &connection,
            operation.binding().operation_id(),
            Some(&artifact.obligation_json),
            Some(&artifact.channel_json),
            at + 1,
            at + 1,
            &fixture.fence,
        )?;
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1",
        [artifact.atom.obligation_id()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn exact_replay_accepts_a_later_legal_disposition_successor() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let source_operation = operation(&fixture, "prefix-source", at)?;
    let artifact = per_call_artifact(at + 1, "prefix")?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &source_operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        source_operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        None,
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    drop(connection);

    let successor_operation = operation(&fixture, "prefix-successor", at + 2)?;
    let successor = artifact.disposition.advance(
        &artifact.atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-prefix".to_owned(),
            authority_digest: economic_digest("round-prefix-authority"),
        },
    )?;
    let successor_json = canonical_json_bytes(&successor)?;
    let successor_digest = successor.digest(&artifact.atom)?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &successor_operation, &fixture.fence, at + 3)?;
    transaction.execute(
        r#"
        INSERT INTO obligation_disposition_records (
            obligation_id, version, lifecycle_fence, atom_digest,
            disposition_digest, operation_id, record_json, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            successor.obligation_id(),
            i64::try_from(successor.version())?,
            i64::try_from(successor.lifecycle_fence())?,
            successor.atom_digest(),
            successor_digest,
            successor_operation.binding().operation_id().as_str(),
            successor_json,
            i64::try_from(at + 3)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;

    super::super::obligation::verify_obligation_projection(
        &connection,
        source_operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        None,
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    let current = super::super::obligation::load_durable_obligation(
        &connection,
        artifact.atom.obligation_id(),
    )?
    .ok_or("canonical obligation disappeared after its successor")?;
    assert!(matches!(
        current.disposition().disposition(),
        ObligationDispositionV1::ClearingReserved { round_id } if round_id == "round-prefix"
    ));
    Ok(())
}

#[test]
fn conflicting_obligation_source_and_digest_are_rejected() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let source_receipt_digest = economic_digest("receipt-conflict");
    let first_operation = operation(&fixture, "conflict-first", at)?;
    let first = obligation_artifact(
        at + 1,
        "conflict-first",
        &economic_digest("intent-conflict-first"),
        "receipt-conflict",
        &source_receipt_digest,
        29,
    )?;
    commit_projection_with_obligation(&fixture, &first_operation, &first, at + 1)?;

    let second_operation = operation(&fixture, "conflict-second", at + 2)?;
    let second = obligation_artifact(
        at + 3,
        "conflict-second",
        &economic_digest("intent-conflict-second"),
        "receipt-conflict",
        &source_receipt_digest,
        29,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &second_operation, &fixture.fence, at + 3)?;
    assert!(super::super::obligation::insert_obligation_projection(
        &transaction,
        second_operation.binding().operation_id(),
        Some(&second.obligation_json),
        Some(&second.channel_json),
        at + 3,
        at + 3,
        &fixture.fence,
    )
    .is_err());
    transaction.rollback()?;

    let mut substituted: serde_json::Value = serde_json::from_slice(&first.obligation_json)?;
    substituted["source"]["source_record_digest"] =
        serde_json::json!(economic_digest("substituted-atom-digest"));
    let substituted = canonical_json_bytes(&substituted)?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    assert!(super::super::obligation::insert_obligation_projection(
        &transaction,
        first_operation.binding().operation_id(),
        Some(&substituted),
        Some(&first.channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )
    .is_err());
    transaction.rollback()?;
    Ok(())
}

#[test]
fn obligation_failure_rolls_back_local_terminal_and_obligation_state() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "rollback", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "rollback",
        &economic_digest("intent-rollback"),
        "receipt-rollback",
        &economic_digest("receipt-rollback"),
        31,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        Some(&artifact.channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    transaction.rollback()?;
    let count: i64 = connection.query_row(
        r#"
        SELECT (SELECT COUNT(*) FROM admission_operation_terminal_projections WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_atoms WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_disposition_records WHERE operation_id = ?1)
        "#,
        [operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
