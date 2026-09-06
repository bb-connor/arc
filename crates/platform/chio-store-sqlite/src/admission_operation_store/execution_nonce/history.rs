//! Bounded nonce phase history, authenticated by exact admission commits.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    CapturePending,
    Committed,
    Cancelled,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::CapturePending => "capture_pending",
            Self::Committed => "committed",
            Self::Cancelled => "cancelled",
        }
    }

    fn state(self) -> AdmissionOperationState {
        match self {
            Self::CapturePending => AdmissionOperationState::CapturePending,
            Self::Committed => AdmissionOperationState::DispatchCommitted,
            Self::Cancelled => AdmissionOperationState::CompensatedBeforeDispatch,
        }
    }

    fn parse(value: &str) -> Result<Self, AdmissionOperationStoreError> {
        match value {
            "capture_pending" => Ok(Self::CapturePending),
            "committed" => Ok(Self::Committed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invariant("unknown nonce transition phase")),
        }
    }
}

pub(super) fn preserves_attachments(
    source: &AdmissionOperationV1,
    current: &AdmissionOperationV1,
) -> bool {
    source
        .attachments()
        .iter()
        .all(|attachment| current.attachments().contains(attachment))
}

pub(super) fn insert(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    phase: Phase,
    participant_digest: Option<&str>,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if operation.state() != phase.state()
        || (phase == Phase::Cancelled) != participant_digest.is_none()
    {
        return Err(invariant("nonce transition does not match its operation"));
    }
    transaction
        .execute(
            "INSERT INTO admission_execution_nonce_transitions (
            operation_id, kind, operation_json, participant_digest, recorded_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation.binding().operation_id().as_str(),
                phase.name(),
                encode_operation(operation)?,
                participant_digest,
                sqlite_i64(now, "nonce_transition_time")?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn preparation_digest(
    nonce: &AdmissionExecutionNonceReservationV1,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct Preparation {
        schema: &'static str,
        reservation_digest: String,
        operation_digest: String,
        recorded_at_unix_ms: u64,
    }
    canonical_json_bytes(&Preparation {
        schema: "chio.admission-execution-nonce-capture-preparation.v1",
        reservation_digest: sha256_hex(nonce.canonical_bytes()),
        operation_digest: sha256_hex(&encode_operation(operation)?),
        recorded_at_unix_ms: now,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|error| invariant(error.to_string()))
}

pub(super) fn verify(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    ready: &AdmissionOperationV1,
    nonce: &AdmissionExecutionNonceReservationV1,
    reserved_at: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT CASE WHEN length(kind) <= 15 THEN kind END,
                CASE WHEN length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END,
                recorded_at_unix_ms,
                CASE WHEN length(participant_digest) = 64 THEN participant_digest END,
                participant_digest IS NULL
         FROM admission_execution_nonce_transitions WHERE operation_id = ?1
         ORDER BY CASE kind WHEN 'capture_pending' THEN 0 WHEN 'committed' THEN 1 ELSE 2 END
         LIMIT 4",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([operation.binding().operation_id().as_str()])
        .map_err(sqlite_error)?;
    let mut phases = Vec::with_capacity(3);
    let mut previous = ready.clone();
    let mut previous_time = reserved_at;
    let original = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("nonce transition lost its original request"))?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        if phases.len() == 3 {
            return Err(invariant("nonce transition inventory exceeds its bound"));
        }
        let kind: Option<String> = row.get(0).map_err(sqlite_error)?;
        let bytes: Option<Vec<u8>> = row.get(1).map_err(sqlite_error)?;
        let (Some(kind), Some(bytes)) = (kind, bytes) else {
            return Err(invariant("nonce transition exceeds its storage bound"));
        };
        let phase = Phase::parse(&kind)?;
        let time = stored_u64(row.get(2).map_err(sqlite_error)?, "nonce_transition_time")?;
        let participant: Option<String> = row.get(3).map_err(sqlite_error)?;
        let participant_is_null: bool = row.get(4).map_err(sqlite_error)?;
        if participant.is_none() != participant_is_null {
            return Err(invariant(
                "nonce transition participant exceeds its storage bound",
            ));
        }
        let snapshot = AdmissionOperationV1::from_persisted(
            serde_json::from_slice::<PersistedAdmissionOperationV1>(&bytes)
                .map_err(|error| invariant(error.to_string()))?,
        )?;
        if snapshot.state() != phase.state()
            || snapshot.binding() != operation.binding()
            || snapshot.version() <= previous.version()
            || snapshot.version() > operation.version()
            || time < previous_time
            || encode_operation(&snapshot)? != bytes
            || !preserves_attachments(&previous, &snapshot)
            || !preserves_attachments(&snapshot, operation)
            || (phase == Phase::Cancelled) != participant.is_none()
        {
            return Err(invariant(
                "nonce transition snapshot or ordering is invalid",
            ));
        }
        if phase == Phase::CapturePending
            && participant.as_deref() != Some(preparation_digest(nonce, &snapshot, time)?.as_str())
        {
            return Err(invariant(
                "nonce preparation lost its exact participant commitment",
            ));
        }
        let committed: bool = connection
            .query_row(
                "SELECT COUNT(*) = 1 FROM admission_operation_commits
             WHERE operation_id = ?1 AND operation_version = ?2
               AND mutation_kind = 'compare_and_swap' AND operation_digest = ?3
               AND recorded_at_unix_ms = ?4 AND participant_digest IS ?5",
                params![
                    operation.binding().operation_id().as_str(),
                    sqlite_i64(snapshot.version(), "nonce_transition_version")?,
                    sha256_hex(&bytes),
                    sqlite_i64(time, "nonce_transition_time")?,
                    participant
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !committed {
            return Err(invariant(
                "nonce transition lost its exact admission commit",
            ));
        }
        if phase != Phase::Cancelled {
            AdmissionExecutionNonceReservationV1::from_canonical_bytes(
                nonce.canonical_bytes(),
                &snapshot,
                &original,
                nonce.issuer(),
                time,
            )?;
        }
        phases.push(phase);
        previous = snapshot;
        previous_time = time;
    }
    let valid = match operation.state() {
        AdmissionOperationState::ReadyToDispatch => phases.is_empty(),
        AdmissionOperationState::CapturePending => phases == [Phase::CapturePending],
        AdmissionOperationState::CompensatedBeforeDispatch => {
            phases == [Phase::Cancelled] || phases == [Phase::CapturePending, Phase::Cancelled]
        }
        AdmissionOperationState::DispatchCommitted
        | AdmissionOperationState::Finalizing
        | AdmissionOperationState::Completed
        | AdmissionOperationState::NotAcceptedAfterDispatchCommit
        | AdmissionOperationState::OutcomeUnknownAfterDispatch
        | AdmissionOperationState::DeniedAfterDelivery => {
            phases == [Phase::CapturePending, Phase::Committed]
        }
        _ => false,
    };
    if !valid {
        return Err(invariant(
            "nonce history does not authorize its operation phase",
        ));
    }
    Ok(())
}

pub(super) fn verify_absent(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_execution_nonce_transitions WHERE operation_id = ?1)",
        [operation.binding().operation_id().as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if present {
        return Err(invariant("nonce transition has no reservation"));
    }
    Ok(())
}

pub(super) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_execution_nonce_transitions AS transition
         WHERE NOT EXISTS(SELECT 1 FROM admission_execution_nonce_reservations AS reservation
                          WHERE reservation.operation_id = transition.operation_id))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant("nonce transition has no owning reservation"));
    }
    Ok(())
}
