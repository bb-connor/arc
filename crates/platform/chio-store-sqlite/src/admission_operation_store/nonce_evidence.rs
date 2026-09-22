//! Public nonce history from the anchored authority, excluding private requests.

use chio_kernel::execution_nonce::SignedExecutionNonce;

use super::*;

/// Historical store readback. An exporter must authenticate this observation;
/// decoding it alone proves neither custody nor permission to execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNonceEvidenceV1 {
    pub operation: PersistedAdmissionOperationV1,
    pub signed_nonce: SignedExecutionNonce,
    pub reserved_at_unix_ms: Option<u64>,
    pub verified_at_unix_ms: u64,
}

impl SqliteAdmissionOperationStore {
    /// Read the original issuance and reservation using their existing commit,
    /// fence, clock, private-request and phase-history validation.
    pub fn load_execution_nonce_evidence(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ExecutionNonceEvidenceV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&transaction, now)?;
        let result = if let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? {
            stored.verify_decision_time(now)?;
            let reserved = execution_nonce::verify_reservation(&transaction, &stored.operation)?;
            let issued = execution_nonce::issuance::verify(&transaction, &stored.operation)?;
            match reserved.as_ref().or(issued.as_ref()) {
                Some(checked) => {
                    let reserved_at = if reserved.is_some() {
                        let time: i64 = transaction.query_row(
                            "SELECT reserved_at_unix_ms FROM admission_execution_nonce_reservations WHERE operation_id = ?1",
                            [operation_id.as_str()],
                            |row| row.get(0),
                        ).map_err(sqlite_error)?;
                        Some(stored_u64(time, "nonce reservation time")?)
                    } else {
                        None
                    };
                    let verified_at = match reserved_at {
                        Some(time) => threshold_approval::nonce_verification_time_unix_ms(
                            &transaction,
                            &stored.operation,
                            time,
                        )?,
                        None => u64::try_from(checked.signed_nonce().nonce.issued_at)
                            .ok()
                            .and_then(|time| time.checked_mul(1000))
                            .ok_or_else(|| invariant("invalid nonce issuance time"))?,
                    };
                    Some(ExecutionNonceEvidenceV1 {
                        operation: stored.operation.to_persisted(),
                        signed_nonce: checked.signed_nonce().clone(),
                        reserved_at_unix_ms: reserved_at,
                        verified_at_unix_ms: verified_at,
                    })
                }
                None => None,
            }
        } else {
            None
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}
