//! Host-only reservation bridge. No store lock spans native/provider execution.
mod origin;
mod unused_reservation;
pub use unused_reservation::{
    ClosedUnusedRecoveryReservation, UnusedRecoveryReservationClosureData,
};

use crate::{digest, validate_id, ProcessError, ProcessRuntime};
use chio_kernel::recovery::RecoveryProcessReservationV1;
use chio_kernel::{RecoveryRequestCustody, ToolCallRequest};
use chio_security_types::recovery::{ContinuationId, IntentDigest};
use serde::{Deserialize, Serialize};

/// Process reservation identity. The journal, not this serializable value,
/// proves that the logical call was reserved.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecoveryCallReservation {
    pub(crate) data: RecoveryProcessReservationV1,
}
impl RecoveryCallReservation {
    pub fn process_id(&self) -> &str {
        &self.data.process_id
    }
    pub fn request_id(&self) -> &str {
        &self.data.request_id
    }
    pub fn operation_key(&self) -> &str {
        &self.data.operation_key
    }
    pub fn continuation_id(&self) -> &ContinuationId {
        &self.data.continuation_id
    }
    pub const fn unsigned_intent(&self) -> IntentDigest {
        self.data.unsigned_intent
    }
    /// Borrow identity data for independent verification by the native owner.
    pub fn identity(&self) -> &RecoveryProcessReservationV1 {
        &self.data
    }
}
impl core::fmt::Debug for RecoveryCallReservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCallReservation([redacted])")
    }
}

impl ProcessRuntime {
    /// Exact host-selected information-flow identity used by ordinary invoke.
    pub fn recovery_security_context(
        &self,
        process_id: &str,
    ) -> Result<chio_kernel::SecurityInvocationContext, ProcessError> {
        let profile = self
            .security_profile
            .as_ref()
            .ok_or(ProcessError::Configuration(
                "recovery requires native information flow",
            ))?;
        let (process, lineage) =
            self.with_store(|store| Ok((store.process(process_id)?, store.lineage(process_id)?)))?;
        if let Some(context) = self.enforcement.confined_context(
            &self.namespace,
            &process.root_id,
            &process.id,
            &lineage,
        )? {
            return Ok(context);
        }
        let root = lineage
            .first()
            .ok_or(ProcessError::Invalid("missing process lineage"))?;
        profile.context(
            &self.namespace,
            process.capability.subject.to_hex(),
            &root.id,
        )
    }
    fn recovery_host_binding(&self, server: &str) -> Result<String, ProcessError> {
        digest(&(
            "chio.process.recovery-reservation.v1",
            server,
            self.routes.get(server),
            &self.security_profile,
            true,
        ))
    }
    /// Reserve the first-call identity and charge its logical slot once, before
    /// approval. Repeated calls compare immutable content before any new charge.
    pub fn reserve_recovery_call(
        &self,
        process_id: &str,
        operation_key: &str,
        continuation: &ContinuationId,
        unsigned_intent: IntentDigest,
        server_id: &str,
    ) -> Result<RecoveryCallReservation, ProcessError> {
        validate_id(server_id)?;
        let process = self.process(process_id)?;
        let reservation = RecoveryCallReservation {
            data: RecoveryProcessReservationV1 {
                runtime_id: self.namespace.clone(),
                process_id: process_id.to_owned(),
                continuation_id: continuation.clone(),
                operation_key: operation_key.to_owned(),
                request_id: self.request_id(process_id, operation_key)?,
                capability_digest: digest(&process.capability)?,
                unsigned_intent,
                server_id: server_id.to_owned(),
                host_binding: self.recovery_host_binding(server_id)?,
            },
        };
        self.with_store(|store| store.reserve_recovery(&reservation))?;
        Ok(reservation)
    }

    /// Finalize only from native-verified protected custody. A signed request is
    /// immutable thereafter, including its mode, route and security profile.
    pub fn finalize_recovery_call(
        &self,
        reservation: &RecoveryCallReservation,
        custody: &RecoveryRequestCustody,
    ) -> Result<(), ProcessError> {
        let request = custody.request();
        if custody.continuation() != &reservation.data.continuation_id
            || custody.action_intent() != reservation.data.unsigned_intent
            || custody.scope().process_id.as_str() != reservation.data.process_id
            || self.kernel.durable_authority_id() != Some(custody.scope().authority_domain.as_str())
            || reservation.data.runtime_id != self.namespace
            || reservation.data.request_id != request.request_id
            || reservation.data.server_id != request.server_id
            || request.execution_nonce.is_some()
            || reservation.data.host_binding != self.recovery_host_binding(&request.server_id)?
        {
            return Err(ProcessError::Conflict);
        }
        let binding = self.derive_call_binding(
            &reservation.data.process_id,
            &reservation.data.operation_key,
            request,
            true,
        )?;
        if binding.request_hash != custody.process_request_digest()
            || binding.binding_hash != custody.process_binding_digest()
        {
            return Err(ProcessError::Conflict);
        }
        self.with_store(|store| {
            store.finalize_recovery(reservation, request, &binding.binding_hash)?;
            if let Some(nonce) = custody.original_execution_nonce() {
                store.retain_nonce(
                    &reservation.data.process_id,
                    &reservation.data.operation_key,
                    1,
                    &binding.binding_hash,
                    nonce,
                )?;
            }
            Ok(())
        })
    }

    /// Load the frozen complete process digests for protected custody creation.
    /// This is only a prediction; neither hash grants execution authority.
    pub fn recovery_request_digests(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
    ) -> Result<(String, String), ProcessError> {
        if request.request_id != self.request_id(process_id, operation_key)?
            || request.execution_nonce.is_some()
        {
            return Err(ProcessError::Conflict);
        }
        let binding = self.derive_call_binding(process_id, operation_key, request, true)?;
        Ok((binding.request_hash, binding.binding_hash))
    }
}

impl chio_kernel::recovery::RecoveryProcessReservationPort for ProcessRuntime {
    fn verify_reservation(
        &self,
        data: &chio_kernel::recovery::RecoveryProcessReservationV1,
    ) -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError> {
        let verify = || -> Result<(), ProcessError> {
            let reservation = RecoveryCallReservation { data: data.clone() };
            if reservation.data.runtime_id != self.namespace
                || reservation.data.host_binding
                    != self.recovery_host_binding(&reservation.data.server_id)?
                || reservation.data.request_id
                    != self.request_id(
                        &reservation.data.process_id,
                        &reservation.data.operation_key,
                    )?
            {
                return Err(ProcessError::Conflict);
            }
            self.with_store(|store| store.verify_recovery_reservation(&reservation))
        };
        verify().map_err(|_| {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                "recovery process reservation refused".into(),
            )
        })
    }
}
