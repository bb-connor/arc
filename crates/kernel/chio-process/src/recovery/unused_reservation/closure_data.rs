//! Retained closed custody describes history and cannot construct the live role.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnusedRecoveryReservationClosureData {
    schema: ClosureSchema,
    reservation: RecoveryCallReservation,
    authority_domain: String,
    kernel_key: String,
    root_process: String,
    lineage_digest: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ClosureSchema {
    #[serde(rename = "chio.process.unused-recovery-reservation-closure.v1")]
    V1,
}

impl UnusedRecoveryReservationClosureData {
    pub(crate) fn from_actual_journal(
        reservation: RecoveryCallReservation,
        authority_domain: String,
        kernel_key: String,
        root_process: String,
        lineage_digest: String,
    ) -> Self {
        Self {
            schema: ClosureSchema::V1,
            reservation,
            authority_domain,
            kernel_key,
            root_process,
            lineage_digest,
        }
    }

    pub fn reservation(&self) -> &RecoveryCallReservation {
        &self.reservation
    }

    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub fn kernel_key(&self) -> &str {
        &self.kernel_key
    }

    pub fn root_process(&self) -> &str {
        &self.root_process
    }

    pub fn lineage_digest(&self) -> &str {
        &self.lineage_digest
    }

    pub fn closure_digest(&self) -> Result<String, ProcessError> {
        crate::digest(self)
    }
}

impl core::fmt::Debug for UnusedRecoveryReservationClosureData {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UnusedRecoveryReservationClosureData([redacted])")
    }
}
