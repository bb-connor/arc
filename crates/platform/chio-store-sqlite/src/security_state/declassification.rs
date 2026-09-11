//! Shared declassification semantics over a fixed security data scope.
//! Native inspection is not activation, and production mutations remain legacy.

use super::scoped_sql::{declassification as sql, ScopedMutation, ScopedReader};
use super::*;

mod compaction;
mod integrity;
mod lifecycle;
mod outbox;
mod port;
mod records;
mod uses;

#[cfg(all(test, unix))]
mod tests;

/// Preserve the same receipt-pair contract at creation, inspection and deletion.
fn receipt_pair_matches(
    consumption: &chio_core::receipt::security::DeclassificationConsumptionReceiptBody,
    outcome: &chio_core::receipt::security::DeclassificationOutcomeReceiptBody,
) -> bool {
    consumption.grant_hash == outcome.grant_hash
        && consumption.grant_id == outcome.grant_id
        && consumption.request_hash == outcome.request_hash
        && consumption.policy == outcome.policy
}

use records::{
    insert_evidence as insert_declassification_evidence,
    load_evidence as load_declassification_evidence_record,
    load_transition as load_declassification_use_transition,
    load_use as load_declassification_use_record,
};

impl SecurityStateWriteTransaction<'_> {
    pub(super) fn commit_declassification_consumption_evidence(
        self,
        request: &DeclassificationConsumptionEvidenceCommit,
        clock: &dyn SecurityStateClock,
    ) -> PortResult<(Self, DeclassificationConsume)> {
        let consumed = ScopedMutation::legacy(self.transaction())
            .commit_declassification_consumption_evidence(request, || {
                trusted_time_in_transaction(self.transaction(), clock)
            })?;
        Ok((self, consumed))
    }

    pub(super) fn commit_declassification_outcome_evidence(
        self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<Self> {
        ScopedMutation::legacy(self.transaction())
            .commit_declassification_outcome_evidence(request)?;
        Ok(self)
    }
}

pub(super) fn verify_legacy_lifecycle(connection: &Connection) -> PortResult<()> {
    lifecycle::verify(ScopedReader::legacy(connection))
}

pub(super) fn reset_legacy_lifecycle(transaction: &Transaction<'_>) -> PortResult<()> {
    ScopedMutation::legacy(transaction).reset_declassification_lifecycle()
}

pub(super) fn verify_legacy_integrity(connection: &Connection) -> PortResult<()> {
    integrity::verify(ScopedReader::legacy(connection))
}

/// Data validation under the hydration transaction, never mutable authority.
pub(crate) fn verify_native_declassification_state(
    connection: &Connection,
    authority: &str,
) -> PortResult<()> {
    let reader = ScopedReader::native(connection, authority);
    lifecycle::verify(reader)?;
    integrity::verify(reader)
}

#[cfg(test)]
pub(super) fn load_legacy_use(
    connection: &Connection,
    query: &DeclassificationUseQuery,
) -> PortResult<Option<DeclassificationUseRecord>> {
    records::load_use(ScopedReader::legacy(connection), query)
}

#[cfg(test)]
pub(super) fn load_legacy_evidence(
    connection: &Connection,
    query: &DeclassificationEvidenceQuery,
) -> PortResult<Option<DeclassificationEvidenceRecord>> {
    records::load_evidence(ScopedReader::legacy(connection), query)
}
