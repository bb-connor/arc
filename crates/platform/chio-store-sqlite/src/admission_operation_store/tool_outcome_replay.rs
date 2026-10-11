//! One checked admission history for a terminal-payload maintenance transaction.
use super::*;

pub(crate) struct QualifiedToolOutcomeReplayOwner {
    pub(crate) operation: AdmissionOperationV1,
    pub(crate) terminal_receipt: Option<Vec<u8>>,
}

pub(crate) struct ToolOutcomeReplayOwnerReader<'scope, 'transaction> {
    transaction: &'scope Transaction<'transaction>,
    history: CheckedHistoryScope<'scope>,
}

impl<'scope, 'transaction> ToolOutcomeReplayOwnerReader<'scope, 'transaction> {
    pub(crate) fn new(transaction: &'scope Transaction<'transaction>) -> Self {
        Self {
            transaction,
            history: CheckedHistoryScope::new(transaction),
        }
    }

    pub(crate) fn load(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<QualifiedToolOutcomeReplayOwner>, AdmissionOperationStoreError> {
        load_by_operation_id_tx_with_history_and_terminal_receipt(
            self.transaction,
            operation_id,
            &self.history,
        )
        .map(|stored| {
            stored.map(|stored| QualifiedToolOutcomeReplayOwner {
                operation: stored.stored.operation,
                terminal_receipt: stored.terminal_receipt,
            })
        })
    }
}
